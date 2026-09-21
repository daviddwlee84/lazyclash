package vps

import (
	"context"
	"fmt"
)

// ValidateAction checks the entire graph before a destructive mutation. Tags
// alone never authorize deleting a resource attached to someone else's VM.
func (a ec2Adapter) ValidateAction(ctx context.Context, op operation, action string) error {
	if op.PendingResourceKind != "" {
		return fmt.Errorf("EC2 write %s is unconfirmed; reconcile it before lifecycle operations", op.PendingResourceKind)
	}
	if len(op.PrivateData["ec2_run_instances"]) > 0 {
		if err := a.validateLaunchRecord(&op); err != nil {
			return err
		}
	}
	for _, resource := range op.CloudResources {
		if resource.Deleted {
			continue
		}
		row, err := a.find(ctx, &op, resource.Kind)
		if err != nil {
			return err
		}
		if row == nil {
			if action != "delete" {
				return fmt.Errorf("EC2 %s is missing; lifecycle action requires the saved resource graph", resource.Kind)
			}
			continue
		}
		if action == "delete" {
			if err = a.validateAttachments(ctx, &op, resource.Kind, row); err != nil {
				return err
			}
		}
	}
	if action != "delete" && ec2ID(&op, "instance") == "" {
		return fmt.Errorf("EC2 instance creation has not completed")
	}
	if action == "delete" {
		return a.validateVPCContents(ctx, &op)
	}
	return nil
}
func (a ec2Adapter) validateAttachments(ctx context.Context, op *operation, kind string, row map[string]any) error {
	instance := ec2RecordedID(op, "instance")
	switch kind {
	case "instance":
		for _, raw := range arr(row["BlockDeviceMappings"]) {
			b := obj(raw)
			id := str(obj(b["Ebs"])["VolumeId"])
			if id == "" {
				continue
			}
			rows, err := a.list(ctx, op.Request, "ec2-volume", []map[string]any{{"Name": "volume-id", "Values": []string{id}}})
			if err != nil {
				return err
			}
			if len(rows) != 1 || !ec2HasOwnership(rows[0], op, "ec2-volume") {
				return fmt.Errorf("EC2 instance has an unowned attached volume; detach it before deletion")
			}
			if saved := ec2ID(op, "ec2-volume"); saved != "" && id != saved {
				return fmt.Errorf("EC2 instance has an unexpected extra volume")
			}
		}
		for _, raw := range arr(row["NetworkInterfaces"]) {
			n := obj(raw)
			id := str(n["NetworkInterfaceId"])
			rows, err := a.list(ctx, op.Request, "ec2-eni", []map[string]any{{"Name": "network-interface-id", "Values": []string{id}}})
			if err != nil {
				return err
			}
			if len(rows) != 1 || !ec2HasOwnership(rows[0], op, "ec2-eni") {
				return fmt.Errorf("EC2 instance has an unowned network interface; detach it before deletion")
			}
			if saved := ec2ID(op, "ec2-eni"); saved != "" && id != saved {
				return fmt.Errorf("EC2 instance has an unexpected extra network interface")
			}
		}
	case "ec2-volume":
		for _, raw := range arr(row["Attachments"]) {
			if str(obj(raw)["InstanceId"]) != instance || instance == "" {
				return fmt.Errorf("EC2 owned volume is attached to another instance; resource retained")
			}
		}
	case "ec2-eni":
		if attach := obj(row["Attachment"]); len(attach) > 0 && (str(attach["InstanceId"]) != instance || instance == "") {
			return fmt.Errorf("EC2 owned network interface is attached to another instance")
		}
	case "ec2-address":
		if str(row["AssociationId"]) != "" && (str(row["InstanceId"]) != instance || str(row["NetworkInterfaceId"]) != ec2RecordedID(op, "ec2-eni")) {
			return fmt.Errorf("EC2 static IP is attached to a foreign resource")
		}
	case "ec2-igw":
		for _, raw := range arr(row["Attachments"]) {
			if str(obj(raw)["VpcId"]) != ec2ID(op, "ec2-vpc") {
				return fmt.Errorf("EC2 gateway is attached to another VPC")
			}
		}
	case "ec2-route-table":
		for _, raw := range arr(row["Associations"]) {
			assoc := obj(raw)
			if truth(assoc["Main"]) || str(assoc["SubnetId"]) != ec2ID(op, "ec2-subnet") || str(assoc["GatewayId"]) != "" {
				return fmt.Errorf("EC2 route table acquired a foreign/main association")
			}
		}
		for _, raw := range arr(row["Routes"]) {
			r := obj(raw)
			if str(r["GatewayId"]) == "local" {
				continue
			}
			if str(r["GatewayId"]) != ec2ID(op, "ec2-igw") || str(r["DestinationCidrBlock"]) != "0.0.0.0/0" {
				return fmt.Errorf("EC2 route table contains a foreign route")
			}
		}
	case "ec2-key-pair":
		rows, err := a.list(ctx, op.Request, "instance", []map[string]any{{"Name": "key-name", "Values": []string{str(row["KeyName"])}}})
		if err != nil {
			return err
		}
		for _, r := range rows {
			if str(obj(r["State"])["Name"]) != "terminated" && str(r["InstanceId"]) != instance {
				return fmt.Errorf("EC2 key pair is used by another instance; resource retained")
			}
		}
	}
	return nil
}
func (a ec2Adapter) validateVPCContents(ctx context.Context, op *operation) error {
	vpc := ec2ID(op, "ec2-vpc")
	if vpc == "" {
		return nil
	}
	// The VPC's automatically created default SG and main route table are the
	// only untagged resources accepted. EC2 deletes those with an otherwise empty
	// VPC; custom subnets, routes, endpoints and interfaces remain protected.
	for _, kind := range []string{"ec2-subnet", "ec2-route-table", "ec2-security-group", "ec2-eni", "instance"} {
		rows, err := a.list(ctx, op.Request, kind, []map[string]any{{"Name": "vpc-id", "Values": []string{vpc}}})
		if err != nil {
			return err
		}
		for _, row := range rows {
			if kind == "instance" && str(obj(row["State"])["Name"]) == "terminated" {
				continue
			}
			if ec2HasOwnership(row, op, kind) {
				if saved := ec2ID(op, kind); saved != "" && str(row[ec2ResourceSpecs[kind].id]) != saved {
					return fmt.Errorf("EC2 VPC contains an unexpected additional %s", kind)
				}
				if err = a.validateAttachments(ctx, op, kind, row); err != nil {
					return err
				}
				continue
			}
			if kind == "ec2-security-group" && str(row["GroupName"]) == "default" {
				continue
			}
			if kind == "ec2-route-table" {
				defaultOnly := len(arr(row["Associations"])) == 1 && truth(obj(arr(row["Associations"])[0])["Main"])
				for _, raw := range arr(row["Routes"]) {
					defaultOnly = defaultOnly && str(obj(raw)["GatewayId"]) == "local"
				}
				if defaultOnly {
					continue
				}
			}
			return fmt.Errorf("EC2 VPC contains a foreign %s; remove or relocate it before deleting this host", kind)
		}
	}
	// Gateway attachment is mutable independently of its tags.
	gateways, err := a.list(ctx, op.Request, "ec2-igw", []map[string]any{{"Name": "attachment.vpc-id", "Values": []string{vpc}}})
	if err != nil {
		return err
	}
	for _, g := range gateways {
		if str(g["InternetGatewayId"]) != ec2ID(op, "ec2-igw") || !ec2HasOwnership(g, op, "ec2-igw") {
			return fmt.Errorf("EC2 VPC has a foreign internet gateway")
		}
	}
	return nil
}
func (a ec2Adapter) Action(ctx context.Context, op *operation, action string) error {
	if err := a.ValidateAction(ctx, *op, action); err != nil {
		return err
	}
	if action != "delete" {
		api := map[string]string{"start": "start-instances", "stop": "stop-instances", "reboot": "reboot-instances"}[action]
		if api == "" {
			return fmt.Errorf("unsupported EC2 lifecycle action")
		}
		if err := a.checkAccount(ctx, op); err != nil {
			return err
		}
		_, err := a.s.call(ctx, op.Request, "ec2", api, "--instance-ids", ec2ID(op, "instance"))
		if err != nil {
			return err
		}
		op.Host.Status = action + "-requested"
		return a.s.cloudPersist(op)
	}
	op.State = "delete-pending"
	op.Host.Status = "delete-pending"
	if err := a.s.cloudPersist(op); err != nil {
		return err
	}
	row, err := a.find(ctx, op, "instance")
	if err != nil {
		return err
	}
	if row != nil {
		if err = a.validateAttachments(ctx, op, "instance", row); err != nil {
			return err
		}
		if err = a.checkAccount(ctx, op); err != nil {
			return err
		}
		if _, err = a.s.call(ctx, op.Request, "ec2", "terminate-instances", "--instance-ids", str(row["InstanceId"])); err != nil {
			return fmt.Errorf("EC2 termination is unconfirmed; inspect status before retrying: %w", err)
		}
		if _, err = a.s.call(ctx, op.Request, "ec2", "wait", "instance-terminated", "--instance-ids", str(row["InstanceId"])); err != nil {
			return fmt.Errorf("EC2 termination is still pending; resume deletion to release disk/IP costs: %w", err)
		}
	}
	if r := cloudResourceOf(op, "instance"); r != nil && !r.Deleted {
		if err = a.markDeleted(op, "instance"); err != nil {
			return err
		}
	}
	op.Host.Status = "cleanup-required"
	if err = a.s.cloudPersist(op); err != nil {
		return err
	}
	for _, kind := range []string{"ec2-address", "ec2-volume", "ec2-eni", "ec2-key-pair", "ec2-security-group", "ec2-route-table", "ec2-subnet", "ec2-igw", "ec2-vpc"} {
		if r := cloudResourceOf(op, kind); r == nil || r.Deleted {
			continue
		}
		row, err = a.find(ctx, op, kind)
		if err != nil {
			return err
		}
		if row == nil {
			if err = a.markDeleted(op, kind); err != nil {
				return err
			}
			continue
		}
		if err = a.validateAttachments(ctx, op, kind, row); err != nil {
			return err
		}
		args, err := a.deleteArgs(ctx, op, kind, row)
		if err != nil {
			return err
		}
		if err = a.checkAccount(ctx, op); err != nil {
			return err
		}
		if _, err = a.s.call(ctx, op.Request, args...); err != nil {
			return fmt.Errorf("EC2 %s cleanup is unconfirmed; retained IDs allow a reviewed retry: %w", kind, err)
		}
		if err = a.markDeleted(op, kind); err != nil {
			return err
		}
	}
	op.State = "deleted"
	op.Host.Status = "deleted"
	op.Host.Owned = false
	op.Host.PublicHost = ""
	op.Host.SSHHost = ""
	return a.s.cloudPersist(op)
}
func (a ec2Adapter) markDeleted(op *operation, kind string) error {
	r := cloudResourceOf(op, kind)
	if r == nil {
		return nil
	}
	r.Deleted = true
	removeFirewallResource(&op.Host, kind, r.ID)
	return a.s.cloudPersist(op)
}
func (a ec2Adapter) deleteArgs(ctx context.Context, op *operation, kind string, row map[string]any) ([]string, error) {
	id := str(row[ec2ResourceSpecs[kind].id])
	switch kind {
	case "ec2-address":
		if association := str(row["AssociationId"]); association != "" {
			if err := a.checkAccount(ctx, op); err != nil {
				return nil, err
			}
			if _, err := a.s.call(ctx, op.Request, "ec2", "disassociate-address", "--association-id", association); err != nil {
				return nil, err
			}
		}
		return []string{"ec2", "release-address", "--allocation-id", id}, nil
	case "ec2-volume":
		if len(arr(row["Attachments"])) != 0 {
			return nil, fmt.Errorf("EC2 root disk remains attached; wait for termination before cleanup")
		}
		return []string{"ec2", "delete-volume", "--volume-id", id}, nil
	case "ec2-eni":
		if str(obj(row["Attachment"])["AttachmentId"]) != "" {
			return nil, fmt.Errorf("EC2 network interface remains attached; wait for termination")
		}
		return []string{"ec2", "delete-network-interface", "--network-interface-id", id}, nil
	case "ec2-key-pair":
		return []string{"ec2", "delete-key-pair", "--key-pair-id", id}, nil
	case "ec2-security-group":
		return []string{"ec2", "delete-security-group", "--group-id", id}, nil
	case "ec2-route-table":
		for _, raw := range arr(row["Associations"]) {
			assoc := obj(raw)
			if err := a.checkAccount(ctx, op); err != nil {
				return nil, err
			}
			if _, err := a.s.call(ctx, op.Request, "ec2", "disassociate-route-table", "--association-id", str(assoc["RouteTableAssociationId"])); err != nil {
				return nil, err
			}
		}
		return []string{"ec2", "delete-route-table", "--route-table-id", id}, nil
	case "ec2-subnet":
		return []string{"ec2", "delete-subnet", "--subnet-id", id}, nil
	case "ec2-igw":
		if len(arr(row["Attachments"])) > 0 {
			if err := a.checkAccount(ctx, op); err != nil {
				return nil, err
			}
			if _, err := a.s.call(ctx, op.Request, "ec2", "detach-internet-gateway", "--internet-gateway-id", id, "--vpc-id", ec2ID(op, "ec2-vpc")); err != nil {
				return nil, err
			}
		}
		return []string{"ec2", "delete-internet-gateway", "--internet-gateway-id", id}, nil
	case "ec2-vpc":
		if err := a.validateVPCContents(ctx, op); err != nil {
			return nil, err
		}
		return []string{"ec2", "delete-vpc", "--vpc-id", id}, nil
	}
	return nil, fmt.Errorf("unsupported EC2 cleanup resource")
}
