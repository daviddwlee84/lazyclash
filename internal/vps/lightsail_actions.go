package vps

import (
	"context"
	"fmt"
	"strings"
)

func (a lightsailAdapter) ValidateAction(ctx context.Context, op operation, action string) error {
	if action != "start" && action != "stop" && action != "reboot" && action != "delete" {
		return fmt.Errorf("unsupported Lightsail action")
	}
	if err := a.s.cloudVerifyAccount(ctx, op); err != nil {
		return err
	}
	if pending := op.PendingResourceKind; pending != "" {
		deleting := action == "delete" && (pending == "lightsail-delete-instance" || pending == "lightsail-release-ip")
		if !deleting && pending != "lightsail-"+action {
			return fmt.Errorf("Lightsail %s must be reconciled before lifecycle changes", pending)
		}
	}
	for _, kind := range []string{"instance", "lightsail-ip"} {
		r := cloudResourceOf(&op, kind)
		if r == nil || r.Deleted {
			continue
		}
		row, err := a.find(ctx, &op, kind)
		if err != nil {
			return err
		}
		if row == nil {
			if action != "delete" {
				return fmt.Errorf("Lightsail owned %s is missing", kind)
			}
			continue
		}
		if kind == "lightsail-ip" {
			attached := str(row["attachedTo"])
			if truth(row["isAttached"]) != (attached != "") || (attached != "" && attached != op.ID) {
				return fmt.Errorf("Lightsail static IP has a foreign or inconsistent attachment; nothing was deleted")
			}
		}
		if kind == "instance" && action == "delete" {
			for _, raw := range arr(obj(row["hardware"])["disks"]) {
				if !truth(obj(raw)["isSystemDisk"]) {
					return fmt.Errorf("Lightsail instance has an additional disk; detach it before deleting the owned instance")
				}
			}
		}
	}
	if action != "delete" {
		if r := cloudResourceOf(&op, "instance"); r == nil || r.Deleted {
			return fmt.Errorf("Lightsail instance creation is incomplete")
		}
	}
	return nil
}

func (a lightsailAdapter) Action(ctx context.Context, op *operation, action string) error {
	if err := a.ValidateAction(ctx, *op, action); err != nil {
		return err
	}
	if op.PendingResourceKind != "" {
		if err := a.pending(ctx, op); err != nil {
			return err
		}
		if action != "delete" {
			return nil
		}
	}
	if action != "delete" {
		api := map[string]string{"start": "start-instance", "stop": "stop-instance", "reboot": "reboot-instance"}[action]
		return a.write(ctx, op, "lightsail-"+action, api, "--instance-name", op.ID)
	}
	op.State = "delete-pending"
	op.Host.Status = "cleanup-required"
	if err := a.s.cloudPersist(op); err != nil {
		return err
	}
	for _, kind := range []string{"instance", "lightsail-ip"} {
		receipt := cloudResourceOf(op, kind)
		if receipt == nil || receipt.Deleted {
			continue
		}
		// Repeat the graph check before each destructive request; the IP could
		// have been moved independently while instance deletion was pending.
		if err := a.ValidateAction(ctx, *op, "delete"); err != nil {
			return err
		}
		row, err := a.find(ctx, op, kind)
		if err != nil {
			return err
		}
		if row == nil {
			receipt.Deleted = true
			removeFirewallResource(&op.Host, kind, receipt.ID)
			if err = a.s.cloudPersist(op); err != nil {
				return err
			}
			continue
		}
		if kind == "instance" {
			if err = a.write(ctx, op, "lightsail-delete-instance", "delete-instance", "--instance-name", op.ID); err != nil {
				return err
			}
		} else {
			if truth(row["isAttached"]) || str(row["attachedTo"]) != "" {
				return fmt.Errorf("Lightsail static IP remains attached; wait for instance deletion before release")
			}
			if err = a.write(ctx, op, "lightsail-release-ip", "release-static-ip", "--static-ip-name", lightsailName(op, kind)); err != nil {
				return err
			}
		}
	}
	// Any retained auxiliary resource is visible rather than silently removed.
	for _, resource := range op.CloudResources {
		if !resource.Deleted && strings.HasPrefix(resource.Kind, "lightsail-") {
			return fmt.Errorf("Lightsail cleanup is incomplete; retained resources may still bill")
		}
	}
	op.State = "deleted"
	op.Host.Status = "deleted"
	op.Host.Owned = false
	op.Host.PublicHost = ""
	op.Host.SSHHost = ""
	return a.s.cloudPersist(op)
}
