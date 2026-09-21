package vps

import (
	"context"
	"fmt"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

// accountIdentity pins the authenticated account/principal without retaining
// email addresses or authentication material in the inventory or review.
func (s *Service) accountIdentity(ctx context.Context, req CreateRequest) (string, error) {
	var args []string
	switch req.Provider {
	case "digitalocean":
		args = []string{"account", "get"}
	case "vultr":
		args = []string{"account", "info"}
	case "linode":
		args = []string{"profile", "view"}
	case "oracle":
		args = []string{"iam", "tenancy", "get", "--tenancy-id", req.TenancyID}
	default:
		return "", fmt.Errorf("unsupported provider")
	}
	v, err := s.call(ctx, req, args...)
	if err != nil {
		return "", fmt.Errorf("cannot establish cloud account identity: %w", err)
	}
	m, err := one(v, "account", "data")
	if err != nil {
		return "", err
	}
	identity := ""
	switch req.Provider {
	case "digitalocean":
		identity = str(m["uuid"])
	case "vultr":
		identity = str(m["email"])
	case "linode":
		identity = str(m["uid"]) + ":" + str(m["username"])
		if str(m["username"]) == "" {
			identity = ""
		}
	case "oracle":
		identity = str(m["id"])
		if identity != req.TenancyID {
			return "", fmt.Errorf("Oracle tenancy identity differs from request")
		}
	}
	if identity == "" {
		return "", fmt.Errorf("provider account identity is unavailable; refusing an unbound cloud operation")
	}
	return req.Provider + ":" + digest(identity), nil
}

func (s *Service) verifyOwned(ctx context.Context, host serverstate.Host) (operation, error) {
	op, err := s.readOperation(host.OperationID)
	if err != nil {
		return op, fmt.Errorf("private creation record is required to manage an owned VM: %w", err)
	}
	if op.Host.ID != host.ID || op.Host.Provider != host.Provider || op.Host.Profile != host.Profile || op.Host.Region != host.Region || op.Host.ResourceID != host.ResourceID || op.ID != host.OperationID {
		return op, fmt.Errorf("inventory differs from private resource ownership record; reconcile before managing this VM")
	}
	account, err := s.accountIdentity(ctx, op.Request)
	if err != nil {
		return op, err
	}
	if account != op.AccountID {
		return op, fmt.Errorf("cloud CLI account changed; restore the account used to create this host")
	}
	if host.ResourceID != "" && host.Status != "cleanup-required" && host.Status != "delete-pending" {
		remote, err := s.findRemote(ctx, op.Request, op.ID)
		if err != nil {
			return op, err
		}
		if remote.ResourceID != host.ResourceID {
			return op, fmt.Errorf("cloud resource operation marker does not match the saved owned VM")
		}
	}
	return op, nil
}
