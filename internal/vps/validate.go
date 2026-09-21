package vps

import (
	"context"
	"fmt"
)

func (s *Service) validateImage(ctx context.Context, req CreateRequest) error {
	switch req.Provider {
	case "digitalocean":
		if req.Image != "ubuntu-24-04-x64" {
			return fmt.Errorf("DigitalOcean deployment requires the official ubuntu-24-04-x64 image")
		}
	case "linode":
		if req.Image != "linode/ubuntu24.04" {
			return fmt.Errorf("Linode deployment requires the official linode/ubuntu24.04 image")
		}
	case "vultr":
		choices, err := s.Discover(ctx, req, "images")
		if err != nil {
			return err
		}
		for _, c := range choices {
			if c.ID == req.Image {
				return nil
			}
		}
		return fmt.Errorf("Vultr OS ID is not an available Ubuntu 24.04 image; inspect vps discover --kind images")
	}
	return nil
}

func (s *Service) verifyLaunch(ctx context.Context, op operation) error {
	if op.Request.Provider == "oracle" {
		if err := validateOracleInitializer(op.Request); err != nil {
			return err
		}
	}
	if op.Request.SSHKeyFingerprint != "" {
		key, err := publicKey(op.Request.SSHKey)
		if err != nil {
			return err
		}
		if digest(key) != op.Request.SSHKeyFingerprint {
			return fmt.Errorf("SSH public key changed after preview; no VM was created; restore the reviewed key before resuming")
		}
	}
	account, err := s.accountIdentity(ctx, op.Request)
	if err != nil {
		return err
	}
	if account != op.AccountID {
		return fmt.Errorf("cloud account changed while preparing networking; no VM was submitted")
	}
	if op.Request.Provider == "oracle" {
		if err = s.oracleFree(ctx, op.Request); err != nil {
			return err
		}
	} else {
		q, err := s.Quote(ctx, op.Request)
		if err != nil {
			return err
		}
		if q.MonthlyUSD != op.Host.MonthlyUSD {
			return fmt.Errorf("monthly VM price changed after review; no VM was submitted")
		}
	}
	return nil
}

func reviewedPublicKey(req CreateRequest) (string, error) {
	key, err := publicKey(req.SSHKey)
	if err != nil {
		return "", err
	}
	if req.SSHKeyFingerprint == "" || digest(key) != req.SSHKeyFingerprint {
		return "", fmt.Errorf("SSH public key differs from the reviewed key")
	}
	return key, nil
}
