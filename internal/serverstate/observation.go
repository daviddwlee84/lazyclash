package serverstate

import (
	"errors"
	"strings"
	"time"
	"unicode"
)

// CloudObservationBinding grants no lifecycle ownership. It pins the cloud
// account and resource used only for read-only monitoring and billing queries.
type CloudObservationBinding struct {
	Provider       string    `toml:"provider" json:"provider"`
	Profile        string    `toml:"profile,omitempty" json:"profile,omitempty"`
	Region         string    `toml:"region" json:"region"`
	ResourceID     string    `toml:"resource_id" json:"resource_id"`
	TenancyID      string    `toml:"tenancy_id,omitempty" json:"tenancy_id,omitempty"`
	CompartmentID  string    `toml:"compartment_id,omitempty" json:"compartment_id,omitempty"`
	SubscriptionID string    `toml:"subscription_id,omitempty" json:"subscription_id,omitempty"`
	AccountID      string    `toml:"account_id" json:"account_id"`
	VerifiedAt     time.Time `toml:"verified_at" json:"verified_at"`
}

func validateObservation(b *CloudObservationBinding) error {
	if b == nil {
		return nil
	}
	if (b.Provider != "oracle" && b.Provider != "azure") || b.Region == "" || b.ResourceID == "" || b.AccountID == "" || b.VerifiedAt.IsZero() {
		return errors.New("cloud observation binding requires a supported provider, region, resource, verified account and timestamp")
	}
	for _, value := range []string{b.Provider, b.Profile, b.Region, b.ResourceID, b.TenancyID, b.CompartmentID, b.SubscriptionID, b.AccountID} {
		if strings.IndexFunc(value, unicode.IsControl) >= 0 || strings.HasPrefix(value, "-") {
			return errors.New("cloud observation fields cannot contain controls or begin with '-'")
		}
	}
	return nil
}
