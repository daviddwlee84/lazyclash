package vps

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

type CloudBindPreview struct {
	Action     string                              `json:"action"`
	ID         string                              `json:"id"`
	Binding    serverstate.CloudObservationBinding `json:"binding"`
	Owned      bool                                `json:"owned"`
	HostDigest string                              `json:"host_sha256"`
	Warnings   []string                            `json:"warnings"`
	Digest     string                              `json:"digest"`
}

func validateObservationRequest(b serverstate.CloudObservationBinding) error {
	for _, value := range []string{b.Provider, b.Profile, b.Region, b.ResourceID, b.TenancyID, b.CompartmentID, b.SubscriptionID} {
		if strings.IndexFunc(value, unicode.IsControl) >= 0 || strings.HasPrefix(value, "-") {
			return fmt.Errorf("cloud observation fields cannot contain controls or begin with '-'")
		}
	}
	if b.Region == "" || b.ResourceID == "" {
		return fmt.Errorf("cloud observation requires --region and --resource-id")
	}
	switch b.Provider {
	case "oracle":
		valid := regexp.MustCompile(`^[a-z0-9.-]+$`)
		if !strings.HasPrefix(b.ResourceID, "ocid1.instance.") || !valid.MatchString(b.ResourceID) || !strings.HasPrefix(b.TenancyID, "ocid1.tenancy.") || !valid.MatchString(b.TenancyID) {
			return fmt.Errorf("Oracle observation requires an instance OCID and --tenancy OCID")
		}
		if b.SubscriptionID != "" {
			return fmt.Errorf("--subscription applies only to Azure")
		}
	case "azure":
		if !regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`).MatchString(b.SubscriptionID) {
			return fmt.Errorf("Azure observation requires an explicit --subscription UUID")
		}
		parts := strings.Split(strings.Trim(b.ResourceID, "/"), "/")
		if len(parts) != 8 || !strings.EqualFold(parts[0], "subscriptions") || !strings.EqualFold(parts[1], b.SubscriptionID) || !strings.EqualFold(parts[2], "resourceGroups") || !strings.EqualFold(parts[4], "providers") || !strings.EqualFold(parts[5], "Microsoft.Compute") || !strings.EqualFold(parts[6], "virtualMachines") || parts[3] == "" || parts[7] == "" || strings.ContainsAny(b.ResourceID, "?#%") {
			return fmt.Errorf("Azure resource ID must identify a VM in the selected subscription")
		}
		if b.Profile != "" || b.TenancyID != "" || b.CompartmentID != "" {
			return fmt.Errorf("Azure observation uses --subscription, not Oracle profile/tenancy/compartment fields")
		}
	default:
		return fmt.Errorf("cloud observation supports oracle and azure")
	}
	return nil
}

func (s *Service) observationIdentity(ctx context.Context, b serverstate.CloudObservationBinding) (string, error) {
	r := CreateRequest{Provider: b.Provider, Profile: b.Profile, Region: b.Region, TenancyID: b.TenancyID, SubscriptionID: b.SubscriptionID}
	if b.Provider == "oracle" {
		return s.accountIdentity(ctx, r)
	}
	v, err := s.call(ctx, r, "account", "show")
	if err != nil {
		return "", err
	}
	a := obj(v)
	if str(a["environmentName"]) != "AzureCloud" || !strings.EqualFold(str(a["id"]), b.SubscriptionID) || str(a["tenantId"]) == "" {
		return "", fmt.Errorf("Azure account identity differs from the observation subscription")
	}
	// account show is cached; confirm that the selected subscription is still
	// readable, including historical data on a Disabled subscription.
	v, err = s.call(ctx, r, "rest", "--method", "get", "--url", "https://management.azure.com/subscriptions/"+b.SubscriptionID+"?api-version=2022-12-01")
	if err != nil {
		return "", err
	}
	live := obj(v)
	if !strings.EqualFold(str(live["subscriptionId"]), b.SubscriptionID) || str(live["state"]) == "" {
		return "", fmt.Errorf("Azure did not confirm the live subscription identity")
	}
	return "azure:" + digest([]string{"AzureCloud", strings.ToLower(str(a["tenantId"])), strings.ToLower(b.SubscriptionID)}), nil
}

func (s *Service) PlanBindCloud(ctx context.Context, id string, b serverstate.CloudObservationBinding) (CloudBindPreview, error) {
	if err := validateObservationRequest(b); err != nil {
		return CloudBindPreview{}, err
	}
	inv, err := s.store.Load()
	if err != nil {
		return CloudBindPreview{}, err
	}
	h, err := inv.Host(id)
	if err != nil {
		return CloudBindPreview{}, err
	}
	if h.Owned && (h.Provider != b.Provider || h.ResourceID != b.ResourceID || h.Region != b.Region || h.Profile != b.Profile || h.SubscriptionID != b.SubscriptionID) {
		return CloudBindPreview{}, fmt.Errorf("an owned host observation must match its existing cloud identity")
	}
	b.AccountID, err = s.observationIdentity(ctx, b)
	if err != nil {
		return CloudBindPreview{}, err
	}
	b.VerifiedAt = time.Time{}
	r := CreateRequest{Provider: b.Provider, Profile: b.Profile, Region: b.Region, SubscriptionID: b.SubscriptionID}
	warnings := []string{"This saves a read-only cloud observation binding. VM ownership and lifecycle permissions are unchanged.", "Monitoring bytes and delayed shared billing meters are separate; no guaranteed remaining quota or trial-credit balance is inferred."}
	if b.Provider == "oracle" {
		v, e := s.call(ctx, r, "compute", "instance", "get", "--instance-id", b.ResourceID)
		if e != nil {
			return CloudBindPreview{}, e
		}
		m := obj(obj(v)["data"])
		if str(m["id"]) != b.ResourceID || str(m["compartment-id"]) == "" {
			return CloudBindPreview{}, fmt.Errorf("Oracle instance response does not confirm the requested resource")
		}
		if b.CompartmentID != "" && b.CompartmentID != str(m["compartment-id"]) {
			return CloudBindPreview{}, fmt.Errorf("Oracle instance is not in the requested compartment")
		}
		b.CompartmentID = str(m["compartment-id"])
		if e = s.verifyOracleCompartment(ctx, r, b.CompartmentID, b.TenancyID); e != nil {
			return CloudBindPreview{}, e
		}
		v, e = s.call(ctx, r, "compute", "instance", "list-vnics", "--instance-id", b.ResourceID, "--all")
		if e != nil {
			return CloudBindPreview{}, e
		}
		vnics, e := strictItems(v, "data")
		if e != nil {
			return CloudBindPreview{}, e
		}
		if expected := net.ParseIP(h.PublicHost); expected != nil {
			matched := false
			for _, n := range vnics {
				if actual := net.ParseIP(str(n["public-ip"])); actual != nil && actual.Equal(expected) {
					matched = true
				}
			}
			if !matched {
				return CloudBindPreview{}, fmt.Errorf("Oracle instance public IP does not match the registered host")
			}
		} else {
			warnings = append(warnings, "The registered public address is a DNS name; verify that this reviewed instance is the server behind that name.")
		}
	} else {
		v, e := s.call(ctx, r, "vm", "show", "--ids", b.ResourceID)
		if e != nil {
			return CloudBindPreview{}, e
		}
		m := obj(v)
		if !strings.EqualFold(str(m["id"]), b.ResourceID) || !strings.EqualFold(str(m["location"]), b.Region) {
			return CloudBindPreview{}, fmt.Errorf("Azure VM response differs from the requested resource or region")
		}
		warnings = append(warnings, "Review that this VM is the server behind the registered SSH/public address; the observation binding does not modify that address.")
	}
	p := CloudBindPreview{Action: "bind-cloud-observation", ID: id, Binding: b, Owned: h.Owned, HostDigest: digest(h), Warnings: warnings}
	p.Digest = digest(p)
	return p, nil
}

func (s *Service) verifyOracleCompartment(ctx context.Context, r CreateRequest, compartment, tenancy string) error {
	seen := map[string]bool{}
	for depth := 0; compartment != tenancy; depth++ {
		if depth >= 32 || seen[compartment] {
			return fmt.Errorf("Oracle compartment ancestry does not establish the selected tenancy")
		}
		seen[compartment] = true
		v, err := s.call(ctx, r, "iam", "compartment", "get", "--compartment-id", compartment)
		if err != nil {
			return err
		}
		m := obj(obj(v)["data"])
		if str(m["id"]) != compartment || str(m["compartment-id"]) == "" {
			return fmt.Errorf("Oracle compartment ancestry is incomplete")
		}
		compartment = str(m["compartment-id"])
	}
	return nil
}

func (s *Service) BindCloud(ctx context.Context, id string, b serverstate.CloudObservationBinding, expected string) (serverstate.Host, error) {
	if s.options.ReadOnly {
		return serverstate.Host{}, fmt.Errorf("cloud observation binding is disabled in read-only mode")
	}
	p, err := s.PlanBindCloud(ctx, id, b)
	if err != nil {
		return serverstate.Host{}, err
	}
	if expected == "" || p.Digest != expected {
		return serverstate.Host{}, fmt.Errorf("cloud binding preview changed; review a fresh digest")
	}
	var result serverstate.Host
	err = s.store.Update(func(inv *serverstate.Inventory) error {
		h, e := inv.Host(id)
		if e != nil {
			return e
		}
		if digest(h) != p.HostDigest {
			return serverstate.ErrConflict
		}
		binding := p.Binding
		binding.VerifiedAt = s.options.Now().UTC()
		h.Observation = &binding
		h.UpdatedAt = binding.VerifiedAt
		result = h
		return inv.UpsertHost(h)
	})
	return result, err
}
