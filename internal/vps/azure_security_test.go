package vps

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestAzureSecurityValidationAndArguments(t *testing.T) {
	for _, r := range []CreateRequest{
		{Provider: "azure", AzureSecurityType: "wrong"},
		{Provider: "aws-ec2", AzureSecurityType: "TrustedLaunch"},
		{Provider: "oracle", AzureSecurityType: "Standard"},
	} {
		if err := ValidateDraft(r); err == nil {
			t.Fatalf("accepted invalid security mode: %+v", r)
		}
	}
	want := []string{"--security-type", "TrustedLaunch", "--enable-secure-boot", "true", "--enable-vtpm", "true"}
	if got := azureSecurityArgs(CreateRequest{AzureSecurityType: "TrustedLaunch"}); !reflect.DeepEqual(got, want) {
		t.Fatalf("Trusted Launch flags: %v", got)
	}
	for _, value := range []string{"", "Standard"} {
		if got := azureSecurityArgs(CreateRequest{AzureSecurityType: value}); !reflect.DeepEqual(got, []string{"--security-type", "Standard"}) {
			t.Fatalf("legacy/Standard flags: %v", got)
		}
	}
	r := CreateRequest{Provider: "azure"}
	before := digest(r)
	r.AzureSecurityType = "TrustedLaunch"
	if before == digest(r) {
		t.Fatal("security mode is not bound to request digest")
	}
}

func trustedLaunchFixture(t *testing.T, imageSupported bool) *azureFixture {
	t.Helper()
	f := newAzureFixture(t)
	f.s.options.Run = func(ctx context.Context, exe string, args []string) ([]byte, error) {
		data, err := f.run(ctx, exe, args)
		if err != nil {
			return data, err
		}
		command := strings.Join(args, " ")
		if strings.HasPrefix(command, "vm list-skus") {
			var rows []map[string]any
			if err := json.Unmarshal(data, &rows); err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				if row["name"] == "Standard_B2pts_v2" {
					row["capabilities"] = append(row["capabilities"].([]any), map[string]any{"name": "TrustedLaunchDisabled", "value": "True"})
				}
			}
			return json.Marshal(rows)
		}
		if strings.HasPrefix(command, "vm image show") && !imageSupported {
			var image map[string]any
			if err := json.Unmarshal(data, &image); err != nil {
				t.Fatal(err)
			}
			delete(image, "features")
			return json.Marshal(image)
		}
		return data, nil
	}
	return f
}

func TestAzureTrustedLaunchFiltersSizeAndValidatesImageBeforeWrites(t *testing.T) {
	f := trustedLaunchFixture(t, true)
	r := f.op.Request
	r.Plan, r.Image, r.Architecture, r.AzureSecurityType = "", "", "auto", "TrustedLaunch"
	resolved, _, err := f.a.Resolve(context.Background(), r)
	if err != nil || resolved.Plan != "Standard_B2ats_v2" || resolved.Architecture != "amd64" || resolved.AzureSecurityType != "TrustedLaunch" {
		t.Fatalf("unexpected resolution: %+v, %v", resolved, err)
	}
	r.Plan = "Standard_B2pts_v2"
	if _, _, err := f.a.Resolve(context.Background(), r); err == nil {
		t.Fatal("accepted a size with TrustedLaunchDisabled=True")
	}
	if len(f.writes) != 0 {
		t.Fatal("security preflight mutated the cloud")
	}
	f = trustedLaunchFixture(t, false)
	r.Plan = "Standard_B2ats_v2"
	if _, _, err := f.a.Resolve(context.Background(), r); err == nil || !strings.Contains(err.Error(), "image does not advertise") {
		t.Fatalf("unsupported image was not rejected: %v", err)
	}
}

func TestAzureTrustedLaunchProvisionAndSecurityVerification(t *testing.T) {
	f := newAzureFixture(t)
	// This fixture advertises no TrustedLaunchDisabled capability. The separate
	// real-world-shaped fixture above covers sizes that explicitly disable it.
	f.op.Request.AzureSecurityType = "TrustedLaunch"
	checkedFlags := false
	f.s.options.Run = func(ctx context.Context, exe string, args []string) ([]byte, error) {
		data, err := f.run(ctx, exe, args)
		if err == nil && len(args) >= 2 && args[0] == "vm" && args[1] == "create" {
			checkedFlags = true
			if azureFlag(args, "--security-type") != "TrustedLaunch" || azureFlag(args, "--enable-secure-boot") != "true" || azureFlag(args, "--enable-vtpm") != "true" {
				t.Fatalf("missing security settings: %v", args)
			}
			f.resources["azure-vm"]["securityProfile"] = map[string]any{"securityType": "TrustedLaunch", "uefiSettings": map[string]any{"secureBootEnabled": true, "vTpmEnabled": true}}
		}
		return data, err
	}
	if err := f.a.Provision(context.Background(), f.op, true); err != nil || !checkedFlags {
		t.Fatalf("provision flags=%v error=%v", checkedFlags, err)
	}
	vm := f.resources["azure-vm"]
	obj(obj(vm["securityProfile"])["uefiSettings"])["secureBootEnabled"] = false
	sp, _ := azureSpecFor(*f.op, "azure-vm")
	if err := f.a.finishResource(context.Background(), f.op, sp, vm); err == nil || !strings.Contains(err.Error(), "Trusted Launch") {
		t.Fatalf("security downgrade was not reported: %v", err)
	}
	if f.op.State != "cleanup-required" || cloudResourceOf(f.op, "azure-disk") == nil {
		t.Fatal("failed verification lost cleanup state or billable disk receipt")
	}
}
