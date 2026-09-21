package cli

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/vps"
)

func TestCloudVPSMachineAndInvalidInputsNeverPromptOrCallProvider(t *testing.T) {
	isolated(t)
	for _, args := range [][]string{
		{"vps", "create", "--provider", "azure", "--subscription", "subscription-id", "--interactive", "--json"},
		{"vps", "create", "--provider", "aws-lightsail", "--interactive", "--json"},
		{"vps", "create", "--provider", "aws-ec2", "--interactive", "--json"},
		{"vps", "create", "--provider", "azure", "--architecture", "aarch64", "--interactive"},
		{"vps", "create", "--provider", "aws-ec2", "--disk-gb", "-1", "--interactive"},
		{"vps", "quote", "--provider", "aws-ec2", "--plan", "t4g.micro", "--architecture", "typo"},
		{"vps", "estimate", "--provider", "aws-lightsail", "--plan", "fixture", "--egress", "1", "--ingress", "NaN", "--json"},
		{"vps", "estimate", "--provider", "aws-lightsail", "--plan", "fixture", "--egress", "1", "--ingress", "-1", "--json"},
		{"--read-only", "vps", "create", "fixture", "--provider", "azure", "--yes", "--expect", "fixture"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			calls := 0
			deps := Dependencies{Terminal: func(io.Reader, io.Writer) bool { return true }, VPS: vps.Options{Run: func(context.Context, string, []string) ([]byte, error) {
				calls++
				return nil, nil
			}}}
			_, _, err := run(t, deps, args...)
			if ExitCode(err) != 2 {
				t.Fatalf("want usage error before I/O: %v", err)
			}
			if calls != 0 {
				t.Fatalf("invalid/machine invocation contacted provider %d times", calls)
			}
		})
	}
}

func TestCloudVPSCompletionIsOffline(t *testing.T) {
	isolated(t)
	deps := Dependencies{VPS: vps.Options{Run: func(context.Context, string, []string) ([]byte, error) {
		t.Fatal("completion must not contact a cloud account")
		return nil, nil
	}}}
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"vps", "create", "--provider", ""}, "azure"},
		{[]string{"vps", "quote", "--provider", ""}, "aws-lightsail"},
		{[]string{"vps", "estimate", "--provider", ""}, "aws-ec2"},
		{[]string{"vps", "create", "--architecture", ""}, "arm64"},
		{[]string{"vps", "discover", "--kind", ""}, "zones"},
		{[]string{"vps", "discover", "--kind", ""}, "subscriptions"},
	} {
		out, _, err := run(t, deps, append([]string{"__complete"}, test.args...)...)
		if err != nil || !strings.Contains(out, test.want) || !strings.Contains(out, ":4") {
			t.Fatalf("%v => %q, %v", test.args, out, err)
		}
		if strings.Contains(out, "mihomo") || strings.Contains(out, "verge") {
			t.Fatalf("VPS discovery used unrelated core-kind completions: %s", out)
		}
	}
}

func TestCloudWizardPreservesArchitectureAndDiskPrefills(t *testing.T) {
	for _, provider := range []string{"azure", "aws-lightsail", "aws-ec2"} {
		t.Run(provider, func(t *testing.T) {
			original := vps.CreateRequest{Provider: provider, SubscriptionID: "fixture-subscription", Architecture: "arm64", AvailabilityZone: "fixture-zone", DiskGB: 64}
			values := map[string]string{}
			for _, field := range vpsCloudWizardFields(original) {
				values[field.Key] = field.Value
			}
			req := vps.CreateRequest{Provider: provider}
			if err := vpsApplyCloudWizardFields(&req, values); err != nil {
				t.Fatal(err)
			}
			if req.Architecture != original.Architecture || req.AvailabilityZone != original.AvailabilityZone {
				t.Fatalf("lost plan constraints: %+v", req)
			}
			if provider == "azure" && req.SubscriptionID != original.SubscriptionID {
				t.Fatal("lost Azure subscription")
			}
			if provider != "aws-lightsail" && req.DiskGB != original.DiskGB {
				t.Fatal("lost disk size")
			}
			if provider == "aws-lightsail" && req.DiskGB != 0 {
				t.Fatal("Lightsail bundle exposed mutable root disk")
			}
			if !vpsUsesPublicKeyFile(provider) {
				t.Fatal("new provider must collect a public key file")
			}
		})
	}
	for _, disk := range []string{"-1", "0", "1.5", "oops"} {
		req := vps.CreateRequest{Provider: "aws-ec2"}
		if err := vpsApplyCloudWizardFields(&req, map[string]string{"disk": disk}); ExitCode(err) != 2 {
			t.Fatalf("invalid disk %q accepted: %v", disk, err)
		}
	}
}
