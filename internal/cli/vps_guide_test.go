package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/vps"
)

func TestVPSGuideOfflineWithMissingCLIAndBrokenSettings(t *testing.T) {
	settings := isolated(t)
	if err := os.MkdirAll(filepath.Dir(settings), 0700); err != nil {
		t.Fatal(err)
	}
	private := []byte("not valid TOML; secret-that-must-not-be-exported")
	if err := os.WriteFile(settings, private, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	deps := Dependencies{Terminal: func(io.Reader, io.Writer) bool {
		t.Fatal("guide must never prompt")
		return false
	}, VPS: vps.Options{Run: func(context.Context, string, []string) ([]byte, error) {
		t.Fatal("guide must never invoke a cloud CLI")
		return nil, nil
	}}}
	for provider := range vpsGuideProviders {
		t.Run(provider, func(t *testing.T) {
			out, _, err := run(t, deps, "--config", settings, "--read-only", "vps", "guide", "--provider", provider, "--format", "agent", "--json")
			if err != nil {
				t.Fatal(err)
			}
			var g vpsGuide
			if err := json.Unmarshal([]byte(out), &g); err != nil {
				t.Fatal(err)
			}
			if g.CLIInstalled || g.AgentPrompt == "" || len(g.Steps) < 7 || !strings.Contains(out, "brew install") || strings.Contains(out, string(private)) {
				t.Fatalf("invalid offline guide: %s", out)
			}
		})
	}
	after, _ := os.ReadFile(settings)
	if string(after) != string(private) {
		t.Fatal("guide changed settings")
	}
	entries, _ := os.ReadDir(filepath.Dir(settings))
	if len(entries) != 1 {
		t.Fatal("guide created an inventory or journal")
	}
}

func TestVPSGuideShellCommandsPreserveLiteralArgumentsAndRequireMissingValues(t *testing.T) {
	// Execute the generated preview against a harmless argument recorder. This
	// exercises shell quoting and the missing-value guards, not a cloud account.
	dir := t.TempDir()
	fake := filepath.Join(dir, "lazy clash")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "injected")
	profile := "dev' $(touch " + marker + ") `touch " + marker + "`"
	r := vps.CreateRequest{ID: "test-vps", Provider: "aws-lightsail", Region: "ap-northeast-1", Profile: profile, SSHKey: filepath.Join(dir, "a' key.pub"), SSHCIDR: "192.0.2.1/32", Plan: "micro_3_0"}
	g, err := buildVPSGuide(r, guideQuote(fake), "security_token", "markdown", exec.LookPath)
	if err != nil {
		t.Fatal(err)
	}
	var preview, apply string
	for _, step := range g.Steps {
		if step.Title == "Preview the VM" {
			preview = step.Commands[0]
		}
		if step.Title == "Apply the reviewed VM" {
			apply = step.Commands[0]
		}
	}
	output, err := exec.Command("/bin/sh", "-c", preview).CombinedOutput()
	if err != nil {
		t.Fatalf("preview shell failed: %s %v", output, err)
	}
	if !strings.Contains(string(output), "--profile\n"+profile+"\n") || !strings.Contains(string(output), "--ssh-key\n"+r.SSHKey+"\n") || strings.Contains(string(output), "--yes") {
		t.Fatalf("arguments were altered: %s", output)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("generated command performed shell substitution")
	}
	blocked := exec.Command("/bin/sh", "-c", "unset LC_REVIEWED_DIGEST; "+apply)
	if output, err = blocked.CombinedOutput(); err == nil || strings.Contains(string(output), "--yes\n") {
		t.Fatalf("missing reviewed digest did not block execution: %s %v", output, err)
	}
	r.Region = ""
	g, err = buildVPSGuide(r, guideQuote(fake), "security_token", "markdown", exec.LookPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range g.Steps {
		if step.Title == "Preview the VM" {
			output, err = exec.Command("/bin/sh", "-c", "unset LC_REGION; "+step.Commands[0]).CombinedOutput()
			if err == nil || strings.Contains(string(output), "--provider\n") {
				t.Fatalf("unset region reached the executable: %s %v", output, err)
			}
		}
	}
}

func TestVPSGuidePreservesScopeAndOracleSession(t *testing.T) {
	isolated(t)
	t.Setenv("LAZYCLASH_SERVERS_CONFIG", "chosen servers.toml")
	out, _, err := run(t, Dependencies{}, "vps", "guide", "oracle-test", "--provider", "oracle", "--profile", "my-session", "--region", "ap-tokyo-1", "--tenancy", "ocid.tenancy", "--compartment", "ocid.compartment", "--format", "agent", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var g vpsGuide
	if err = json.Unmarshal([]byte(out), &g); err != nil {
		t.Fatal(err)
	}
	for _, step := range g.Steps {
		for _, command := range step.Commands {
			if strings.Contains(command, " vps ") || strings.Contains(command, " servers ") {
				if !strings.HasPrefix(command, "OCI_CLI_AUTH=security_token ") || !strings.Contains(command, "--servers-config") || !strings.Contains(command, "chosen servers.toml") {
					t.Fatalf("lost session or inventory scope: %s", command)
				}
			}
		}
	}
	if strings.Contains(out, "--expect DIGEST") || strings.Contains(out, "--yes --expect REVIEWED_DIGEST") {
		t.Fatal("unguarded digest placeholder")
	}
}

func TestVPSGuideInputValidationAndCompletion(t *testing.T) {
	isolated(t)
	for _, args := range [][]string{{}, {"--provider", "unknown"}, {"--provider", "aws-lightsail", "--format", "script"}, {"--provider", "aws-lightsail", "--oci-auth", "api_key"}, {"--provider", "oracle", "--region", "bad\x1bregion"}, {"--provider", "oracle", "--profile", "```"}} {
		_, _, err := run(t, Dependencies{}, append([]string{"vps", "guide"}, args...)...)
		if ExitCode(err) != 2 {
			t.Fatalf("invalid guide input %v: %v", args, err)
		}
	}
	for flag, want := range map[string]string{"--provider": "aws-lightsail", "--format": "agent", "--oci-auth": "security_token"} {
		out, _, err := run(t, Dependencies{}, "__complete", "vps", "guide", flag, "")
		if err != nil || !strings.Contains(out, want) {
			t.Fatal(fmt.Sprintf("completion %s: %s %v", flag, out, err))
		}
	}
}
