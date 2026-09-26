package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/spf13/cobra"
)

func registrationCandidate(id, port string) config.Target {
	return config.Target{ID: id, Controller: "http://127.0.0.1:" + port, SSHHost: "fixture-host", SourceConfig: "/fixture/" + id + ".yaml", Configs: []config.CoreConfig{{ID: "runtime", Path: "/fixture/" + id + ".yaml"}}, Secret: "private-secret", Transient: true, TransportOverride: true, AuthRequired: true, RuleSource: &config.RuleSource{Kind: "file"}, ConfigSource: &config.ConfigSource{Kind: "file"}, Service: &config.ClientService{Kind: "systemd"}, ManagedCoreID: "owner"}
}

func registrationAnswers(spec wizard.Spec) map[string]string {
	values := map[string]string{}
	for _, f := range spec.Fields {
		values[f.Key] = f.Value
	}
	return values
}

func registrationFixture(t *testing.T, cfg *config.Config) targetRegistrationOps {
	t.Helper()
	return targetRegistrationOps{
		load: func() (config.Config, error) { return *cfg, nil },
		save: func(next config.Config) error { *cfg = next; return nil },
		ui: targetRegistrationUI{
			choose: func(context.Context, string, []wizard.Choice) (string, error) {
				t.Fatal("unexpected picker")
				return "", nil
			},
			edit: func(context.Context, wizard.Spec) (map[string]string, error) {
				t.Fatal("unexpected form")
				return nil, nil
			},
		},
	}
}

func TestTargetRegistrationReviewsSingleCandidateAndSavesOnlyReferences(t *testing.T) {
	cfg := config.Config{}
	ops := registrationFixture(t, &cfg)
	candidate := registrationCandidate("core-found", "19090")
	ops.discover = func(_ context.Context, host string) ([]config.Target, error) {
		if host != "fixture-host" {
			t.Fatalf("wrong host %q", host)
		}
		return []config.Target{candidate}, nil
	}
	edits := 0
	ops.ui.edit = func(_ context.Context, spec wizard.Spec) (map[string]string, error) {
		edits++
		if len(cfg.Targets) != 0 || spec.Title != "Review target registration" || spec.SubmitLabel != "Save" || !strings.Contains(spec.Description, "without testing") {
			t.Fatalf("missing review before save: %+v", spec)
		}
		return registrationAnswers(spec), nil
	}
	result, err := runTargetRegistration(context.Background(), config.Target{SSHHost: "fixture-host"}, nil, true, "/settings.toml", ops)
	if err != nil || edits != 1 || result.existing {
		t.Fatalf("result=%+v edits=%d err=%v", result, edits, err)
	}
	got := result.target
	if got.ID != candidate.ID || got.SourceConfig != candidate.SourceConfig || !reflect.DeepEqual(got.Configs, candidate.Configs) || cfg.DefaultTarget != got.ID {
		t.Fatalf("lost discovered metadata: %+v", got)
	}
	if got.Secret != "" || got.Transient || got.TransportOverride || got.AuthRequired || got.RuleSource != nil || got.ConfigSource != nil || got.Service != nil || got.ManagedCoreID != "" {
		t.Fatalf("unsafe persisted target: %+v", got)
	}
	if len(cfg.Targets) != 1 || !reflect.DeepEqual(cfg.Targets[0], got) {
		t.Fatalf("wrong saved target: %+v", cfg)
	}
	if candidate.Secret != "private-secret" || !candidate.Transient {
		t.Fatal("mutated discovered candidate")
	}
}

func TestTargetRegistrationMultipleUsesChosenCandidateAndExplicitFields(t *testing.T) {
	cfg := config.Config{}
	ops := registrationFixture(t, &cfg)
	first, second := registrationCandidate("core-first", "19090"), registrationCandidate("core-second", "19091")
	second.SecretFile = "/candidate-secret"
	ops.discover = func(context.Context, string) ([]config.Target, error) { return []config.Target{first, second}, nil }
	ops.ui.choose = func(_ context.Context, title string, choices []wizard.Choice) (string, error) {
		if title != "Choose discovered controller" || len(choices) != 2 || !strings.Contains(choices[1].Label, second.Controller) || !strings.Contains(choices[1].Label, second.SourceConfig) {
			t.Fatalf("ambiguous picker: %s %+v", title, choices)
		}
		return "1", nil
	}
	ops.ui.edit = func(_ context.Context, spec wizard.Spec) (map[string]string, error) {
		values := registrationAnswers(spec)
		if values["controller"] != second.Controller || values["id"] != "chosen-name" || values["secret-env"] != "MY_SECRET" || values["secret-file"] != "" {
			t.Fatalf("wrong candidate/overrides: %+v", values)
		}
		return values, nil
	}
	result, err := runTargetRegistration(context.Background(), config.Target{ID: "chosen-name", SSHHost: "fixture-host", SecretEnv: "MY_SECRET"}, map[string]bool{"id": true, "secret-env": true}, true, "settings", ops)
	if err != nil || result.target.SourceConfig != second.SourceConfig || len(cfg.Targets) != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestTargetRegistrationZeroAndAuthenticationFailureRetainPrefill(t *testing.T) {
	for _, discoveryErr := range []error{nil, errors.New("SSH authentication failed")} {
		t.Run("manual-"+fmtError(discoveryErr), func(t *testing.T) {
			cfg := config.Config{}
			ops := registrationFixture(t, &cfg)
			ops.discover = func(context.Context, string) ([]config.Target, error) { return nil, discoveryErr }
			ops.ui.choose = func(_ context.Context, title string, choices []wizard.Choice) (string, error) {
				if !strings.Contains(title, "Discover SSH controller") || len(choices) != 2 {
					t.Fatalf("missing recovery: %q %+v", title, choices)
				}
				return "manual", nil
			}
			ops.ui.edit = func(_ context.Context, spec wizard.Spec) (map[string]string, error) {
				values := registrationAnswers(spec)
				if values["id"] != "manual-id" || values["ssh"] != "fixture-host" || values["secret-env"] != "MY_SECRET" {
					t.Fatalf("lost prefill: %+v", values)
				}
				values["controller"] = "127.0.0.1:19092"
				return values, nil
			}
			result, err := runTargetRegistration(context.Background(), config.Target{ID: "manual-id", SSHHost: "fixture-host", SecretEnv: "MY_SECRET"}, map[string]bool{"id": true, "secret-env": true}, true, "settings", ops)
			if err != nil || result.target.Controller != "http://127.0.0.1:19092" || result.target.SecretEnv != "MY_SECRET" {
				t.Fatalf("%+v %v", result, err)
			}
		})
	}
}

func fmtError(err error) string {
	if err == nil {
		return "zero"
	}
	return "auth"
}

func TestTargetRegistrationRetriesDiscoveryAndPreservesDraftAcrossBack(t *testing.T) {
	cfg := config.Config{}
	ops := registrationFixture(t, &cfg)
	discoveries, edits := 0, 0
	ops.discover = func(context.Context, string) ([]config.Target, error) {
		discoveries++
		if discoveries == 1 {
			return nil, nil
		}
		return []config.Target{registrationCandidate("core-found", "19090")}, nil
	}
	ops.ui.choose = func(_ context.Context, title string, _ []wizard.Choice) (string, error) {
		if strings.HasPrefix(title, "Discover SSH controller") {
			return "retry", nil
		}
		return "edit", nil
	}
	// An OS-absolute path: "/local/secret" is relative on Windows, where the
	// registration loop would keep asking for a valid draft forever.
	secretFile := filepath.Join(t.TempDir(), "secret")
	ops.ui.edit = func(_ context.Context, spec wizard.Spec) (map[string]string, error) {
		edits++
		if edits > 5 {
			t.Fatalf("registration kept re-editing: %s", spec.Description)
		}
		values := registrationAnswers(spec)
		if edits == 1 {
			values["name"] = "Edited name"
			values["secret-file"] = secretFile
			return values, wizard.ErrBack
		}
		if values["name"] != "Edited name" || values["secret-file"] != secretFile {
			t.Fatalf("Back discarded draft: %+v", values)
		}
		return values, nil
	}
	result, err := runTargetRegistration(context.Background(), config.Target{SSHHost: "fixture-host"}, nil, true, "settings", ops)
	if err != nil || discoveries != 2 || edits != 2 || result.target.Name != "Edited name" {
		t.Fatalf("result=%+v discoveries=%d edits=%d err=%v", result, discoveries, edits, err)
	}
}

func TestTargetRegistrationExistingEndpointAndIDCollision(t *testing.T) {
	t.Run("existing endpoint", func(t *testing.T) {
		candidate := registrationCandidate("new-generated-id", "19090")
		cfg := config.Config{Targets: []config.Target{{ID: "already-saved", Controller: candidate.Controller + "/", SSHHost: candidate.SSHHost}}}
		ops := registrationFixture(t, &cfg)
		ops.discover = func(context.Context, string) ([]config.Target, error) { return []config.Target{candidate}, nil }
		ops.save = func(config.Config) error { t.Fatal("duplicate endpoint wrote settings"); return nil }
		result, err := runTargetRegistration(context.Background(), config.Target{SSHHost: "fixture-host"}, nil, true, "settings", ops)
		if err != nil || !result.existing || result.target.ID != "already-saved" || len(cfg.Targets) != 1 {
			t.Fatalf("%+v %v", result, err)
		}
	})
	t.Run("ID collision", func(t *testing.T) {
		original := config.Target{ID: "core-found", Controller: "http://127.0.0.1:9999", SSHHost: "fixture-host"}
		cfg := config.Config{DefaultTarget: original.ID, Targets: []config.Target{original}}
		ops := registrationFixture(t, &cfg)
		ops.discover = func(context.Context, string) ([]config.Target, error) {
			return []config.Target{registrationCandidate("core-found", "19090")}, nil
		}
		edits := 0
		ops.ui.edit = func(_ context.Context, spec wizard.Spec) (map[string]string, error) {
			edits++
			values := registrationAnswers(spec)
			if edits == 1 {
				values["name"] = "Retained name"
				return values, nil
			}
			if !strings.Contains(spec.Description, "already exists") || values["name"] != "Retained name" || values["controller"] != "http://127.0.0.1:19090" {
				t.Fatalf("collision discarded draft: %+v %+v", spec, values)
			}
			values["id"] = "renamed"
			return values, nil
		}
		result, err := runTargetRegistration(context.Background(), config.Target{SSHHost: "fixture-host"}, nil, true, "settings", ops)
		if err != nil || edits != 2 || result.target.ID != "renamed" || len(cfg.Targets) != 2 || !reflect.DeepEqual(cfg.Targets[0], original) || cfg.DefaultTarget != original.ID {
			t.Fatalf("result=%+v cfg=%+v err=%v", result, cfg, err)
		}
	})
}

func TestTargetRegistrationTransportEditClearsDetectedMetadata(t *testing.T) {
	cfg := config.Config{}
	ops := registrationFixture(t, &cfg)
	ops.discover = func(context.Context, string) ([]config.Target, error) {
		return []config.Target{registrationCandidate("core-found", "19090")}, nil
	}
	ops.ui.edit = func(_ context.Context, spec wizard.Spec) (map[string]string, error) {
		values := registrationAnswers(spec)
		values["controller"] = "http://127.0.0.1:2222"
		return values, nil
	}
	result, err := runTargetRegistration(context.Background(), config.Target{SSHHost: "fixture-host"}, nil, true, "settings", ops)
	if err != nil || len(result.target.Configs) != 0 || result.target.SourceConfig != "" {
		t.Fatalf("stale transport metadata: %+v %v", result, err)
	}
	changed := mergeDiscoveredTarget(registrationCandidate("core-other", "19091"), result.target, map[string]bool{"controller": true})
	if changed.SourceConfig != "" || len(changed.Configs) != 0 || changed.Secret != "" {
		t.Fatalf("reselected candidate has wrong metadata: %+v", changed)
	}
}

func TestTargetRegistrationSanitizesDiscoveredDisplayNamesWithoutChangingSourcePaths(t *testing.T) {
	candidate := registrationCandidate("core-found", "19090")
	candidate.Name = "Fixture\x1b]52;c;PRIVATE_CLIPBOARD\a\x1b[31m core"
	candidate.Configs[0].Name = "Runtime\x1b[32m YAML"
	got := mergeDiscoveredTarget(candidate, config.Target{SSHHost: "fixture-host"}, nil)
	if got.Name != "Fixture core" || got.Configs[0].Name != "Runtime YAML" || got.SourceConfig != candidate.SourceConfig || got.Configs[0].Path != candidate.Configs[0].Path {
		t.Fatalf("bad sanitized annotations: %+v", got)
	}
	if candidate.Configs[0].Name != "Runtime\x1b[32m YAML" {
		t.Fatal("mutated candidate metadata")
	}
}

func TestTargetRegistrationSaveConflictRetainsDraftAndReloads(t *testing.T) {
	cfg := config.Config{}
	ops := registrationFixture(t, &cfg)
	loads, saves, edits := 0, 0, 0
	ops.load = func() (config.Config, error) { loads++; return cfg, nil }
	ops.save = func(next config.Config) error {
		saves++
		if saves == 1 {
			cfg.Targets = append(cfg.Targets, config.Target{ID: "concurrent", Controller: "http://127.0.0.1:19999"})
			cfg.DefaultTarget = "concurrent"
			return config.ErrConflict
		}
		cfg = next
		return nil
	}
	ops.ui.edit = func(_ context.Context, spec wizard.Spec) (map[string]string, error) {
		edits++
		values := registrationAnswers(spec)
		if edits == 2 && (!strings.Contains(spec.Description, "Save failed") || values["name"] != "Draft") {
			t.Fatalf("lost conflict draft: %+v", spec)
		}
		return values, nil
	}
	result, err := runTargetRegistration(context.Background(), config.Target{ID: "manual", Name: "Draft", Controller: "http://127.0.0.1:19090"}, nil, false, "settings", ops)
	if err != nil || saves != 2 || edits != 2 || loads != 4 || len(cfg.Targets) != 2 || result.target.Name != "Draft" {
		t.Fatalf("result=%+v cfg=%+v loads=%d saves=%d edits=%d err=%v", result, cfg, loads, saves, edits, err)
	}
}

func TestTargetRegistrationCancelAndWindowsManualNeverSaveOrDiscover(t *testing.T) {
	cfg := config.Config{}
	ops := registrationFixture(t, &cfg)
	ops.discover = func(context.Context, string) ([]config.Target, error) {
		t.Fatal("Windows must not run POSIX discovery")
		return nil, nil
	}
	ops.save = func(config.Config) error { t.Fatal("canceled form saved"); return nil }
	ops.ui.edit = func(_ context.Context, spec wizard.Spec) (map[string]string, error) {
		if !strings.Contains(spec.Description, "Windows") {
			t.Fatal("missing remote discovery limitation")
		}
		return registrationAnswers(spec), wizard.ErrCanceled
	}
	_, err := runTargetRegistration(context.Background(), config.Target{ID: "windows", SSHHost: "fixture-host", HostOS: "windows"}, nil, true, "settings", ops)
	if !errors.Is(err, wizard.ErrCanceled) || len(cfg.Targets) != 0 {
		t.Fatalf("wrong cancellation %v %+v", err, cfg)
	}
}

func TestTargetDiscoveryNoninteractiveIntentNeverAccessesNetwork(t *testing.T) {
	isolated(t)
	deps := Dependencies{Terminal: func(io.Reader, io.Writer) bool { return false }, Discover: func(context.Context, string) ([]config.Target, error) {
		t.Fatal("incomplete noninteractive command discovered")
		return nil, nil
	}, Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		t.Fatal("incomplete noninteractive command opened core")
		return nil, nil, nil
	}}
	for _, args := range [][]string{{"targets", "add", "--ssh", "fixture-host"}, {"targets", "add", "explicit", "--ssh", "fixture-host", "--json"}, {"targets", "add", "--interactive"}, {"targets", "add", "--interactive", "--json", "--controller", "http://127.0.0.1:19090"}} {
		code, out, errOut := runProcess(t, deps, args...)
		if code != 2 || out != "" || (!strings.Contains(errOut, "discover --ssh") && !strings.Contains(errOut, "--interactive requires")) {
			t.Fatalf("%v code=%d out=%q err=%q", args, code, out, errOut)
		}
	}
}

func TestTargetDiscoveryUsesActualAddSSHFlagBeforeAnyReview(t *testing.T) {
	isolated(t)
	for _, args := range [][]string{
		{"targets", "add", "--ssh", "fixture-host", "--secret-env", "LOCAL_SECRET"},
		{"--ssh", "fixture-host", "targets", "add", "--secret-file", "/local/secret"},
	} {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		deps := Dependencies{
			Terminal: func(io.Reader, io.Writer) bool { return true },
			Discover: func(_ context.Context, host string) ([]config.Target, error) {
				calls++
				if host != "fixture-host" {
					t.Fatalf("%v discovered %q", args, host)
				}
				cancel()
				return nil, context.Canceled
			},
			Authenticate: func(context.Context, string) (*exec.Cmd, error) {
				t.Fatal("canceled discovery authenticated")
				return nil, nil
			},
		}
		var output bytes.Buffer
		cmd := New(deps)
		cmd.SetArgs(args)
		cmd.SetIn(strings.NewReader(""))
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		err := cmd.ExecuteContext(ctx)
		cancel()
		if !errors.Is(err, context.Canceled) || calls != 1 || !strings.Contains(output.String(), "Discovering controllers on fixture-host") {
			t.Fatalf("%v calls=%d output=%q err=%v", args, calls, output.String(), err)
		}
	}
}

func TestTargetDiscoveryRejectsInvalidSSHBeforeHintsOrNetwork(t *testing.T) {
	isolated(t)
	deps := Dependencies{Discover: func(context.Context, string) ([]config.Target, error) {
		t.Fatal("invalid SSH discovered")
		return nil, nil
	}}
	code, out, errOut := runProcess(t, deps, "targets", "add", "--ssh", "bad\x1b]52;c;PRIVATE_CLIPBOARD\a")
	if code != 2 || out != "" || !strings.Contains(errOut, "must not contain control") || strings.Contains(errOut, "PRIVATE_CLIPBOARD") || strings.Contains(errOut, "\x1b") {
		t.Fatalf("unsafe invalid host error: code=%d out=%q err=%q", code, out, errOut)
	}
}

func TestDiscoverCommandAuthenticatesExactHostAndRetriesOnce(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetIn(strings.NewReader(""))
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	calls := 0
	o := options{ssh: "wrong-global-host", deps: Dependencies{Terminal: func(io.Reader, io.Writer) bool { return true }, Authenticate: func(ctx context.Context, host string) (*exec.Cmd, error) {
		if host != "fixture-host" {
			t.Fatalf("auth wrong host %q", host)
		}
		return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 0"), nil
	}}}
	found, err := o.discoverCommandUsing(cmd, "fixture-host", func(_ context.Context, host string) ([]config.Target, error) {
		calls++
		if host != "fixture-host" {
			t.Fatalf("discover wrong host %q", host)
		}
		if calls == 1 {
			return nil, &connection.AuthRequiredError{Host: host}
		}
		return []config.Target{registrationCandidate("core-found", "19090")}, nil
	})
	if err != nil || calls != 2 || len(found) != 1 {
		t.Fatalf("calls=%d found=%+v err=%v", calls, found, err)
	}
}
