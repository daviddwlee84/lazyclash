package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/spf13/cobra"
)

// The host is explicit because targets add has local flags which shadow the
// root's temporary transport flags. Authentication happens between UI screens.
func (o *options) discoverCommandUsing(cmd *cobra.Command, host string, discover func(context.Context, string) ([]config.Target, error)) ([]config.Target, error) {
	targets, err := discover(cmd.Context(), host)
	if err != nil && connection.IsAuthRequired(err) && !o.json && o.deps.Terminal(cmd.InOrStdin(), cmd.ErrOrStderr()) {
		auth, e := o.deps.Authenticate(cmd.Context(), host)
		if e != nil {
			return nil, e
		}
		auth.Stdin, auth.Stdout, auth.Stderr = cmd.InOrStdin(), cmd.ErrOrStderr(), cmd.ErrOrStderr()
		if e = auth.Run(); e != nil {
			return nil, fmt.Errorf("SSH authentication failed: %w", e)
		}
		return discover(cmd.Context(), host)
	}
	return targets, err
}

func quoteTargetArgument(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func validateTargetRegistrationPrefill(draft config.Target) error {
	if draft.ID == "" {
		draft.ID = "registration"
	}
	if draft.Controller == "" {
		draft.Controller = "http://127.0.0.1:9090"
	} else if !strings.Contains(draft.Controller, "://") {
		draft.Controller = "http://" + draft.Controller
	}
	return config.Validate(config.Config{Targets: []config.Target{draft}})
}

type targetRegistrationUI struct {
	choose func(context.Context, string, []wizard.Choice) (string, error)
	edit   func(context.Context, wizard.Spec) (map[string]string, error)
}
type targetRegistrationOps struct {
	discover func(context.Context, string) ([]config.Target, error)
	load     func() (config.Config, error)
	save     func(config.Config) error
	ui       targetRegistrationUI
}
type targetRegistrationResult struct {
	target   config.Target
	existing bool
}

func (o *options) addTargetWithDiscovery(cmd *cobra.Command, draft config.Target, discover bool) error {
	defer connection.CloseAuthentications()
	_, path, err := o.load(cmd)
	if err != nil {
		return err
	}
	explicit := map[string]bool{}
	for _, field := range targetRegistrationFields(draft) {
		if cmd.Flags().Changed(field.Key) {
			explicit[field.Key] = true
		}
	}
	if draft.ID != "" {
		explicit["id"] = true
	}
	ops := targetRegistrationOps{
		discover: func(ctx context.Context, host string) ([]config.Target, error) {
			if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "Discovering controllers on %s…\n", core.Sanitize(host)); err != nil {
				return nil, fmt.Errorf("write discovery status: %w", err)
			}
			return o.discoverCommandUsing(cmd, host, o.deps.Discover)
		},
		load: func() (config.Config, error) { cfg, _, e := o.load(cmd); return cfg, e },
		save: func(cfg config.Config) error { return saveSettings(path, cfg) },
		ui: targetRegistrationUI{
			choose: func(ctx context.Context, title string, choices []wizard.Choice) (string, error) {
				return wizard.Choose(ctx, title, choices, cmd.InOrStdin(), cmd.OutOrStdout())
			},
			edit: func(ctx context.Context, spec wizard.Spec) (map[string]string, error) {
				return wizard.EditDraft(ctx, spec, cmd.InOrStdin(), cmd.OutOrStdout())
			},
		},
	}
	result, err := runTargetRegistration(cmd.Context(), draft, explicit, discover, path, ops)
	if err != nil {
		return err
	}
	if result.existing {
		return o.result(cmd, "Controller already registered as "+result.target.ID+"; use targets edit to change its fields")
	}
	return o.result(cmd, "Saved target "+result.target.ID)
}

func runTargetRegistration(ctx context.Context, draft config.Target, explicit map[string]bool, discover bool, path string, ops targetRegistrationOps) (targetRegistrationResult, error) {
	explicit = maps.Clone(explicit)
	if explicit == nil {
		explicit = map[string]bool{}
	}
	var candidates []config.Target
	message := ""
	for {
		if err := ctx.Err(); err != nil {
			return targetRegistrationResult{}, err
		}
		if discover && draft.HostOS == "windows" {
			discover = false
			message = "Remote discovery currently requires a POSIX host. Enter the Windows core controller URL manually."
		}
		if discover {
			found, err := ops.discover(ctx, draft.SSHHost)
			if ctx.Err() != nil {
				return targetRegistrationResult{}, ctx.Err()
			}
			if err != nil || len(found) == 0 {
				message = "No controllers found on " + draft.SSHHost + "."
				if err != nil {
					message = "Discovery failed: " + core.Sanitize(err.Error())
				}
				choice, e := ops.ui.choose(ctx, "Discover SSH controller · "+message, []wizard.Choice{{Value: "retry", Label: "Retry discovery"}, {Value: "manual", Label: "Enter controller manually"}})
				if e != nil {
					return targetRegistrationResult{}, e
				}
				if choice == "retry" {
					continue
				}
				discover = false
				candidates = nil
			} else {
				candidates = found
				chosen := 0
				if len(candidates) > 1 {
					choices := make([]wizard.Choice, 0, len(candidates))
					for i, candidate := range candidates {
						label := candidate.Controller
						if candidate.SourceConfig != "" {
							label += " · " + candidate.SourceConfig
						}
						if candidate.AuthRequired {
							label += " · controller authentication required"
						}
						choices = append(choices, wizard.Choice{Value: fmt.Sprint(i), Label: core.Sanitize(label)})
					}
					choice, e := ops.ui.choose(ctx, "Choose discovered controller", choices)
					if e != nil {
						return targetRegistrationResult{}, e
					}
					chosen = -1
					for i := range candidates {
						if choice == fmt.Sprint(i) {
							chosen = i
							break
						}
					}
					if chosen < 0 {
						return targetRegistrationResult{}, errors.New("choose one discovered controller")
					}
				}
				draft = mergeDiscoveredTarget(candidates[chosen], draft, explicit)
				discover = false
				message = "Found controller. Review the detected ID, endpoint and source path before saving."
				if draft.AuthRequired {
					message += " Discovery could not authenticate this controller. Local secret references entered here are saved without testing them."
				}
			}
		}
		cfg, err := ops.load()
		if err != nil {
			return targetRegistrationResult{}, err
		}
		if existing, ok := existingRegistration(cfg, draft); ok {
			return targetRegistrationResult{target: existing, existing: true}, nil
		}
		spec := wizard.Spec{Title: "Review target registration", Description: message + "\nSettings: " + path + "\nSource YAML supplies matching controller credentials only; no persistent write owner is granted.", SubmitLabel: "Save", Back: true, Fields: targetRegistrationFields(draft)}
		values, editErr := ops.ui.edit(ctx, spec)
		previous := draft
		draft = targetRegistrationValues(draft, values)
		for _, field := range targetRegistrationFields(previous) {
			if value, ok := values[field.Key]; ok && value != field.Value {
				explicit[field.Key] = true
			}
		}
		if previous.Controller != draft.Controller || previous.SSHHost != draft.SSHHost || previous.HostOS != draft.HostOS {
			draft.Configs = nil
			if !explicit["source-config"] {
				draft.SourceConfig = ""
			}
			draft.Secret = ""
		}
		if errors.Is(editErr, wizard.ErrBack) {
			choices := []wizard.Choice{{Value: "edit", Label: "Continue editing this draft"}}
			if draft.SSHHost != "" {
				choices = append(choices, wizard.Choice{Value: "discover", Label: "Discover controllers on this SSH host again"})
			}
			choice, e := ops.ui.choose(ctx, "Target registration · draft retained", choices)
			if e != nil {
				return targetRegistrationResult{}, e
			}
			discover = choice == "discover"
			continue
		}
		if editErr != nil {
			return targetRegistrationResult{}, editErr
		}
		draft = registrationSafeTarget(draft)
		if draft.Controller != "" && !strings.Contains(draft.Controller, "://") {
			draft.Controller = "http://" + draft.Controller
		}
		if err = config.Validate(config.Config{Targets: []config.Target{draft}}); err != nil {
			message = "Invalid target: " + core.Sanitize(err.Error())
			continue
		}
		cfg, err = ops.load()
		if err != nil {
			message = "Cannot load settings: " + core.Sanitize(err.Error())
			continue
		}
		if existing, ok := existingRegistration(cfg, draft); ok {
			return targetRegistrationResult{target: existing, existing: true}, nil
		}
		if _, err = targetIndex(cfg, draft.ID); err == nil {
			message = "Target ID " + draft.ID + " already exists. Choose another ID; the existing target will not be replaced."
			continue
		}
		cfg.Targets = append(cfg.Targets, draft)
		if cfg.DefaultTarget == "" {
			cfg.DefaultTarget = draft.ID
		}
		if err = ops.save(cfg); err != nil {
			message = "Save failed: " + core.Sanitize(err.Error())
			continue
		}
		return targetRegistrationResult{target: draft}, nil
	}
}

func existingRegistration(cfg config.Config, draft config.Target) (config.Target, bool) {
	if draft.Controller == "" {
		return config.Target{}, false
	}
	endpoint := strings.TrimSuffix(draft.Controller, "/")
	if !strings.Contains(endpoint, "://") {
		endpoint = "http://" + endpoint
	}
	for _, target := range cfg.Targets {
		if target.SSHHost == draft.SSHHost && strings.TrimSuffix(target.Controller, "/") == endpoint {
			return target, true
		}
	}
	return config.Target{}, false
}

func registrationSafeTarget(target config.Target) config.Target {
	target.Secret = ""
	target.Transient = false
	target.TransportOverride = false
	target.AuthRequired = false
	target.RuleSource = nil
	target.ConfigSource = nil
	target.Service = nil
	target.ManagedCoreID = ""
	return target
}

func mergeDiscoveredTarget(candidate, draft config.Target, explicit map[string]bool) config.Target {
	originalController, originalSSH, originalOS := candidate.Controller, candidate.SSHHost, candidate.HostOS
	candidate.SSHHost = draft.SSHHost
	// Display names are local annotations, not remote API identifiers. Strip
	// terminal control sequences from discovered labels before making a draft.
	candidate.Name = core.Sanitize(candidate.Name)
	fields := targetRegistrationFields(draft)
	values := map[string]string{}
	for _, field := range fields {
		if explicit[field.Key] {
			values[field.Key] = field.Value
		}
	}
	candidate = targetRegistrationValues(candidate, values)
	if explicit["secret-env"] {
		candidate.SecretFile = ""
	} else if explicit["secret-file"] {
		candidate.SecretEnv = ""
	}
	if explicit["probe-password-env"] {
		candidate.ProbePasswordFile = ""
	} else if explicit["probe-password-file"] {
		candidate.ProbePasswordEnv = ""
	}
	if candidate.Controller != originalController || candidate.SSHHost != originalSSH || (originalOS != "" && candidate.HostOS != originalOS) {
		candidate.Configs = nil
		candidate.Secret = ""
		if !explicit["source-config"] {
			candidate.SourceConfig = ""
		}
	}
	if candidate.ID == "" {
		sum := sha256.Sum256([]byte(candidate.SSHHost + "\x00" + candidate.Controller))
		candidate.ID = "core-" + hex.EncodeToString(sum[:4])
	}
	// Own the discovered metadata; saving a draft must not mutate its candidate.
	candidate.Configs = append([]config.CoreConfig(nil), candidate.Configs...)
	for i := range candidate.Configs {
		candidate.Configs[i].Name = core.Sanitize(candidate.Configs[i].Name)
	}
	return candidate
}

func targetRegistrationFields(d config.Target) []wizard.Field {
	return []wizard.Field{
		{Key: "id", Label: "Target ID", Value: d.ID, Required: true},
		{Key: "name", Label: "Display name (optional)", Value: d.Name},
		{Key: "controller", Label: "Controller URL on the core host", Value: d.Controller, Required: true},
		{Key: "ssh", Label: "SSH host alias (optional)", Value: d.SSHHost},
		{Key: "source-config", Label: "Source YAML for controller credentials (optional)", Value: d.SourceConfig},
		{Key: "secret-env", Label: "Local controller secret environment variable (optional)", Value: d.SecretEnv},
		{Key: "secret-file", Label: "Local controller secret file (optional)", Value: d.SecretFile},
		{Key: "ca-cert", Label: "Local HTTPS CA file (optional)", Value: d.CAFile},
		{Key: "host-os", Label: "Core host OS: darwin / linux / windows (optional)", Value: d.HostOS},
		{Key: "probe-proxy", Label: "Data proxy URL on the core host (optional)", Value: d.ProbeProxy},
		{Key: "probe-username", Label: "Data proxy username (optional)", Value: d.ProbeUsername},
		{Key: "probe-password-env", Label: "Local data proxy password environment variable (optional)", Value: d.ProbePasswordEnv},
		{Key: "probe-password-file", Label: "Local data proxy password file (optional)", Value: d.ProbePasswordFile},
		{Key: "probe-ca-cert", Label: "Local data proxy CA file (optional)", Value: d.ProbeCAFile},
	}
}

func targetRegistrationValues(d config.Target, values map[string]string) config.Target {
	for key, dst := range map[string]*string{"id": &d.ID, "name": &d.Name, "controller": &d.Controller, "ssh": &d.SSHHost, "source-config": &d.SourceConfig, "secret-env": &d.SecretEnv, "secret-file": &d.SecretFile, "ca-cert": &d.CAFile, "host-os": &d.HostOS, "probe-proxy": &d.ProbeProxy, "probe-username": &d.ProbeUsername, "probe-password-env": &d.ProbePasswordEnv, "probe-password-file": &d.ProbePasswordFile, "probe-ca-cert": &d.ProbeCAFile} {
		if value, ok := values[key]; ok {
			*dst = strings.TrimSpace(value)
		}
	}
	return d
}
