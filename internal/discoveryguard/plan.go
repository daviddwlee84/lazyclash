// Package discoveryguard owns bounded, temporary fallback changes in a
// separate process, so losing the foreground collector also ends the change.
package discoveryguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

// Plan contains only identity evidence, never controller credentials or logs.
type Plan struct {
	TargetID       string   `json:"target_id"`
	FallbackPolicy string   `json:"fallback_policy"`
	Group          string   `json:"group,omitempty"`
	Previous       string   `json:"previous,omitempty"`
	AlreadyDirect  bool     `json:"already_direct"`
	Warnings       []string `json:"warnings,omitempty"`
	Digest         string   `json:"digest"`
	BindingDigest  string   `json:"binding_digest"`
	ControllerKey  string   `json:"controller_key"`
	RulesDigest    string   `json:"rules_digest"`
	GroupDigest    string   `json:"group_digest,omitempty"`
	CoreVersion    string   `json:"core_version"`
}

// Preview reads the actual enabled MATCH rule, not a group named "FINAL".
// Start separately proves this exact target is present in the settings file.
func Preview(ctx context.Context, target config.Target) (Plan, error) {
	if err := savedShape(target); err != nil {
		return Plan{}, err
	}
	c, closer, err := connection.Open(ctx, target, true)
	if err != nil {
		return Plan{}, err
	}
	defer closer.Close()
	return inspect(ctx, c, target)
}

func savedShape(t config.Target) error {
	if t.ID == "" || t.Transient || t.TransportOverride || t.Secret != "" {
		return errors.New("DIRECT discovery requires a saved target and saved credential references; temporary overrides are not supported")
	}
	return config.ValidateTarget(t)
}

func bindingDigest(t config.Target) string {
	return digest([]string{t.ID, t.Controller, t.SSHHost, t.HostOS, t.SecretEnv, t.SecretFile, t.SourceConfig, t.CAFile})
}

func controllerKey(t config.Target) string {
	u, _ := url.Parse(t.Controller)
	u.Host = strings.ToLower(u.Host)
	if (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
		u.Host = u.Hostname()
		if strings.Contains(u.Host, ":") {
			u.Host = "[" + u.Host + "]"
		}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return digest([]string{t.SSHHost, u.String()})
}

func digest(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func inspect(ctx context.Context, c *core.Client, t config.Target) (Plan, error) {
	p := Plan{TargetID: t.ID, BindingDigest: bindingDigest(t), ControllerKey: controllerKey(t)}
	general, err := c.Config(ctx)
	if err != nil {
		return p, err
	}
	mode, _ := general["mode"].(string)
	if !strings.EqualFold(mode, "rule") {
		return p, errors.New("DIRECT discovery requires rule mode; mode will not be changed automatically")
	}
	version, err := c.Version(ctx)
	if err != nil {
		return p, err
	}
	p.CoreVersion, _ = version["version"].(string)
	if p.CoreVersion == "" {
		return p, errors.New("controller identity is unavailable")
	}
	rules, err := c.Rules(ctx)
	if err != nil {
		return p, err
	}
	rows, ok := rules["rules"].([]any)
	if !ok {
		return p, errors.New("controller did not return ordered runtime rules")
	}
	stable := make([][]any, 0, len(rows))
	refs := map[string]int{}
	for _, raw := range rows {
		r, ok := raw.(map[string]any)
		if !ok {
			return p, errors.New("invalid runtime rule")
		}
		kind, k := r["type"].(string)
		payload, h := r["payload"].(string)
		policy, a := r["proxy"].(string)
		if !k || !h || !a {
			return p, errors.New("incomplete runtime rule")
		}
		disabled := false
		if extra, present := r["extra"]; present && extra != nil {
			m, ok := extra.(map[string]any)
			if !ok {
				return p, errors.New("invalid runtime rule state")
			}
			if value, present := m["disabled"]; present {
				var valid bool
				disabled, valid = value.(bool)
				if !valid {
					return p, errors.New("unknown runtime rule enabled state")
				}
			}
		}
		stable = append(stable, []any{kind, payload, policy, disabled})
		if disabled {
			continue
		}
		refs[policy]++
		if p.FallbackPolicy == "" && strings.EqualFold(kind, "match") {
			p.FallbackPolicy = policy
		}
	}
	if p.FallbackPolicy == "" {
		return p, errors.New("no enabled MATCH fallback was reported by this controller")
	}
	p.RulesDigest = digest(stable)
	if p.FallbackPolicy == "DIRECT" {
		p.AlreadyDirect = true
		p.Digest = digest(p)
		return p, nil
	}
	proxies, err := c.Proxies(ctx)
	if err != nil {
		return p, err
	}
	g, ok := proxies[p.FallbackPolicy]
	if !ok || !strings.EqualFold(g.Type, "selector") || !slices.Contains(g.All, "DIRECT") {
		return p, errors.New("MATCH must target DIRECT or a manual Selector containing DIRECT; no nested or automatic group will be changed")
	}
	if g.Now == "" || !slices.Contains(g.All, g.Now) {
		return p, errors.New("fallback Selector's original selection cannot be restored")
	}
	p.Group, p.Previous, p.AlreadyDirect = p.FallbackPolicy, g.Now, g.Now == "DIRECT"
	p.GroupDigest = digest([]any{p.Group, g.Type, g.All})
	if count := refs[p.Group] - 1; count > 0 {
		p.Warnings = append(p.Warnings, fmt.Sprintf("%d additional enabled rules reference this Selector; their new connections will also use DIRECT.", count))
	}
	parents := 0
	for name, proxy := range proxies {
		if name != p.Group && slices.Contains(proxy.All, p.Group) {
			parents++
		}
	}
	if parents > 0 {
		p.Warnings = append(p.Warnings, fmt.Sprintf("%d other groups contain this Selector and may also be affected.", parents))
	}
	p.Warnings = append(p.Warnings, "Restoration checks observed state; the controller has no atomic compare-and-set, so simultaneous external edits cannot be fully detected.")
	p.Digest = digest(p)
	return p, nil
}

func sameIdentity(a, b Plan) bool {
	return a.TargetID == b.TargetID && a.BindingDigest == b.BindingDigest && a.ControllerKey == b.ControllerKey && a.CoreVersion == b.CoreVersion && a.RulesDigest == b.RulesDigest && a.FallbackPolicy == b.FallbackPolicy && a.Group == b.Group && a.GroupDigest == b.GroupDigest
}

func loadTarget(path, id string) (config.Target, error) {
	cfg, err := config.Load(path, true)
	if err != nil {
		return config.Target{}, err
	}
	for _, t := range cfg.Targets {
		if t.ID == id {
			return t, savedShape(t)
		}
	}
	return config.Target{}, errors.New("discovery target is no longer saved in this settings file")
}
