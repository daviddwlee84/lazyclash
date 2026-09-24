package rulework

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
	"go.yaml.in/yaml/v3"
)

// RulesView describes one independently observed ordered rule list. Section
// remains part of every entry's identity, including Verge delete directives.
type RulesView struct {
	Status      string            `json:"status"`
	Shape       string            `json:"shape,omitempty"`
	Entries     []rulecheck.Entry `json:"entries"`
	Message     string            `json:"message,omitempty"`
	Limitations []string          `json:"limitations,omitempty"`
}

type RulesSnapshot struct {
	TargetID              string          `json:"target_id"`
	Scope                 string          `json:"scope"`
	ObservedAt            string          `json:"observed_at"`
	Version               string          `json:"version,omitempty"`
	Mode                  string          `json:"mode,omitempty"`
	SourceBinding         string          `json:"source_binding,omitempty"`
	Owner                 *Source         `json:"owner,omitempty"`
	Source                *RulesView      `json:"source,omitempty"`
	Runtime               *RulesView      `json:"runtime,omitempty"`
	Policies              map[string]bool `json:"policies,omitempty"`
	Providers             int             `json:"providers"`
	Limitations           []string        `json:"limitations,omitempty"`
	source                *Source
	sourceErr, runtimeErr error
}

func NormalizeRulesScope(scope string) (string, error) {
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope == "" {
		scope = "both"
	}
	if scope != "runtime" && scope != "source" && scope != "both" {
		return "", errors.New("rule scope must be runtime, source or both")
	}
	return scope, nil
}

// ReadRulesSnapshot never validates candidates, writes bindings or files,
// reloads a core, refreshes a provider, or sends test traffic.
func ReadRulesSnapshot(ctx context.Context, target config.Target, scope string, opts Options) (RulesSnapshot, error) {
	scope, err := NormalizeRulesScope(scope)
	s := RulesSnapshot{TargetID: target.ID, Scope: scope, ObservedAt: time.Now().UTC().Format(time.RFC3339)}
	if err != nil {
		return s, err
	}
	opts.ReadOnly = true
	if err = ctx.Err(); err != nil {
		return s, err
	}
	if scope == "source" || scope == "both" {
		readSnapshotSource(ctx, target, opts, &s)
	}
	if err = ctx.Err(); err != nil {
		return s, err
	}
	if scope == "runtime" || scope == "both" {
		readSnapshotRuntime(ctx, target, opts, &s)
	}
	if err = ctx.Err(); err != nil {
		return s, err
	}
	var failures []error
	usable := false
	for _, v := range []*RulesView{s.Source, s.Runtime} {
		if v != nil {
			usable = usable || v.Status == "available"
			if v.Status == "error" {
				failures = append(failures, errors.New(v.Message))
			}
		}
	}
	if len(failures) > 0 {
		return s, errors.Join(failures...)
	}
	if !usable {
		return s, errors.Join(s.sourceErr, s.runtimeErr)
	}
	return s, nil
}

func readSnapshotSource(ctx context.Context, target config.Target, opts Options, s *RulesSnapshot) {
	s.Source = &RulesView{Status: "unavailable", Entries: []rulecheck.Entry{}}
	fail := func(err error) {
		s.sourceErr = err
		s.Source.Message = core.Sanitize(err.Error())
		if !errors.Is(err, ErrSourceUnavailable) {
			s.Source.Status = "error"
		}
	}
	candidate := target
	if candidate.RuleSource != nil {
		s.SourceBinding = "rule_source"
	} else if candidate.ConfigSource != nil {
		copied, err := config.RuleSourceFromConfigSource(candidate)
		if err != nil {
			fail(err)
			return
		}
		candidate.RuleSource = copied
		s.SourceBinding = "config_source"
		s.Source.Limitations = append(s.Source.Limitations, "Configuration source is inspected read-only; no persistent rule write binding is created.")
	} else {
		fail(fmt.Errorf("%w: no persistent rule or configuration source is bound", ErrSourceUnavailable))
		s.Source.Limitations = append(s.Source.Limitations, "No persistent rule source is bound; original configuration syntax cannot be verified.")
		return
	}
	// Retain all original target transport, ConfigSource and managed metadata.
	// Only the ephemeral rule descriptor changes for read-only fallback.
	source, err := inspectSource(ctx, candidate, opts)
	if err != nil {
		fail(err)
		return
	}
	s.source = &source
	s.Owner = &source
	entries, err := snapshotSourceEntries(source)
	if err != nil {
		fail(err)
		return
	}
	s.Source.Status = "available"
	s.Source.Entries = entries
	s.Source.Shape = "complete"
	if source.Kind == "verge" {
		s.Source.Shape = "verge-companion"
		s.Source.Limitations = append(s.Source.Limitations, "Source analysis covers the bound Rules companion prepend/append/delete; base profile, Merge and Script composition is represented only by the separate runtime snapshot.")
	}
}

func snapshotSourceEntries(source Source) ([]rulecheck.Entry, error) {
	doc, err := decodeYAML(source.file.Data)
	if err != nil {
		return nil, err
	}
	keys := []string{"rules"}
	if source.Kind == "verge" {
		keys = []string{"prepend", "append", "delete"}
	}
	entries := []rulecheck.Entry{}
	for _, section := range keys {
		seq := mappingValue(doc.Content[0], section)
		if seq == nil {
			continue
		}
		if seq.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("%s must be a YAML sequence", section)
		}
		for i, node := range seq.Content {
			if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
				return nil, fmt.Errorf("%s entries must be rule strings", section)
			}
			entries = append(entries, rulecheck.Entry{Section: section, Rule: rulecheck.ParseExisting(node.Value, i)})
		}
	}
	return entries, nil
}

func readSnapshotRuntime(ctx context.Context, target config.Target, opts Options, s *RulesSnapshot) {
	s.Runtime = &RulesView{Status: "unavailable", Shape: "complete", Entries: []rulecheck.Entry{}}
	fail := func(err error) {
		s.runtimeErr = err
		s.Runtime.Message = core.Sanitize(err.Error())
		if !unavailableCore(err) {
			s.Runtime.Status = "error"
		}
	}
	client, cleanup, err := openCore(ctx, target, true, opts)
	if err != nil {
		fail(err)
		return
	}
	defer cleanup()
	object, err := client.Rules(ctx)
	if err != nil {
		fail(err)
		if unavailableCore(err) {
			return
		}
	} else {
		rules, e := runtimeRuleList(object)
		if e != nil {
			s.runtimeErr = e
			s.Runtime.Status = "error"
			s.Runtime.Message = core.Sanitize(e.Error())
		} else {
			s.Runtime.Status = "available"
			for _, r := range rules {
				s.Runtime.Entries = append(s.Runtime.Entries, rulecheck.Entry{Section: "rules", Rule: r})
			}
		}
	}
	if version, e := client.Version(ctx); e == nil {
		s.Version, _ = version["version"].(string)
	} else {
		s.Limitations = append(s.Limitations, "Core version could not be read.")
	}
	if general, e := client.Config(ctx); e == nil {
		s.Mode, _ = general["mode"].(string)
	} else {
		s.Limitations = append(s.Limitations, "Runtime mode could not be read.")
	}
	if proxies, e := client.Proxies(ctx); e == nil {
		s.Policies = policyNames(proxies)
	} else {
		s.Limitations = append(s.Limitations, "Policy availability could not be checked.")
	}
	if providers, e := client.Providers(ctx, "rules"); e == nil {
		if items, ok := providers["providers"].(map[string]any); ok {
			s.Providers = len(items)
		}
	} else {
		s.Limitations = append(s.Limitations, "Rule provider metadata could not be read.")
	}
	s.Runtime.Limitations = append(s.Runtime.Limitations, "Runtime rules do not expose all source options (including no-resolve); matching entries do not prove identical source semantics.")
}
