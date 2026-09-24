package configwork

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"go.yaml.in/yaml/v3"
)

func decodeChangeSetFile(s *source, path string, data []byte) (*yaml.Node, error) {
	merge := false
	for _, candidate := range s.mergePaths {
		merge = merge || candidate == path
	}
	if merge {
		dec := yaml.NewDecoder(bytes.NewReader(data))
		var doc yaml.Node
		err := dec.Decode(&doc)
		if err == io.EOF {
			return mapNode(map[string]any{}), nil
		}
		if err == nil && len(doc.Content) == 1 && doc.Content[0].Tag == "!!null" {
			var value any
			var next yaml.Node
			if doc.Decode(&value) == nil && value == nil && dec.Decode(&next) == io.EOF {
				return mapNode(map[string]any{}), nil
			}
		}
	}
	return decode(data)
}

func changeSetTarget(t config.Target) (config.Target, error) {
	if t.ConfigSource != nil {
		return t, nil
	}
	if t.RuleSource == nil {
		return t, fmt.Errorf("%w: bind a configuration or rule source", ErrConfigUnavailable)
	}
	if err := config.ValidateRuleSource(t); err != nil {
		return t, err
	}
	r := t.RuleSource
	kind := r.Kind
	if kind == "mihomo" {
		kind = "native"
	}
	t.ConfigSource = &config.ConfigSource{Kind: kind, ConfigID: r.ConfigID, Binary: r.Binary, Home: r.Home, HostPath: r.HostPath, CorePath: r.CorePath, Container: r.Container, DockerHost: r.DockerHost, ValidationDockerHost: r.ValidationDockerHost, ValidationImage: r.ValidationImage, DataDir: r.DataDir, Version: r.Version, ProfileUID: r.ProfileUID}
	return t, nil
}

// changeSetEffective composes only declarative owner stages. Scripts are never
// executed, and execution refuses unknown scripts when exact proof is needed.
func changeSetEffective(s *source) (*yaml.Node, error) {
	root := s.effective()
	if s.Kind != "verge" {
		return root, nil
	}
	if s.rules != "" {
		comp := s.docs[s.rules]
		if err := validateCompanion(comp); err != nil {
			return nil, err
		}
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		deleted := map[string]bool{}
		if d := get(comp, "delete"); d != nil {
			for _, n := range d.Content {
				if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
					return nil, errors.New("Verge rule delete entries must be strings")
				}
				deleted[n.Value] = true
			}
		}
		for _, section := range []string{"prepend", "original", "append"} {
			items := get(comp, section)
			if section == "original" {
				items = get(root, "rules")
			}
			if items == nil {
				continue
			}
			if items.Kind != yaml.SequenceNode {
				return nil, errors.New("Verge rules must be a sequence")
			}
			for _, n := range items.Content {
				if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
					return nil, errors.New("Verge rules must contain strings")
				}
				if section != "original" || !deleted[n.Value] {
					seq.Content = append(seq.Content, clone(n))
				}
			}
		}
		set(root, "rules", seq)
	}
	for _, path := range s.mergePaths {
		root = deepMergeOwner(root, s.docs[path])
	}
	return root, nil
}

func deepMergeOwner(base, patch *yaml.Node) *yaml.Node {
	if patch == nil {
		return clone(base)
	}
	if base == nil || base.Kind != yaml.MappingNode || patch.Kind != yaml.MappingNode {
		return clone(patch)
	}
	out := clone(base)
	for i := 0; i+1 < len(patch.Content); i += 2 {
		key := patch.Content[i].Value
		set(out, key, deepMergeOwner(get(out, key), patch.Content[i+1]))
	}
	return out
}

func sameChangeSetRuleOwner(t config.Target) error {
	if t.RuleSource == nil {
		return errors.New("selected rules require an explicit rules source binding")
	}
	expected, err := config.RuleSourceFromConfigSource(t)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(expected, t.RuleSource) {
		return errors.New("rule and configuration sources identify different owners; explicitly align the bindings before a combined change")
	}
	return nil
}

func ownerHasScripts(s *source) bool {
	for _, path := range s.scriptPaths {
		text := string(s.files[path].Data)
		var lines []string
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || trimmed == "" {
				continue
			}
			lines = append(lines, trimmed)
		}
		compact := strings.Join(strings.Fields(strings.Join(lines, "")), "")
		if compact != "" && compact != "functionmain(config){returnconfig;}" && compact != "functionmain(config){returnconfig}" {
			return true
		}
	}
	return false
}

func adaptChangeSetOwner(t config.Target, s *source, desired *yaml.Node, selection StructuralSelection) ([]string, error) {
	before, err := changeSetEffective(s)
	if err != nil {
		return nil, err
	}
	rulesChanged := semantic(get(before, "rules")) != semantic(get(desired, "rules"))
	if rulesChanged {
		if err := sameChangeSetRuleOwner(t); err != nil {
			return nil, err
		}
	}
	if s.Kind != "verge" {
		s.docs[s.base] = clone(desired)
		return []string{s.base}, nil
	}
	if ownerHasScripts(s) {
		return nil, errors.New("Verge Scripts prevent exact declarative composition proof; adapt this profile in its native owner")
	}
	if (s.blockedProxies && semantic(get(before, "proxies")) != semantic(get(desired, "proxies"))) || (s.blockedGroups && semantic(get(before, "proxy-groups")) != semantic(get(desired, "proxy-groups"))) {
		return nil, errors.New("later Verge Merge replaces a selected node/group section")
	}
	paths := []string{}
	for _, item := range []struct{ section, path, kind string }{{"proxies", s.proxies, "proxy"}, {"proxy-groups", s.groups, "group"}} {
		current, e := changeSetEffective(s)
		if e != nil {
			return nil, e
		}
		old, e := definitions(current, item.section, item.kind, "")
		if e != nil {
			return nil, e
		}
		next, e := definitions(desired, item.section, item.kind, "")
		if e != nil {
			return nil, e
		}
		changed := false
		for _, d := range next {
			previous, exists := find(old, d.Name)
			if exists && semantic(previous.Node) == semantic(d.Node) {
				continue
			}
			if item.path == "" {
				return nil, fmt.Errorf("existing Verge %s companion is required", item.section)
			}
			comp := s.docs[item.path]
			if exists {
				overrideCompanion(comp, d.Name, d.Node)
			} else {
				sequence(comp, "prepend").Content = append(sequence(comp, "prepend").Content, clone(d.Node))
			}
			changed = true
		}
		if changed {
			paths = append(paths, item.path)
		}
	}
	providersChanged := false
	for _, section := range []string{"proxy-providers", "rule-providers"} {
		providersChanged = providersChanged || semantic(get(before, section)) != semantic(get(desired, section))
	}
	needsRulesMerge := rulesChanged
	if rulesChanged && s.rules != "" {
		mergeRules := false
		for _, path := range s.mergePaths {
			mergeRules = mergeRules || get(s.docs[path], "rules") != nil
		}
		beforeRules, afterRules := get(before, "rules"), get(desired, "rules")
		if !mergeRules && beforeRules != nil && afterRules != nil && afterRules.Kind == yaml.SequenceNode && len(afterRules.Content) >= len(beforeRules.Content) {
			extra := len(afterRules.Content) - len(beforeRules.Content)
			prefix, suffix := true, true
			for i, n := range beforeRules.Content {
				prefix = prefix && semantic(n) == semantic(afterRules.Content[i])
				suffix = suffix && semantic(n) == semantic(afterRules.Content[extra+i])
			}
			if suffix {
				seq := sequence(s.docs[s.rules], "prepend")
				items := []*yaml.Node{}
				for _, n := range afterRules.Content[:extra] {
					items = append(items, clone(n))
				}
				seq.Content = append(items, seq.Content...)
				needsRulesMerge = false
				paths = append(paths, s.rules)
			} else if prefix {
				seq := sequence(s.docs[s.rules], "append")
				for _, n := range afterRules.Content[len(beforeRules.Content):] {
					seq.Content = append(seq.Content, clone(n))
				}
				needsRulesMerge = false
				paths = append(paths, s.rules)
			}
		}
	}
	if providersChanged || needsRulesMerge {
		if s.profileMerge == "" {
			return nil, errors.New("create an active-profile Merge companion in Verge before selected provider changes or rules that need an ordered override")
		}
		merge := clone(s.docs[s.profileMerge])
		for _, section := range []string{"proxy-providers", "rule-providers"} {
			if semantic(get(before, section)) != semantic(get(desired, section)) {
				patch := clone(get(merge, section))
				if patch == nil {
					patch = mapNode(map[string]any{})
				}
				if patch.Kind != yaml.MappingNode {
					return nil, errors.New("Verge provider merge must be a mapping")
				}
				providers := get(desired, section)
				if providers == nil || providers.Kind != yaml.MappingNode {
					return nil, errors.New("provider deletion is unsupported by selective Verge merge")
				}
				for i := 0; i+1 < len(providers.Content); i += 2 {
					name := providers.Content[i].Value
					if semantic(get(get(before, section), name)) != semantic(providers.Content[i+1]) {
						set(patch, name, clone(providers.Content[i+1]))
					}
				}
				set(merge, section, patch)
			}
		}
		if needsRulesMerge {
			if get(merge, "rules") == nil && !selection.AllowVergeRulesOverride {
				return nil, errors.New("Verge requires explicit acknowledgement of a full per-profile Merge.rules override")
			}
			set(merge, "rules", clone(get(desired, "rules")))
		}
		s.docs[s.profileMerge] = merge
		paths = append(paths, s.profileMerge)
	}
	for _, file := range paths {
		if file == s.rules || file == s.proxies || file == s.groups {
			for _, section := range []string{"prepend", "append", "delete"} {
				sequence(s.docs[file], section)
			}
		}
	}
	actual, err := changeSetEffective(s)
	if err != nil {
		return nil, err
	}
	for _, section := range []string{"proxies", "proxy-groups", "proxy-providers", "rule-providers", "rules"} {
		equal := semantic(get(actual, section)) == semantic(get(desired, section))
		if section == "proxies" || section == "proxy-groups" {
			equal = namedSectionEqual(get(actual, section), get(desired, section))
		}
		if !equal {
			return nil, fmt.Errorf("Verge deep merge cannot reproduce the selected %s definition exactly; no files changed", section)
		}
	}
	return paths, nil
}

func namedSectionEqual(a, b *yaml.Node) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.Kind != yaml.SequenceNode || b.Kind != yaml.SequenceNode || len(a.Content) != len(b.Content) {
		return false
	}
	values := map[string]string{}
	for _, n := range a.Content {
		name := scalar(n, "name")
		if name == "" || values[name] != "" {
			return false
		}
		values[name] = semantic(n)
	}
	for _, n := range b.Content {
		if values[scalar(n, "name")] != semantic(n) {
			return false
		}
	}
	return true
}
