package configwork

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"go.yaml.in/yaml/v3"
)

func open(ctx context.Context, t config.Target, ro bool, opts Options) (*core.Client, func(), error) {
	f := opts.Open
	if f == nil {
		f = connection.Open
	}
	c, closer, e := f(ctx, t, ro)
	cleanup := func() {
		if closer != nil {
			_ = closer.Close()
		}
		if c != nil {
			_ = c.Close()
		}
	}
	if e != nil {
		cleanup()
		return nil, func() {}, e
	}
	if c == nil {
		cleanup()
		return nil, func() {}, errors.New("controller opener returned no client")
	}
	return c, cleanup, nil
}
func Preview(ctx context.Context, t config.Target, req Request, opts Options) (Plan, error) {
	s, e := inspectWithOptions(ctx, t, opts)
	if e != nil {
		return Plan{}, e
	}
	c, close, e := open(ctx, t, true, opts)
	if e != nil {
		return Plan{}, e
	}
	defer close()
	version, e := c.Version(ctx)
	if e != nil {
		return Plan{}, e
	}
	v, _ := version["version"].(string)
	if v == "" {
		return Plan{}, errors.New("core version unavailable")
	}
	return previewSource(t, s, req, v)
}
func previewSource(t config.Target, s *source, req Request, version string) (Plan, error) {
	if req.Kind != "proxy" && req.Kind != "group" {
		return Plan{}, errors.New("definition kind must be proxy or group")
	}
	if s.Kind == "verge" && ((req.Kind == "proxy" && s.blockedProxies) || (req.Kind == "group" && s.blockedGroups)) {
		return Plan{}, errors.New("a later Verge Merge replaces this section; edit that native owner instead of an ineffective companion")
	}
	beforeDefinitions := append(append([]Definition{}, s.Proxies...), s.Groups...)
	var expected []Definition
	if req.Action == "import" {
		if req.Kind != "proxy" {
			return Plan{}, errors.New("batch import applies to nodes")
		}
		defs, diagnostics, e := ParseImport(req.Input)
		if e != nil {
			return Plan{}, e
		}
		if len(diagnostics) > 0 {
			var messages []string
			for _, d := range diagnostics {
				messages = append(messages, fmt.Sprintf("line %d: %s", d.Index, d.Message))
			}
			return Plan{}, errors.New("import rejected: " + strings.Join(messages, "; "))
		}
		for _, d := range defs {
			raw, _ := d.Raw()
			sub := req
			sub.Action = "add"
			sub.Input = raw
			sub.Name = d.Name
			item, e := s.mutate(sub)
			if e != nil {
				return Plan{}, e
			}
			expected = append(expected, item)
		}
	} else {
		d, e := s.mutate(req)
		if e != nil {
			return Plan{}, e
		}
		expected = append(expected, d)
	}
	if e := validateGraph(s.effective()); e != nil {
		return Plan{}, e
	}
	p := Plan{TargetID: t.ID, Owner: s.Kind, Action: req.Action, Kind: req.Kind, Name: expected[0].Name, Warnings: s.Warnings, CoreVersion: version, source: s, expected: expected}
	if len(expected) > 1 {
		p.Name = fmt.Sprintf("%d nodes", len(expected))
	}
	// Preserve deliberate order: compensating group replacements precede a
	// same-name replacement; a new node precedes groups referencing it.
	order := []string{s.base}
	if s.Kind == "verge" {
		order = []string{s.proxies, s.groups}
		if req.Action == "edit" && req.Kind == "proxy" {
			order = []string{s.groups, s.proxies}
		}
	}
	for _, path := range order {
		before := s.files[path]
		after, e := encode(s.docs[path])
		if e != nil {
			return Plan{}, e
		}
		if len(after) > MaxDocument {
			return Plan{}, errors.New("candidate exceeds 8 MiB")
		}
		if semantic(s.docs[path]) == semanticMust(before.Data) {
			continue
		}
		p.Changes = append(p.Changes, Change{Path: path, BeforeSHA256: before.SHA256, AfterSHA256: hash(after), Status: "planned", Fingerprint: before.Fingerprint, before: before.Data, after: after})
	}
	p.expectedGroups = s.Groups
	p.Diff = definitionDiff(beforeDefinitions, append(append([]Definition{}, s.Proxies...), s.Groups...))
	p.Summary = fmt.Sprintf("%s %s %q in %s; %d source file(s). Credential values are hidden.", req.Action, req.Kind, p.Name, s.Kind, len(p.Changes))
	digest := struct {
		Binding, Version, Action, Kind, Name, Input, Origin, DockerID, DockerImage string
		Changes                                                                    []Change
		Guards                                                                     []rulework.FileGuard
		Groups                                                                     []string
		Replace                                                                    bool
	}{
		Binding(t), version, req.Action, req.Kind, req.Name, hash(req.Input), req.OriginDigest, s.dockerID, s.dockerImage, p.Changes, s.guards, req.Groups, req.Replace}
	p.Digest = hashJSON(digest)
	return p, nil
}
func semanticMust(data []byte) string {
	n, e := decode(data)
	if e != nil {
		return ""
	}
	return semantic(n)
}
func (s *source) mutate(req Request) (Definition, error) {
	items := s.Proxies
	if req.Kind == "group" {
		items = s.Groups
	}
	var node *yaml.Node
	var e error
	old, exists := find(items, req.Name)
	switch req.Action {
	case "edit", "duplicate":
		if !exists {
			return Definition{}, errors.New("raw definition not found; provider/runtime-only nodes must be explicitly imported as a new private node")
		}
		node = clone(old.Node)
		if len(req.Input) > 0 {
			patch, e := decode(req.Input)
			if e != nil {
				return Definition{}, e
			}
			if patch.Kind != yaml.MappingNode {
				return Definition{}, errors.New("edit requires a YAML/JSON mapping")
			}
			if req.Replace {
				node = patch
			} else {
				node = mergeNode(node, patch)
			}
		}
		if req.Action == "duplicate" {
			if !validName(req.NewName) {
				return Definition{}, errors.New("duplicate requires a new valid name")
			}
			set(node, "name", str(req.NewName))
		} else if scalar(node, "name") != old.Name {
			return Definition{}, errors.New("renaming changes references; use duplicate with an explicit new name")
		}
	case "add":
		if req.Kind == "proxy" {
			defs, diagnostics, err := ParseImport(req.Input)
			if err != nil {
				return Definition{}, err
			}
			if len(diagnostics) > 0 || len(defs) != 1 {
				return Definition{}, errors.New("add needs one complete node; use import for multiple")
			}
			node = defs[0].Node
		} else {
			node, e = decode(req.Input)
			if e != nil {
				return Definition{}, e
			}
		}
		name := req.NewName
		if name == "" {
			name = req.Name
		}
		if name != "" {
			set(node, "name", str(name))
		}
	default:
		return Definition{}, errors.New("action must be add, import, edit or duplicate")
	}
	d, e := definition(node, req.Kind, "candidate")
	if e != nil {
		return d, e
	}
	all := append(append([]Definition{}, s.Proxies...), s.Groups...)
	if req.Action != "edit" {
		if _, ok := find(all, d.Name); ok {
			return d, errors.New("destination name already exists; choose an explicit new name")
		}
	}
	baseline := append([]Definition{}, s.Groups...)
	if s.Kind != "verge" {
		key := "proxies"
		if req.Kind == "group" {
			key = "proxy-groups"
		}
		owner := s.docs[s.base]
		if req.Action == "edit" && old.Provider != "" {
			providerName := old.Provider
			owner = get(get(owner, "proxy-providers"), providerName)
			key = "payload"
		}
		selectedName := req.Name
		if req.Action != "edit" {
			selectedName = d.Name
		}
		if e = replaceSeq(owner, key, selectedName, node, req.Action != "edit"); e != nil {
			return d, e
		}
	} else {
		if req.Action == "edit" && old.Provider != "" {
			return d, errors.New("provider-backed nodes need an explicit private duplicate; Proxies companion cannot replace a provider entry")
		}
		path := s.proxies
		if req.Kind == "group" {
			path = s.groups
		}
		if req.Action == "edit" {
			if !editCompanion(s.docs[path], req.Name, node) {
				overrideCompanion(s.docs[path], req.Name, node)
			}
		} else {
			sequence(s.docs[path], "prepend").Content = append(sequence(s.docs[path], "prepend").Content, clone(node))
		}
	}
	if e = s.refresh(); e != nil {
		return d, e
	}
	if req.Kind == "proxy" {
		// Compute desired group mappings from the pre-change source, not expanded
		// runtime membership. This compensates Verge's automatic selector insertion
		// and delete-side effects without flattening use/filter/include-all.
		wanted := map[string]bool{}
		for _, name := range req.Groups {
			wanted[name] = true
		}
		for _, g := range baseline {
			desired := clone(g.Node)
			if wanted[g.Name] {
				p := sequence(desired, "proxies")
				found := false
				for _, n := range p.Content {
					if n.Value == d.Name {
						found = true
					}
				}
				if !found {
					p.Content = append(p.Content, str(d.Name))
				}
				delete(wanted, g.Name)
			}
			actual, ok := find(s.Groups, g.Name)
			if !ok {
				return d, errors.New("group disappeared while preparing change")
			}
			if semantic(actual.Node) != semantic(desired) {
				if s.Kind == "verge" {
					if s.blockedGroups {
						return d, errors.New("later Verge Merge masks groups needed to preserve node membership")
					}
					if !editCompanion(s.docs[s.groups], g.Name, desired) {
						overrideCompanion(s.docs[s.groups], g.Name, desired)
						s.Warnings = append(s.Warnings, "Group "+g.Name+" becomes a local override; subscription changes to this group will be masked and its display position can change.")
					}
				} else {
					if e = replaceSeq(s.docs[s.base], "proxy-groups", g.Name, desired, false); e != nil {
						return d, e
					}
				}
			}
		}
		if len(wanted) > 0 {
			return d, errors.New("selected destination group does not exist")
		}
	}
	if e = s.refresh(); e != nil {
		return d, e
	}
	return d, nil
}
func editCompanion(comp *yaml.Node, name string, node *yaml.Node) bool {
	for _, key := range []string{"prepend", "append"} {
		seq := get(comp, key)
		if seq != nil {
			for i, n := range seq.Content {
				if scalar(n, "name") == name {
					seq.Content[i] = clone(node)
					return true
				}
			}
		}
	}
	return false
}
func overrideCompanion(comp *yaml.Node, name string, node *yaml.Node) {
	deleted := sequence(comp, "delete")
	has := false
	for _, v := range deleted.Content {
		if v.Value == name {
			has = true
		}
	}
	if !has {
		deleted.Content = append(deleted.Content, str(name))
	}
	if !editCompanion(comp, name, node) {
		seq := sequence(comp, "prepend")
		seq.Content = append(seq.Content, clone(node))
	}
}
func validateGraph(root *yaml.Node) error {
	proxies, e := proxyDefinitions(root, "")
	if e != nil {
		return e
	}
	groups, e := definitions(root, "proxy-groups", "group", "")
	if e != nil {
		return e
	}
	names := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true, "GLOBAL": true}
	for _, d := range append(proxies, groups...) {
		if names[d.Name] {
			return errors.New("node/group name collides with another definition or built-in")
		}
		names[d.Name] = true
	}
	providers := get(root, "proxy-providers")
	hasProviders := providers != nil
	byName := map[string]Definition{}
	for _, g := range groups {
		byName[g.Name] = g
		for _, key := range []string{"proxies", "use"} {
			v := get(g.Node, key)
			if v == nil {
				continue
			}
			for _, m := range v.Content {
				if m.Kind != yaml.ScalarNode {
					return errors.New("group members must be names")
				}
				if key == "use" {
					if get(providers, m.Value) == nil {
						return errors.New("group refers to a missing provider")
					}
				} else if !names[m.Value] && !hasProviders {
					return errors.New("group refers to a missing node or group")
				}
			}
		}
	}
	for _, p := range proxies {
		if dial := scalar(p.Node, "dialer-proxy"); dial != "" && !names[dial] {
			return errors.New("node dialer-proxy dependency is missing")
		}
	}
	visited, stack := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(name string) error {
		if stack[name] {
			return errors.New("proxy group cycle detected")
		}
		if visited[name] {
			return nil
		}
		visited[name] = true
		stack[name] = true
		g := byName[name]
		if seq := get(g.Node, "proxies"); seq != nil {
			for _, n := range seq.Content {
				if _, ok := byName[n.Value]; ok {
					if e := visit(n.Value); e != nil {
						return e
					}
				}
			}
		}
		delete(stack, name)
		return nil
	}
	for name := range byName {
		if e := visit(name); e != nil {
			return e
		}
	}
	return nil
}
func validate(ctx context.Context, t config.Target, p Plan, opts Options) error {
	if t.ConfigSource.Kind == "verge" {
		return nil
	}
	raw, e := encode(p.source.docs[p.source.base])
	if e != nil {
		return e
	}
	if opts.Validate != nil {
		return opts.Validate(ctx, t, raw, p.CoreVersion)
	}
	if t.ConfigSource.Kind == "docker" {
		var result HostResponse
		result, e = dockerSourceOperation(ctx, t, "validate", raw, p.CoreVersion, opts)
		if e == nil && (result.ContainerID != p.source.dockerID || result.Image != p.source.dockerImage) {
			return errors.New("Docker container changed during validation; prepare a new preview")
		}
		return e
	}
	node, err := decode(raw)
	if err != nil {
		return err
	}
	var document any
	if err = node.Decode(&document); err != nil {
		return errors.New("invalid validation document")
	}
	_, err = hostOperation(ctx, t, HostRequest{Op: "validate", Binary: t.ConfigSource.Binary, Home: t.ConfigSource.Home, Version: p.CoreVersion, Document: document}, opts)
	return err
}
func refreshGuard(guards []rulework.FileGuard, path, fingerprint string) []rulework.FileGuard {
	out := append([]rulework.FileGuard{}, guards...)
	for i := range out {
		if out[i].Path == path {
			out[i].Fingerprint = fingerprint
		}
	}
	return out
}
func PreviewCopy(ctx context.Context, from, to config.Target, name, newName string, groups []string, opts Options) (Plan, Request, error) {
	d, e := ReadDefinition(ctx, from, "proxy", name, opts)
	if e != nil {
		return Plan{}, Request{}, e
	}
	raw, e := d.Raw()
	if e != nil {
		return Plan{}, Request{}, e
	}
	if from.ConfigSource == nil {
		return Plan{}, Request{}, errors.New("source target has no raw definition owner")
	}
	for _, key := range []string{"interface-name", "routing-mark"} {
		if get(d.Node, key) != nil {
			return Plan{}, Request{}, errors.New("node has host-specific routing fields; export and adapt explicitly before copying")
		}
	}
	if hasFileDependency(d.Map()) {
		return Plan{}, Request{}, errors.New("node references host-local certificate/key files; export and adapt the dependencies before copying")
	}
	req := Request{Kind: "proxy", Action: "add", NewName: newName, Input: raw, Groups: groups, OriginDigest: hashJSON([]string{Binding(from), semantic(d.Node)})}
	p, e := Preview(ctx, to, req, opts)
	p.SourceTargetID = from.ID
	p.Summary = fmt.Sprintf("Copy raw source node %q from %s to %s. %s", name, from.ID, to.ID, p.Summary)
	return p, req, e
}

func hasFileDependency(value any) bool {
	switch n := value.(type) {
	case map[string]any:
		for key, v := range n {
			text, ok := v.(string)
			fileKey := key == "ca" || key == "certificate" || key == "certificate-path" || key == "private-key-path" || (key == "private-key" && n["certificate"] != nil)
			if fileKey && ok && text != "" && !strings.Contains(text, "\n") && !strings.HasPrefix(text, "-----") {
				return true
			}
			if hasFileDependency(v) {
				return true
			}
		}
	case []any:
		for _, v := range n {
			if hasFileDependency(v) {
				return true
			}
		}
	}
	return false
}
func SortedNames(items []Definition) []string {
	out := make([]string, 0, len(items))
	for _, d := range items {
		out = append(out, d.Name)
	}
	sort.Strings(out)
	return out
}
func WarningsText(p Plan) string {
	return p.Summary + "\n\n" + diffText(p.Diff) + "\n" + strings.Join(p.Warnings, "\n")
}
