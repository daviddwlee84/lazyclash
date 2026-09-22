package configwork

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/daviddwlee84/lazyclash/internal/hostpath"
	"io"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"go.yaml.in/yaml/v3"
)

type source struct {
	opts Options
	Catalog
	docs                                      map[string]*yaml.Node
	files                                     map[string]rulework.HostFile
	guards                                    []rulework.FileGuard
	base, proxies, groups, runtime, applyPath string
	blockedProxies, blockedGroups             bool
	dockerID, dockerImage                     string
	dockerSourceSHA                           string
	dockerSingleFile                          bool
}

func hash(data []byte) string { v := sha256.Sum256(data); return hex.EncodeToString(v[:]) }
func Binding(t config.Target) string {
	v, _ := json.Marshal(struct {
		ID, Controller, SSH, ManagedCoreID string
		HostOS                             string `json:",omitempty"`
		Source                             *config.ConfigSource
		Configs                            []config.CoreConfig
		Service                            *config.ClientService `json:",omitempty"`
	}{t.ID, t.Controller, t.SSHHost, t.ManagedCoreID, t.HostOS, t.ConfigSource, t.Configs, t.Service})
	return hash(v)
}
func semantic(n *yaml.Node) string {
	var v any
	if n != nil {
		if err := n.Decode(&v); err != nil {
			raw, _ := encode(n)
			return hash(raw)
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		b, _ = encode(n)
	}
	return hash(b)
}
func (s *source) read(ctx context.Context, t config.Target, path string) (*yaml.Node, error) {
	f, e := readSourceFile(ctx, t, path, s.opts)
	if e != nil {
		return nil, e
	}
	n, e := decode(f.Data)
	if e != nil {
		return nil, e
	}
	if n.Kind != yaml.MappingNode {
		return nil, errors.New("source must be a YAML mapping")
	}
	s.files[path] = f
	s.docs[path] = n
	s.guards = append(s.guards, rulework.FileGuard{Path: path, Fingerprint: f.Fingerprint})
	s.Files = append(s.Files, path)
	return n, nil
}

// Verge's native empty Merge template contains comments only. It is a valid
// no-op context, unlike an empty proxy/group source. Preserve its byte guard.
func (s *source) readMerge(ctx context.Context, t config.Target, path string) (*yaml.Node, error) {
	f, e := readSourceFile(ctx, t, path, s.opts)
	if e != nil {
		return nil, e
	}
	dec := yaml.NewDecoder(bytes.NewReader(f.Data))
	var doc yaml.Node
	e = dec.Decode(&doc)
	empty := e == io.EOF
	if e == nil && len(doc.Content) == 1 && doc.Content[0].Tag == "!!null" {
		var value any
		var next yaml.Node
		empty = doc.Decode(&value) == nil && value == nil && dec.Decode(&next) == io.EOF
	}
	if !empty {
		return s.read(ctx, t, path)
	}
	n := mapNode(map[string]any{})
	s.files[path] = f
	s.docs[path] = n
	s.guards = append(s.guards, rulework.FileGuard{Path: path, Fingerprint: f.Fingerprint})
	s.Files = append(s.Files, path)
	return n, nil
}
func Inspect(ctx context.Context, t config.Target, opts Options) (Catalog, error) {
	s, e := inspectWithOptions(ctx, t, opts)
	if e != nil {
		return Catalog{}, e
	}
	return s.Catalog, nil
}
func inspect(ctx context.Context, t config.Target) (*source, error) {
	return inspectWithOptions(ctx, t, Options{})
}
func inspectWithOptions(ctx context.Context, t config.Target, opts Options) (*source, error) {
	if t.TransportOverride || t.Transient {
		return nil, errors.New("source operations require a saved endpoint; save and bind its owner first")
	}
	if t.ConfigSource == nil {
		return nil, errors.New("bind a node/group owner with configs source set")
	}
	if e := config.ValidateConfigSource(t); e != nil {
		return nil, e
	}
	c := t.ConfigSource
	s := &source{opts: opts, Catalog: Catalog{Kind: c.Kind, ProfileUID: c.ProfileUID}, docs: map[string]*yaml.Node{}, files: map[string]rulework.HostFile{}}
	switch c.Kind {
	case "native", "mihomo":
		s.Warnings = append(s.Warnings, "Applying this registered YAML reloads all its runtime settings; unrelated runtime-only changes may be replaced.")
		for _, v := range t.Configs {
			if v.ID == c.ConfigID {
				s.base = v.Path
			}
		}
		s.applyPath = s.base
		s.runtime = s.base
	case "docker":
		s.base = c.HostPath
		s.applyPath = c.CorePath
		s.runtime = s.base
		d, e := dockerSourceOperation(ctx, t, "inspect", nil, "", opts)
		if e != nil {
			return nil, e
		}
		if d.ContainerID == "" || d.Image == "" {
			return nil, errors.New("Docker source did not return an exact container and image identity")
		}
		s.dockerID = d.ContainerID
		s.dockerImage = d.Image
		s.dockerSourceSHA, s.dockerSingleFile = d.SourceSHA256, d.SingleFile
		s.Warnings = append(s.Warnings, "The host source is edited through its verified container bind mount; reload uses the container path.")
	case "verge":
		manifest := hostpath.Join(t.HostOS, c.DataDir, "profiles.yaml")
		n, e := s.read(ctx, t, manifest)
		if e != nil {
			return nil, e
		}
		if scalar(n, "current") != c.ProfileUID {
			return nil, errors.New("bound Verge profile is no longer current; rebind before editing")
		}
		items := get(n, "items")
		if items == nil || items.Kind != yaml.SequenceNode {
			return nil, errors.New("invalid Verge profile index")
		}
		byUID := map[string]*yaml.Node{}
		for _, v := range items.Content {
			uid := scalar(v, "uid")
			if uid == "" || byUID[uid] != nil {
				return nil, errors.New("missing or duplicate Verge profile UID")
			}
			byUID[uid] = v
		}
		profile := byUID[c.ProfileUID]
		if profile == nil || (scalar(profile, "type") != "local" && scalar(profile, "type") != "remote") {
			return nil, errors.New("bound Verge profile is not a local or remote profile")
		}
		pathFor := func(item *yaml.Node) (string, error) {
			file := scalar(item, "file")
			if file == "" || hostpath.IsAbs(t.HostOS, file) || hostpath.IsAbs("windows", file) || strings.Contains(file, `\`) {
				return "", errors.New("invalid Verge file binding")
			}
			p := hostpath.Join(t.HostOS, c.DataDir, "profiles", file)
			rel, e := hostpath.Rel(t.HostOS, hostpath.Join(t.HostOS, c.DataDir, "profiles"), p)
			if e != nil || rel == ".." || strings.HasPrefix(rel, "../") {
				return "", errors.New("Verge profile path escapes its directory")
			}
			return p, nil
		}
		s.base, e = pathFor(profile)
		if e != nil {
			return nil, e
		}
		option := get(profile, "option")
		// Reads append guards to the preview digest, so companion order must not
		// depend on map iteration even when their contents have not changed.
		for _, key := range []string{"proxies", "groups"} {
			uid := scalar(option, key)
			item := byUID[uid]
			if uid == "" || item == nil {
				return nil, fmt.Errorf("Verge %s companion is missing; use native profile Update (remote) or re-import/create a profile, then rebind", key)
			}
			if scalar(item, "type") != key {
				return nil, errors.New("Verge companion type mismatch")
			}
			p, e := pathFor(item)
			if e != nil {
				return nil, e
			}
			if key == "proxies" {
				s.proxies = p
			} else {
				s.groups = p
			}
			if _, e = s.read(ctx, t, p); e != nil {
				return nil, e
			}
			if e = validateCompanion(s.docs[p]); e != nil {
				return nil, e
			}
		}
		for _, uid := range []string{"Merge", "Script", scalar(option, "merge"), scalar(option, "script"), scalar(option, "rules")} {
			if uid == "" {
				continue
			}
			item := byUID[uid]
			if item == nil {
				if uid == "Merge" || uid == "Script" {
					continue
				}
				return nil, errors.New("referenced Verge context companion is absent")
			}
			p, e := pathFor(item)
			if e != nil {
				return nil, e
			}
			if _, ok := s.files[p]; ok {
				continue
			}
			if scalar(item, "type") == "script" {
				f, e := readSourceFile(ctx, t, p, opts)
				if e != nil {
					return nil, e
				}
				s.files[p] = f
				s.guards = append(s.guards, rulework.FileGuard{Path: p, Fingerprint: f.Fingerprint})
				s.Warnings = append(s.Warnings, "Verge Scripts can transform this source; native reactivation and generated-config verification are required.")
			} else {
				var d *yaml.Node
				if scalar(item, "type") == "merge" {
					d, e = s.readMerge(ctx, t, p)
				} else {
					d, e = s.read(ctx, t, p)
				}
				if e != nil {
					return nil, e
				}
				if scalar(item, "type") == "merge" {
					if get(d, "proxies") != nil {
						s.blockedProxies = true
					}
					if get(d, "proxy-groups") != nil {
						s.blockedGroups = true
					}
				}
			}
		}
		s.runtime = hostpath.Join(t.HostOS, c.DataDir, "clash-verge.yaml")
		s.Warnings = append(s.Warnings, "Saves are persistent companions. Reactivate the profile in Clash Verge; later Merge/Script can override them.")
	}
	if s.base == "" {
		return nil, errors.New("source path is not registered")
	}
	if _, e := s.read(ctx, t, s.base); e != nil {
		return nil, e
	}
	if c.Kind == "verge" {
		root := hostpath.Join(t.HostOS, hostpath.Dir(t.HostOS, s.files[hostpath.Join(t.HostOS, c.DataDir, "profiles.yaml")].Resolved), "profiles")
		for p, f := range s.files {
			if p == hostpath.Join(t.HostOS, c.DataDir, "profiles.yaml") {
				continue
			}
			rel, e := hostpath.Rel(t.HostOS, root, f.Resolved)
			if e != nil || rel == ".." || strings.HasPrefix(rel, "../") {
				return nil, errors.New("Verge companion symlink resolves outside profiles")
			}
		}
	}
	if e := s.refresh(); e != nil {
		return nil, e
	}
	return s, nil
}
func validateCompanion(n *yaml.Node) error {
	for _, key := range []string{"prepend", "append", "delete"} {
		v := get(n, key)
		if v != nil && v.Kind != yaml.SequenceNode {
			return errors.New("Verge companion expects prepend/append/delete sequences")
		}
	}
	return nil
}
func applySeq(companion, root *yaml.Node, key string) *yaml.Node {
	out := clone(root)
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	deleted := map[string]bool{}
	if d := get(companion, "delete"); d != nil {
		for _, n := range d.Content {
			deleted[n.Value] = true
		}
	}
	var added []string
	for _, k := range []string{"prepend", "original", "append"} {
		part := get(companion, k)
		if k == "original" {
			part = get(out, key)
		}
		if part == nil {
			continue
		}
		for _, n := range part.Content {
			name := scalar(n, "name")
			if k == "original" && deleted[name] {
				continue
			}
			seq.Content = append(seq.Content, clone(n))
			if k != "original" && key == "proxies" {
				added = append(added, name)
			}
		}
	}
	set(out, key, seq)
	if key == "proxies" {
		groups := get(out, "proxy-groups")
		first := false
		if groups != nil {
			for _, g := range groups.Content {
				p := get(g, "proxies")
				if p != nil && p.Kind == yaml.SequenceNode {
					var kept []*yaml.Node
					for _, v := range p.Content {
						if !deleted[v.Value] {
							kept = append(kept, v)
						}
					}
					p.Content = kept
				}
				typ := strings.ToLower(scalar(g, "type"))
				if !first && len(added) > 0 && (typ == "select" || typ == "selector") {
					first = true
					p = sequence(g, "proxies")
					seen := map[string]bool{}
					var all []*yaml.Node
					for _, v := range append(stringsNodes(added), p.Content...) {
						if !seen[v.Value] {
							all = append(all, v)
							seen[v.Value] = true
						}
					}
					p.Content = all
				}
			}
		}
	}
	return out
}
func stringsNodes(values []string) []*yaml.Node {
	out := make([]*yaml.Node, 0, len(values))
	for _, v := range values {
		out = append(out, str(v))
	}
	return out
}
func (s *source) effective() *yaml.Node {
	n := clone(s.docs[s.base])
	if s.Kind == "verge" {
		n = applySeq(s.docs[s.proxies], n, "proxies")
		n = applySeq(s.docs[s.groups], n, "proxy-groups")
	}
	return n
}
func (s *source) refresh() error {
	n := s.effective()
	var e error
	s.Proxies, e = proxyDefinitions(n, s.base)
	if e != nil {
		return e
	}
	s.Groups, e = definitions(n, "proxy-groups", "group", "source")
	if e != nil {
		return e
	}
	for i := range s.Proxies {
		if s.Proxies[i].Provider != "" {
			continue
		}
		s.Proxies[i].Origin = s.origin("proxy", s.Proxies[i].Name)
	}
	for i := range s.Groups {
		s.Groups[i].Origin = s.origin("group", s.Groups[i].Name)
	}
	return nil
}
func (s *source) origin(kind, name string) string {
	if s.Kind != "verge" {
		return s.base
	}
	path := s.proxies
	if kind == "group" {
		path = s.groups
	}
	for _, key := range []string{"prepend", "append"} {
		seq := get(s.docs[path], key)
		if seq != nil {
			for _, n := range seq.Content {
				if scalar(n, "name") == name {
					return path + "#" + key
				}
			}
		}
	}
	return s.base
}
func ReadDefinition(ctx context.Context, t config.Target, kind, name string, opts Options) (Definition, error) {
	s, e := inspectWithOptions(ctx, t, opts)
	if e != nil {
		return Definition{}, e
	}
	items := s.Proxies
	if kind == "group" {
		items = s.Groups
	}
	d, ok := find(items, name)
	if !ok {
		return Definition{}, errors.New("raw definition unavailable; runtime/provider metadata cannot reconstruct credentials")
	}
	return d, nil
}
