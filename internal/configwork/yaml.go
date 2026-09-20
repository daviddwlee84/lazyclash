package configwork

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"
)

func decode(data []byte) (*yaml.Node, error) {
	if len(data) == 0 || len(data) > MaxDocument {
		return nil, errors.New("configuration must contain 1 byte to 8 MiB")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var d yaml.Node
	if dec.Decode(&d) != nil || len(d.Content) != 1 {
		return nil, errors.New("invalid YAML/JSON document")
	}
	var more yaml.Node
	if dec.Decode(&more) != io.EOF {
		return nil, errors.New("only one YAML/JSON document is supported")
	}
	// Decoding also rejects duplicate mapping keys. Do not include parser errors:
	// they can quote credentials from the source.
	var value any
	if d.Decode(&value) != nil {
		return nil, errors.New("invalid or duplicate YAML keys")
	}
	return d.Content[0], nil
}
func encode(n *yaml.Node) ([]byte, error) {
	if n == nil {
		return nil, errors.New("missing YAML definition")
	}
	var b bytes.Buffer
	e := yaml.NewEncoder(&b)
	e.SetIndent(2)
	err := e.Encode(n)
	_ = e.Close()
	return b.Bytes(), err
}
func clone(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	memo := map[*yaml.Node]*yaml.Node{}
	var cp func(*yaml.Node) *yaml.Node
	cp = func(x *yaml.Node) *yaml.Node {
		if x == nil {
			return nil
		}
		if v := memo[x]; v != nil {
			return v
		}
		v := *x
		memo[x] = &v
		v.Content = nil
		for _, c := range x.Content {
			v.Content = append(v.Content, cp(c))
		}
		v.Alias = cp(x.Alias)
		return &v
	}
	return cp(n)
}
func get(n *yaml.Node, key string) *yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.AliasNode {
		return get(n.Alias, key)
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == "<<" {
			merge := n.Content[i+1]
			if merge.Kind == yaml.SequenceNode {
				for _, item := range merge.Content {
					if found := get(item, key); found != nil {
						return found
					}
				}
			} else if found := get(merge, key); found != nil {
				return found
			}
		}
	}
	return nil
}
func set(n *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content[i+1] = value
			return
		}
	}
	n.Content = append(n.Content, str(key), value)
}
func str(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }
func scalar(n *yaml.Node, key string) string {
	v := get(n, key)
	if v != nil {
		return v.Value
	}
	return ""
}
func sequence(n *yaml.Node, key string) *yaml.Node {
	v := get(n, key)
	if v == nil {
		v = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		set(n, key, v)
	}
	return v
}
func mapNode(value any) *yaml.Node { var n yaml.Node; _ = n.Encode(value); return &n }
func validName(s string) bool {
	return s != "" && len(s) <= 4096 && strings.IndexFunc(s, unicode.IsControl) < 0
}
func definition(n *yaml.Node, kind, origin string) (Definition, error) {
	if n == nil || n.Kind != yaml.MappingNode {
		return Definition{}, errors.New("definition must be a YAML mapping")
	}
	name, typ := scalar(n, "name"), scalar(n, "type")
	if !validName(name) || typ == "" {
		return Definition{}, errors.New("definition needs a valid name and type")
	}
	if kind == "proxy" {
		if (typ == "ss" || typ == "vmess" || typ == "vless" || typ == "trojan" || typ == "hysteria2") && (scalar(n, "server") == "" || get(n, "port") == nil) {
			return Definition{}, errors.New("node needs server and port")
		}
	} else {
		switch typ {
		case "select", "url-test", "fallback", "load-balance", "relay":
		default:
			return Definition{}, errors.New("unsupported group type")
		}
		if x := get(n, "proxies"); x != nil && x.Kind != yaml.SequenceNode {
			return Definition{}, errors.New("group proxies must be an ordered sequence")
		}
		if x := get(n, "use"); x != nil && x.Kind != yaml.SequenceNode {
			return Definition{}, errors.New("group use must be an ordered sequence")
		}
	}
	d := Definition{Name: name, Kind: kind, Type: typ, Origin: origin, Node: n}
	if kind == "group" {
		for _, v := range membersContent(get(n, "proxies")) {
			d.Members = append(d.Members, v.Value)
		}
		for _, v := range membersContent(get(n, "use")) {
			d.Providers = append(d.Providers, v.Value)
		}
	}
	return d, nil
}

// A selected definition may refer to anchors outside it. Materialize aliases
// when exporting a standalone node; source edits still retain the original AST.
func standalone(n *yaml.Node, stack map[*yaml.Node]bool) (*yaml.Node, error) {
	if n == nil {
		return nil, errors.New("missing definition")
	}
	if stack[n] {
		return nil, errors.New("cyclic YAML aliases cannot be exported")
	}
	stack[n] = true
	defer delete(stack, n)
	if n.Kind == yaml.AliasNode {
		return standalone(n.Alias, stack)
	}
	out := *n
	out.Anchor = ""
	out.Content = nil
	for _, child := range n.Content {
		v, e := standalone(child, stack)
		if e != nil {
			return nil, e
		}
		out.Content = append(out.Content, v)
	}
	return &out, nil
}
func definitions(root *yaml.Node, key, kind, origin string) ([]Definition, error) {
	v := get(root, key)
	if v == nil {
		return nil, nil
	}
	if v.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%s must be a sequence", key)
	}
	var out []Definition
	seen := map[string]bool{}
	for _, n := range v.Content {
		d, e := definition(n, kind, origin)
		if e != nil {
			return nil, e
		}
		if seen[d.Name] {
			return nil, errors.New("duplicate definition names in source")
		}
		seen[d.Name] = true
		out = append(out, d)
	}
	return out, nil
}
func mergeNode(base, patch *yaml.Node) *yaml.Node {
	out := clone(base)
	if out == nil || out.Kind != yaml.MappingNode || patch.Kind != yaml.MappingNode {
		return clone(patch)
	}
	for i := 0; i+1 < len(patch.Content); i += 2 {
		key := patch.Content[i].Value
		v := patch.Content[i+1]
		old := get(out, key)
		if old != nil && old.Kind == yaml.MappingNode && v.Kind == yaml.MappingNode {
			set(out, key, mergeNode(old, v))
		} else {
			set(out, key, clone(v))
		}
	}
	return out
}
func find(items []Definition, name string) (Definition, bool) {
	for _, d := range items {
		if d.Name == name {
			return d, true
		}
	}
	return Definition{}, false
}
func replaceSeq(root *yaml.Node, key, name string, node *yaml.Node, add bool) error {
	seq := sequence(root, key)
	if seq.Kind != yaml.SequenceNode {
		return errors.New("source sequence is invalid")
	}
	for i, n := range seq.Content {
		if scalar(n, "name") == name {
			if add {
				return errors.New("destination name already exists")
			}
			seq.Content[i] = clone(node)
			return nil
		}
	}
	if !add {
		return errors.New("definition was removed since selection")
	}
	seq.Content = append(seq.Content, clone(node))
	return nil
}
func proxyDefinitions(n *yaml.Node, origin string) ([]Definition, error) {
	out, e := definitions(n, "proxies", "proxy", origin)
	if e != nil {
		return nil, e
	}
	if providers := get(n, "proxy-providers"); providers != nil && providers.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(providers.Content); i += 2 {
			name, p := providers.Content[i].Value, providers.Content[i+1]
			if scalar(p, "type") != "inline" {
				continue
			}
			items, e := definitions(p, "payload", "proxy", origin+"#provider:"+name)
			if e != nil {
				return nil, e
			}
			for _, item := range items {
				item.Provider = name
				if _, exists := find(out, item.Name); exists {
					return nil, errors.New("raw node name is ambiguous across proxy sources")
				}
				out = append(out, item)
			}
		}
	}
	return out, nil
}

// PatchDefinition updates explicit fields and removes only explicitly selected
// keys. All other YAML nodes, including unknown options/comments, are retained.
func PatchDefinition(raw []byte, fields map[string]any, remove []string) ([]byte, error) {
	var n *yaml.Node
	var err error
	if len(raw) == 0 {
		n = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	} else {
		n, err = decode(raw)
		if err != nil {
			return nil, err
		}
		if n.Kind != yaml.MappingNode {
			return nil, errors.New("definition must be a mapping")
		}
	}
	n = clone(n)
	for _, key := range remove {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				n.Content = append(n.Content[:i], n.Content[i+2:]...)
				break
			}
		}
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		set(n, key, mapNode(fields[key]))
	}
	return encode(n)
}
