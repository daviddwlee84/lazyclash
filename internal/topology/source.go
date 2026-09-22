package topology

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/hostpath"
)

var ErrNoSource = errors.New("no complete YAML source: bind configs source or pass --source-path; --live can inspect an API-only target")

// SourceFor resolves read access only. Credential-discovery source_config is
// deliberately not promoted to a complete configuration source.
func SourceFor(t config.Target, explicit string) (Source, error) {
	s := Source{Kind: "yaml", Target: t.ID, Path: explicit}
	if explicit != "" {
		return s, nil
	}
	if t.Transient || t.TransportOverride || t.ConfigSource == nil {
		return s, ErrNoSource
	}
	c := t.ConfigSource
	s.Kind = c.Kind
	switch c.Kind {
	case "native", "mihomo":
		for _, item := range t.Configs {
			if item.ID == c.ConfigID {
				s.Path = item.Path
			}
		}
	case "docker":
		s.Path = c.HostPath
	case "verge":
		s.Path = hostpath.Join(t.HostOS, c.DataDir, "clash-verge.yaml")
		s.Generated = true
	}
	if s.Path == "" {
		return s, ErrNoSource
	}
	return s, nil
}

// Read never validates, reloads, refreshes providers, or writes files. opts.Host
// retains managed-core elevation/SSH handling while restricting the operation
// to read. The validator/binary required for editing is not needed here.
func Read(ctx context.Context, t config.Target, path string, live bool, opts configwork.Options) (Graph, error) {
	source, err := SourceFor(t, path)
	g := Graph{Source: source, Nodes: []Node{}, Edges: []Edge{}, Rules: []Rule{}}
	if err != nil && (!live || !errors.Is(err, ErrNoSource)) {
		return g, err
	}
	if err == nil {
		host := opts.Host
		if host == nil {
			host = configwork.DefaultHostOperation
		}
		result, e := host(ctx, t, configwork.HostRequest{Op: "read", Path: source.Path})
		if e != nil {
			return g, e
		}
		g, err = Parse(result.File.Data, source)
		if err != nil {
			return g, err
		}
	} else {
		g.Source.Kind = "runtime-only"
		g.warn("API-only snapshot: provider/filter declarations and saved YAML are unavailable")
	}
	if !live {
		return g, ctx.Err()
	}
	open := opts.Open
	if open == nil {
		open = connection.Open
	}
	c, closer, err := open(ctx, t, true)
	if closer != nil {
		defer closer.Close()
	}
	if c != nil {
		defer c.Close()
	}
	if err != nil {
		if g.Source.Kind != "runtime-only" && !connection.IsAuthRequired(err) && ctx.Err() == nil {
			g.RuntimeError = "could not connect to the controller; configuration retained"
			return g, nil
		}
		return g, err
	}
	if c == nil {
		return g, errors.New("controller returned no client")
	}
	proxies, err := c.Proxies(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return g, ctx.Err()
		}
		if g.Source.Kind == "runtime-only" || connection.IsAuthRequired(err) {
			return g, err
		}
		g.RuntimeError = "could not read current proxies; configuration retained"
		return g, nil
	}
	g.Overlay(proxies, time.Now().UTC())
	providers, err := c.Providers(ctx, "proxies")
	if err != nil {
		g.warn("Runtime provider membership unavailable")
	} else {
		g.overlayProviders(providers)
	}
	g.cycles("runtime")
	return g, ctx.Err()
}

func runtimeGroup(typ string) bool {
	switch strings.ToLower(typ) {
	case "selector", "select", "urltest", "url-test", "fallback", "loadbalance", "load-balance", "relay":
		return true
	}
	return false
}

// Overlay preserves configured edges. Observations carry their own origin and
// timestamp; no matching name can establish matching credentials or traffic.
func (g *Graph) Overlay(proxies map[string]core.Proxy, at time.Time) {
	g.ObservedAt = at
	ids := map[string]string{}
	kinds := map[string]string{}
	types := map[string]string{}
	members := map[string]map[string]bool{}
	for _, n := range g.Nodes {
		if n.Origin == "config" && (n.Kind == "group" || n.Kind == "proxy") {
			kinds[n.Name] = n.Kind
			types[n.Name] = n.Type
		}
	}
	for _, e := range g.Edges {
		if e.Kind == "member" && e.Origin == "config" {
			if members[e.From] == nil {
				members[e.From] = map[string]bool{}
			}
			members[e.From][e.To] = true
		}
	}
	for _, name := range sortedKeys(proxies) {
		p := proxies[name]
		kind := "proxy"
		if builtin(name) {
			kind = "builtin"
		} else if runtimeGroup(p.Type) || p.All != nil {
			kind = "group"
		}
		if previous := kinds[name]; previous != "" && previous != kind {
			g.warn("Runtime kind of %q differs from configuration (%s → %s)", name, previous, kind)
		}
		if previous := types[name]; previous != "" && normalizedType(previous) != normalizedType(p.Type) {
			g.warn("Runtime type of %q differs from configuration (%s → %s)", name, previous, p.Type)
		}
		ids[name] = g.addNode(kind, name, p.Type, "runtime")
	}
	for _, name := range sortedKeys(proxies) {
		p := proxies[name]
		if !runtimeGroup(p.Type) && p.All == nil {
			continue
		}
		from := ID("group", name)
		configured := members[from]
		for i, member := range p.All {
			to := ids[member]
			if to == "" {
				to = g.addNode("missing-runtime", member, "", "runtime")
				g.warn("Runtime member %q of %q has no definition in this snapshot", member, name)
			}
			g.Edges = append(g.Edges, Edge{From: from, To: to, Kind: "member", Origin: "runtime", Order: i, Selected: p.Now != "" && p.Now == member})
			delete(configured, to)
		}
		for _, id := range sortedKeys(configured) {
			g.warn("Configured member %q of %q is absent from runtime", g.node(id).Name, name)
		}
		if p.Now != "" && !contains(p.All, p.Now) {
			g.warn("Runtime selection of %q is absent from its member snapshot", name)
		}
	}
}

func (g *Graph) overlayProviders(obj core.Object) {
	providers := mapping(obj["providers"])
	for _, name := range sortedKeys(providers) {
		p := mapping(providers[name])
		id := g.addNode("provider", name, text(p["type"]), "runtime")
		for i, proxy := range entries(p["proxies"]) {
			name := text(proxy["name"])
			if name == "" {
				continue
			}
			nid := g.addNode("proxy", name, text(proxy["type"]), "runtime")
			g.edge(id, nid, "payload", "runtime", i)
		}
	}
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func normalizedType(value string) string {
	value = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(value, "-", ""), "_", ""))
	switch value {
	case "selector":
		return "select"
	case "shadowsocks":
		return "ss"
	case "shadowsocksr":
		return "ssr"
	}
	return value
}

func (g Graph) Detail(id string) string {
	n := g.node(id)
	if n == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s [%s / %s; %s]\n", n.Name, n.Kind, n.Type, n.Origin)
	if n.RuntimeType != "" {
		fmt.Fprintf(&b, "Runtime type: %s\n", n.RuntimeType)
	}
	for _, k := range sortedKeys(n.Declarations) {
		fmt.Fprintf(&b, "%s: %s\n", k, n.Declarations[k])
	}
	for _, e := range g.Edges {
		if e.From != id && e.To != id {
			continue
		}
		selected := ""
		if e.Selected {
			selected = " CURRENT"
		}
		fmt.Fprintf(&b, "%s → %s [%s #%d, %s%s]\n", g.node(e.From).Name, g.node(e.To).Name, e.Kind, e.Order+1, e.Origin, selected)
	}
	for _, rule := range g.Rules {
		if rule.Target == n.Name || rule.Scope == n.Name || n.Kind == "rules" && (n.Name == rule.Scope+" → "+rule.Target || n.Name == fmt.Sprintf("%s #%d %s → %s", rule.Scope, rule.Index+1, rule.Type, rule.Target)) {
			fmt.Fprintf(&b, "%s #%d: %s\n", rule.Scope, rule.Index+1, rule.Expression)
		}
	}
	return core.Sanitize(b.String())
}
