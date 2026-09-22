// Package topology inspects configuration relationships without evaluating
// routing rules, downloading providers, or modifying a core.
package topology

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/core"
)

type Source struct {
	Kind      string `json:"kind"`
	Path      string `json:"path,omitempty"`
	Target    string `json:"target,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Generated bool   `json:"generated,omitempty"`
}

// Node intentionally contains only display metadata, never a raw proxy map.
type Node struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Kind         string            `json:"kind"`
	Type         string            `json:"type,omitempty"`
	RuntimeType  string            `json:"runtime_type,omitempty"`
	Origin       string            `json:"origin"`
	Declarations map[string]string `json:"declarations,omitempty"`
}

type Edge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Kind     string `json:"kind"`
	Order    int    `json:"order"`
	Origin   string `json:"origin"`
	Selected bool   `json:"selected,omitempty"`
}

type Rule struct {
	Index      int    `json:"index"`
	Scope      string `json:"scope"`
	Expression string `json:"expression"`
	Type       string `json:"type,omitempty"`
	Target     string `json:"target,omitempty"`
	Provider   string `json:"provider,omitempty"`
	Resolved   bool   `json:"resolved"`
}

type Graph struct {
	Source       Source    `json:"source"`
	Nodes        []Node    `json:"nodes"`
	Edges        []Edge    `json:"edges"`
	Rules        []Rule    `json:"rules"`
	Diagnostics  []string  `json:"diagnostics,omitempty"`
	ObservedAt   time.Time `json:"observed_at,omitzero"`
	RuntimeError string    `json:"runtime_error,omitempty"`
	index        map[string]int
	outbounds    map[string]string
}

func ID(kind, name string) string {
	h := sha256.Sum256([]byte(kind + "\x00" + name))
	return fmt.Sprintf("n%x", h[:12])
}

func (g *Graph) addNode(kind, name, typ, origin string) string {
	g.indexNodes()
	id := ID(kind, name)
	if i, ok := g.index[id]; ok {
		if origin == "runtime" {
			g.Nodes[i].RuntimeType = typ
		}
		if g.Nodes[i].Origin != origin {
			g.Nodes[i].Origin = "config+runtime"
		}
		return id
	}
	g.index[id] = len(g.Nodes)
	if outboundKind(kind) && g.outbounds[name] == "" {
		g.outbounds[name] = id
	}
	g.Nodes = append(g.Nodes, Node{ID: id, Name: name, Kind: kind, Type: typ, Origin: origin})
	return id
}

func (g *Graph) node(id string) *Node {
	g.indexNodes()
	if i, ok := g.index[id]; ok {
		return &g.Nodes[i]
	}
	return nil
}

func outboundKind(kind string) bool { return kind == "group" || kind == "proxy" || kind == "builtin" }
func (g *Graph) indexNodes() {
	if g.index != nil {
		return
	}
	g.index = make(map[string]int, len(g.Nodes))
	g.outbounds = map[string]string{}
	for i, n := range g.Nodes {
		g.index[n.ID] = i
		if outboundKind(n.Kind) && g.outbounds[n.Name] == "" {
			g.outbounds[n.Name] = n.ID
		}
	}
}

func (g *Graph) edge(from, to, kind, origin string, order int) {
	g.Edges = append(g.Edges, Edge{From: from, To: to, Kind: kind, Origin: origin, Order: order})
}

func (g *Graph) warn(format string, args ...any) {
	g.Diagnostics = append(g.Diagnostics, core.Sanitize(fmt.Sprintf(format, args...)))
}

func builtin(name string) bool {
	switch name {
	case "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE":
		return true
	}
	return false
}

func (g *Graph) outbound(name, origin string) string {
	g.indexNodes()
	if id := g.outbounds[name]; id != "" {
		return id
	}
	if builtin(name) {
		return g.addNode("builtin", name, "", origin)
	}
	g.warn("Missing outbound reference %q", name)
	return g.addNode("missing", name, "", origin)
}

// Focus includes upstream ancestors and downstream descendants, without
// pulling in siblings through an ancestor. Names may match several node kinds.
func (g Graph) Focus(name string) (Graph, error) {
	if name == "" {
		return g, nil
	}
	seeds := map[string]bool{}
	for _, n := range g.Nodes {
		if n.Name == name || n.ID == name {
			seeds[n.ID] = true
		}
	}
	if len(seeds) == 0 {
		return Graph{}, fmt.Errorf("topology node %q was not found", core.Sanitize(name))
	}
	keep := map[string]bool{}
	for _, reverse := range []bool{false, true} {
		adj := map[string][]string{}
		for _, e := range g.Edges {
			from, to := e.From, e.To
			if reverse {
				from, to = to, from
			}
			adj[from] = append(adj[from], to)
		}
		seen := map[string]bool{}
		queue := []string{}
		for id := range seeds {
			queue = append(queue, id)
			seen[id] = true
		}
		for len(queue) > 0 {
			id := queue[0]
			queue = queue[1:]
			keep[id] = true
			for _, to := range adj[id] {
				if !seen[to] {
					seen[to] = true
					queue = append(queue, to)
				}
			}
		}
	}
	result := g
	result.Nodes, result.Edges = nil, nil
	result.index, result.outbounds = nil, nil
	for _, n := range g.Nodes {
		if keep[n.ID] {
			result.Nodes = append(result.Nodes, n)
		}
	}
	for _, e := range g.Edges {
		if keep[e.From] && keep[e.To] {
			result.Edges = append(result.Edges, e)
		}
	}
	return result, nil
}

func (g Graph) Summary() string {
	s := fmt.Sprintf("%s · %d nodes · %d relationships", g.Source.Kind, len(g.Nodes), len(g.Edges))
	if g.Source.Target != "" {
		s += " · " + g.Source.Target
	}
	if g.Source.Path != "" {
		s += "\nSource: " + g.Source.Path
	}
	if g.Source.Generated {
		s += "\nGenerated configuration snapshot; not proof of active runtime."
	}
	if !g.ObservedAt.IsZero() {
		s += "\nRuntime observed: " + g.ObservedAt.Format(time.RFC3339) + " (selection, not observed traffic)"
	}
	if g.RuntimeError != "" {
		s += "\nRuntime unavailable: " + g.RuntimeError
	}
	for _, d := range g.Diagnostics {
		s += "\n! " + d
	}
	return core.Sanitize(s)
}

func (g Graph) Relations() string {
	names := map[string]string{}
	var out strings.Builder
	for _, n := range g.Nodes {
		names[n.ID] = n.Name
		fmt.Fprintf(&out, "%s [%s", n.Name, n.Kind)
		if n.Type != "" {
			fmt.Fprintf(&out, "/%s", n.Type)
		}
		fmt.Fprintf(&out, "; %s]\n", n.Origin)
		keys := sortedKeys(n.Declarations)
		for _, k := range keys {
			fmt.Fprintf(&out, "  %s: %s\n", k, n.Declarations[k])
		}
	}
	out.WriteString("\nRelationships (order is local to each source):\n")
	for _, e := range g.Edges {
		selected := ""
		if e.Selected {
			selected = "; current selection"
		}
		fmt.Fprintf(&out, "%s --%s #%d [%s%s]--> %s\n", names[e.From], e.Kind, e.Order+1, e.Origin, selected, names[e.To])
	}
	return core.Sanitize(out.String())
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (g *Graph) cycles(origin string) {
	adj := map[string][]string{}
	for _, e := range g.Edges {
		if e.Origin == origin {
			adj[e.From] = append(adj[e.From], e.To)
		}
	}
	state := map[string]int{}
	var visit func(string)
	visit = func(id string) {
		state[id] = 1
		for _, next := range adj[id] {
			if state[next] == 1 {
				g.warn("Cyclic dependency [%s]: %s → %s", origin, g.node(id).Name, g.node(next).Name)
			} else if state[next] == 0 {
				visit(next)
			}
		}
		state[id] = 2
	}
	for _, n := range g.Nodes {
		if state[n.ID] == 0 {
			visit(n.ID)
		}
	}
}
