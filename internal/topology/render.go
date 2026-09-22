package topology

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/AlexanderGrooff/mermaid-ascii/pkg/diagram"
	"github.com/AlexanderGrooff/mermaid-ascii/pkg/render"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

// Both renderers consume the same conservative Mermaid subset. Syntax-bearing
// punctuation in labels uses visually similar Unicode characters, because the
// terminal renderer does not decode Mermaid HTML entities. Exact names remain
// available in relations/JSON; generated IDs never contain user input.
func label(s string) string {
	s = core.Sanitize(s)
	r := strings.NewReplacer("\n", " ", "\r", " ", "\t", " ", `"`, "＂", "\\", "＼", "&", "＆", "<", "＜", ">", "＞", "|", "｜", "-", "‐", "`", "｀")
	return r.Replace(s)
}

func Mermaid(g Graph) string {
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	for _, n := range orderedNodes(g) {
		fmt.Fprintf(&b, "    %s[\"%s [%s]\"]\n", n.ID, label(n.Name), label(n.Kind))
	}
	for _, e := range g.Edges {
		style := "-->"
		if e.Kind == "dialer" || e.Kind == "dialer-override" || e.Kind == "declaration" {
			style = "-.->"
		}
		text := e.Kind
		if e.Kind == "member" && e.Origin == "config" {
			text = ""
		}
		if e.Origin == "runtime" {
			text += " live"
		}
		if e.Kind == "relay-member" {
			text += fmt.Sprintf(" #%d", e.Order+1)
		}
		if e.Selected {
			text = "CURRENT live"
			style = "==>"
		}
		if text == "" {
			fmt.Fprintf(&b, "    %s %s %s\n", e.From, style, e.To)
		} else {
			fmt.Fprintf(&b, "    %s %s|%s| %s\n", e.From, style, label(text), e.To)
		}
	}
	return b.String()
}

// The terminal engine uses declaration order when placing nodes. Declare DAG
// parents before children so a YAML file's proxies-first order does not turn a
// route into backward/crossing arrows. Model order and edge order stay intact.
func orderedNodes(g Graph) []Node {
	byID := map[string]Node{}
	degree := map[string]int{}
	children := map[string][]string{}
	for _, n := range g.Nodes {
		byID[n.ID] = n
	}
	for _, e := range g.Edges {
		degree[e.To]++
		children[e.From] = append(children[e.From], e.To)
	}
	queue := []Node{}
	for _, n := range g.Nodes {
		if degree[n.ID] == 0 {
			queue = append(queue, n)
		}
	}
	rank := func(kind string) int {
		switch kind {
		case "rules":
			return 0
		case "sub-rule":
			return 1
		case "group":
			return 2
		case "provider", "rule-provider":
			return 3
		}
		return 4
	}
	sort.SliceStable(queue, func(i, j int) bool { return rank(queue[i].Kind) < rank(queue[j].Kind) })
	result := make([]Node, 0, len(g.Nodes))
	seen := map[string]bool{}
	for i := 0; i < len(queue); i++ {
		n := queue[i]
		result = append(result, n)
		seen[n.ID] = true
		for _, id := range children[n.ID] {
			degree[id]--
			if degree[id] == 0 {
				if child, ok := byID[id]; ok {
					queue = append(queue, child)
				}
			}
		}
	}
	// Mermaid can represent cycles even when terminal layout cannot.
	for _, n := range g.Nodes {
		if !seen[n.ID] {
			result = append(result, n)
		}
	}
	return result
}

// ASCII bounds work before entering the third-party layout engine. The full
// graph always remains available as Mermaid/JSON/relations, including cycles.
func ASCII(g Graph, width int) (output string, err error) {
	if len(g.Nodes) == 0 {
		return "No routing relationships found.", nil
	}
	if len(g.Nodes) > 120 || len(g.Edges) > 240 {
		return "", errors.New("graph is too large for terminal layout; use --focus NAME, --view relations, or --format mermaid")
	}
	for _, n := range g.Nodes {
		if len([]rune(n.Name)) > 160 {
			return "", errors.New("a graph label is too long for terminal layout; use relations or Mermaid")
		}
	}
	if hasCycle(g) {
		return "", errors.New("cyclic dependencies are available in relations/Mermaid; terminal layout requires an acyclic graph")
	}
	defer func() {
		if recover() != nil {
			output, err = "", errors.New("terminal layout failed; use relations or Mermaid")
		}
	}()
	cfg := diagram.DefaultConfig()
	cfg.UseAscii = true
	cfg.MaxWidth = max(width, 0)
	cfg.PaddingBetweenX, cfg.PaddingBetweenY = 2, 1
	return render.RenderDiagram(Mermaid(g), cfg)
}

func hasCycle(g Graph) bool {
	adj := map[string][]string{}
	for _, e := range g.Edges {
		adj[e.From] = append(adj[e.From], e.To)
	}
	state := map[string]int{}
	var visit func(string) bool
	visit = func(id string) bool {
		if state[id] == 1 {
			return true
		}
		if state[id] == 2 {
			return false
		}
		state[id] = 1
		for _, next := range adj[id] {
			if visit(next) {
				return true
			}
		}
		state[id] = 2
		return false
	}
	for _, n := range g.Nodes {
		if visit(n.ID) {
			return true
		}
	}
	return false
}
