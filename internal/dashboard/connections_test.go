package dashboard

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/core"
)

func connection(id, network, leaf string) core.Object {
	return core.Object{"id": id, "metadata": core.Object{"network": network}, "chains": []string{leaf, "Auto", "PROXY"}, "rule": "DomainSuffix", "rulePayload": "example.com", "upload": 10, "download": 20}
}

func TestSummaryUsesFullListAndDrillsExactly(t *testing.T) {
	items := make([]any, 2501)
	for i := range items {
		network, leaf := "tcp", "node"
		if i == 2000 {
			network, leaf = "udp", "node/secondary"
		}
		if i == 2500 {
			network, leaf = "icmp", "node"
		}
		items[i] = connection(fmt.Sprint(i), network, leaf)
	}
	summary := SummarizeConnections(core.Object{"connections": items})
	if summary.Count != 2501 || summary.Protocols[0].Count != 2499 || summary.Protocols[1].Count != 1 || summary.Protocols[2].Count != 1 {
		t.Fatalf("summary truncated before aggregation: %+v", summary.Protocols)
	}
	if len(summary.Outbounds) != 2 || summary.Outbounds[0].Count != 2500 || summary.Outbounds[0].Download != 50000 || len(summary.Outbounds[0].ConnectionIDs) != 2500 {
		t.Fatalf("wrong outbound aggregation: %+v", summary.Outbounds)
	}
	if summary.Outbounds[0].Filter.Match(items[2000].(core.Object)) {
		t.Fatal("outbound drill matched a substring, not the exact leaf")
	}
	if !summary.Protocols[2].Filter.Match(items[2500].(core.Object)) || summary.Protocols[2].Filter.Match(items[0].(core.Object)) {
		t.Fatal("other network drill predicate differs from aggregation")
	}
	for _, bucket := range append(append(append(summary.Protocols, summary.Outbounds...), summary.Routes...), summary.Groups...) {
		count := 0
		for _, item := range items {
			if bucket.Filter.Match(item.(core.Object)) {
				count++
			}
		}
		if count != bucket.Count {
			t.Errorf("bucket %s %q counts %d records but drill matches %d", bucket.Filter.Kind, bucket.Key, bucket.Count, count)
		}
	}
}

func TestObservedRoutesReverseLeafFirstChain(t *testing.T) {
	item := connection("one", "TCP", "🇯🇵 東京/01")
	summary := SummarizeConnections(core.Object{"connections": []core.Object{item}})
	route := summary.Routes[0]
	if route.Label != "DomainSuffix: example.com → PROXY → Auto → 🇯🇵 東京/01" || !slices.Equal(route.Groups, []string{"PROXY", "Auto"}) {
		t.Fatalf("route must show rule → outer group → inner group → leaf: %+v", route)
	}
	if summary.Protocols[0].Count != 1 {
		t.Fatal("network case normalization failed")
	}
	changed := connection("two", "tcp", "🇯🇵 東京/01")
	changed["rulePayload"] = "different.example"
	if route.Filter.Match(changed) {
		t.Fatal("route drill ignored rule payload")
	}
	changed["rulePayload"] = "example.com"
	changed["chains"] = []any{"🇯🇵 東京/01", "PROXY", "Auto"}
	if route.Filter.Match(changed) {
		t.Fatal("route drill ignored group order")
	}
}

func TestRouteIdentityCannotCollideOnDisplaySeparators(t *testing.T) {
	one, two := connection("one", "tcp", "node → group"), connection("two", "tcp", "node")
	one["chains"] = []string{"node → group"}
	two["chains"] = []string{"group", "node"}
	if routeLabel(one) != routeLabel(two) {
		t.Fatal("fixture should intentionally collide as a display label")
	}
	if routeKey(one) == routeKey(two) {
		t.Fatal("structured route identity collided")
	}
	summary := SummarizeConnections(core.Object{"connections": []any{one, two}})
	if len(summary.Routes) != 2 {
		t.Fatal("distinct routes merged on display label")
	}
}

func TestUnknownAndEmptyConnections(t *testing.T) {
	empty := SummarizeConnections(core.Object{"connections": []any{}})
	if empty.Count != 0 || len(empty.Protocols) != 3 || len(empty.Routes) != 0 {
		t.Fatalf("empty success: %+v", empty)
	}
	item := core.Object{"id": "one"}
	summary := SummarizeConnections(core.Object{"connections": []map[string]any{map[string]any(item)}})
	if summary.Protocols[2].Count != 1 || summary.Outbounds[0].Label != "Unknown outbound" || !strings.Contains(summary.Routes[0].Label, "Unknown rule") || len(summary.Groups) != 0 {
		t.Fatalf("unknown metadata guessed a route: %+v", summary)
	}
	if !summary.Routes[0].Filter.Match(item) || !summary.Outbounds[0].Filter.Match(item) || (Filter{Kind: "wrong"}).Match(item) {
		t.Fatal("unknown drill predicates inconsistent")
	}
}
