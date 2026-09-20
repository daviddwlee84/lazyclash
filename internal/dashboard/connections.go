package dashboard

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/core"
)

// Filter is an exact predicate, independent of display labels or free-text
// queries. A drill-down remains meaningful as connections open and close.
type Filter struct {
	Kind  string
	Value string
}

func (f Filter) Match(connection core.Object) bool {
	switch f.Kind {
	case "protocol":
		return protocol(connection) == f.Value
	case "outbound":
		return outbound(connection) == f.Value
	case "route":
		return routeKey(connection) == f.Value
	case "group":
		chain := chains(connection)
		for _, group := range chain[min(1, len(chain)):] {
			if group == f.Value {
				return true
			}
		}
		return false
	case "":
		return true
	default:
		return false
	}
}

type Bucket struct {
	Key, Label    string
	Count         int
	Upload        float64
	Download      float64
	ConnectionIDs []string
	// Groups are ordered from outer selector to the innermost group. They
	// describe the observed connection chain, not current group selection.
	Groups []string
	Filter Filter
}

type ConnectionSummary struct {
	Count                        int
	Protocols, Outbounds, Routes []Bucket
	Groups                       []Bucket
}

// SummarizeConnections aggregates every record in the supplied response. The
// caller may then trim the independent connection-browsing list.
func SummarizeConnections(data core.Object) ConnectionSummary {
	protocols, outbounds, routes, groups := make(map[string]*Bucket), make(map[string]*Bucket), make(map[string]*Bucket), make(map[string]*Bucket)
	for _, network := range []string{"tcp", "udp", "other"} {
		protocols[network] = &Bucket{Key: network, Label: strings.ToUpper(network), Filter: Filter{Kind: "protocol", Value: network}}
	}
	result := ConnectionSummary{}
	for _, item := range objects(data["connections"]) {
		if item == nil {
			continue
		}
		result.Count++
		addBucket(protocols[protocol(item)], item)
		leaf := outbound(item)
		if outbounds[leaf] == nil {
			label := leaf
			if label == "" {
				label = "Unknown outbound"
			}
			outbounds[leaf] = &Bucket{Key: leaf, Label: display(label), Filter: Filter{Kind: "outbound", Value: leaf}}
		}
		addBucket(outbounds[leaf], item)
		key := routeKey(item)
		if routes[key] == nil {
			chain := chains(item)
			var routeGroups []string
			for i := len(chain) - 1; i >= 1; i-- {
				routeGroups = append(routeGroups, chain[i])
			}
			routes[key] = &Bucket{Key: key, Label: routeLabel(item), Groups: routeGroups, Filter: Filter{Kind: "route", Value: key}}
		}
		addBucket(routes[key], item)
		seenGroups := make(map[string]bool)
		chain := chains(item)
		for _, name := range chain[min(1, len(chain)):] {
			if seenGroups[name] {
				continue
			}
			seenGroups[name] = true
			if groups[name] == nil {
				groups[name] = &Bucket{Key: name, Label: display(name), Filter: Filter{Kind: "group", Value: name}}
			}
			addBucket(groups[name], item)
		}
	}
	result.Protocols = []Bucket{*protocols["tcp"], *protocols["udp"], *protocols["other"]}
	result.Outbounds, result.Routes, result.Groups = sortedBuckets(outbounds), sortedBuckets(routes), sortedBuckets(groups)
	return result
}

func addBucket(bucket *Bucket, connection core.Object) {
	bucket.Count++
	if value, ok := numeric(connection["upload"]); ok {
		bucket.Upload += value
	}
	if value, ok := numeric(connection["download"]); ok {
		bucket.Download += value
	}
	if id, ok := connection["id"].(string); ok && id != "" {
		bucket.ConnectionIDs = append(bucket.ConnectionIDs, id)
	}
}

func sortedBuckets(values map[string]*Bucket) []Bucket {
	result := make([]Bucket, 0, len(values))
	for _, bucket := range values {
		result = append(result, *bucket)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		if totalI, totalJ := result[i].Upload+result[i].Download, result[j].Upload+result[j].Download; totalI != totalJ {
			return totalI > totalJ
		}
		return result[i].Key < result[j].Key
	})
	return result
}

func protocol(connection core.Object) string {
	network, _ := object(connection["metadata"])["network"].(string)
	network = strings.ToLower(network)
	if network != "tcp" && network != "udp" {
		return "other"
	}
	return network
}

func outbound(connection core.Object) string {
	chain := chains(connection)
	if len(chain) == 0 {
		return ""
	}
	return chain[0]
}

func routeKey(connection core.Object) string {
	rule, _ := connection["rule"].(string)
	payload, _ := connection["rulePayload"].(string)
	// Structured encoding makes separators in rule/group/node names harmless.
	key, _ := json.Marshal([]any{rule, payload, chains(connection)})
	return string(key)
}

func routeLabel(connection core.Object) string {
	rule, _ := connection["rule"].(string)
	payload, _ := connection["rulePayload"].(string)
	if rule == "" {
		rule = "Unknown rule"
	}
	if payload != "" {
		rule += ": " + payload
	}
	parts := []string{rule}
	chain := chains(connection)
	for i := len(chain) - 1; i >= 0; i-- {
		parts = append(parts, chain[i])
	}
	return display(strings.Join(parts, " → "))
}

func display(value string) string {
	return strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(core.Sanitize(value))
}

func chains(connection core.Object) []string {
	switch items := connection["chains"].(type) {
	case []string:
		return items
	case []any:
		result := make([]string, 0, len(items))
		for _, item := range items {
			if value, ok := item.(string); ok {
				result = append(result, value)
			}
		}
		return result
	default:
		return nil
	}
}

func object(value any) core.Object {
	switch value := value.(type) {
	case core.Object:
		return value
	case map[string]any:
		return core.Object(value)
	default:
		return nil
	}
}

func objects(value any) []core.Object {
	switch items := value.(type) {
	case []core.Object:
		return items
	case []map[string]any:
		result := make([]core.Object, len(items))
		for i, item := range items {
			result[i] = core.Object(item)
		}
		return result
	case []any:
		result := make([]core.Object, len(items))
		for i, item := range items {
			result[i] = object(item)
		}
		return result
	default:
		return nil
	}
}
