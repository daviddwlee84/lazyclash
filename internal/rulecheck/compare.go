package rulecheck

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"
)

// Entry retains the source section and its original rule index. A delete
// section contains owner directives, not active routing rules.
type Entry struct {
	Section string `json:"section"`
	Rule    Rule   `json:"rule"`
}

type RuleChange struct {
	Kind   string   `json:"kind"`
	Left   *Entry   `json:"left,omitempty"`
	Right  *Entry   `json:"right,omitempty"`
	Fields []string `json:"fields,omitempty"`
}

type DiffReport struct {
	Equal       bool         `json:"equal_compared_rules"`
	Changes     []RuleChange `json:"changes"`
	Limitations []string     `json:"limitations"`
}

// CompareEntries compares ordered occurrences, not sets. reported compares only
// controller-reported fields; source options are deliberately not inferred.
// Opaque source expressions are literal comparisons, never semantic claims.
func CompareEntries(left, right []Entry, reported bool) DiffReport {
	report := DiffReport{Equal: true, Changes: []RuleChange{}, Limitations: comparisonLimits(reported)}
	leftMatch, rightMatch := make([]int, len(left)), make([]int, len(right))
	literalPairs := map[int]bool{}
	for i := range leftMatch {
		leftMatch[i] = -1
	}
	for i := range rightMatch {
		rightMatch[i] = -1
	}
	pair := func(key func(Entry) string) {
		queues := map[string][]int{}
		for i, entry := range right {
			if rightMatch[i] < 0 {
				if k := key(entry); k != "" {
					queues[k] = append(queues[k], i)
				}
			}
		}
		for i, entry := range left {
			if leftMatch[i] >= 0 {
				continue
			}
			k := key(entry)
			queue := queues[k]
			if k == "" || len(queue) == 0 {
				continue
			}
			j := queue[0]
			queues[k] = queue[1:]
			leftMatch[i], rightMatch[j] = j, i
		}
	}
	// Exact full-rule occurrences get priority, avoiding an earlier policy
	// alternative consuming a later identical rule during selector pairing.
	pair(func(entry Entry) string {
		if entry.Section == "delete" {
			return scopedKey(entry.Section, jsonKey([]any{"directive", strings.TrimSpace(entry.Rule.Raw)}))
		}
		return scopedKey(entry.Section, fullKey(entry.Rule, reported))
	})
	if reported {
		// A source with unknown grammar has only a serialized expression,
		// while the runtime exposes its own parsed fields. Pair identical full
		// expressions without asserting their unknown field boundaries agree.
		allRight, literalRight := map[string][]int{}, map[string][]int{}
		for j, entry := range right {
			if rightMatch[j] >= 0 || strings.TrimSpace(entry.Rule.Raw) == "" {
				continue
			}
			key := scopedKey(entry.Section, literalExpressionKey(entry.Rule, true))
			allRight[key] = append(allRight[key], j)
			if entry.Rule.LiteralOnly {
				literalRight[key] = append(literalRight[key], j)
			}
		}
		for i, entry := range left {
			if leftMatch[i] >= 0 || strings.TrimSpace(entry.Rule.Raw) == "" {
				continue
			}
			key := scopedKey(entry.Section, literalExpressionKey(entry.Rule, true))
			queues := literalRight
			if entry.Rule.LiteralOnly {
				queues = allRight
			}
			queue := queues[key]
			for len(queue) > 0 && rightMatch[queue[0]] >= 0 {
				queue = queue[1:]
			}
			if len(queue) == 0 {
				queues[key] = queue
				continue
			}
			j := queue[0]
			queues[key] = queue[1:]
			leftMatch[i], rightMatch[j], literalPairs[i] = j, i, true
		}
	}
	pair(func(entry Entry) string {
		if entry.Section == "delete" {
			return ""
		}
		key := selectorKey(entry.Rule, reported)
		if key == "" {
			return ""
		}
		return scopedKey(entry.Section, key)
	})
	stable := stableOrder(left, leftMatch)
	for i, entry := range left {
		j := leftMatch[i]
		if j < 0 {
			report.Changes = append(report.Changes, RuleChange{Kind: "removed", Left: copyEntry(entry)})
			continue
		}
		fields := differences(entry.Rule, right[j].Rule, reported)
		if literalPairs[i] || entry.Rule.LiteralOnly || right[j].Rule.LiteralOnly {
			fields = nil
			if entry.Rule.Disabled != right[j].Rule.Disabled {
				fields = append(fields, "enabled")
			}
		}
		if entry.Section == "delete" {
			fields = nil
		}
		moved := !stable[i]
		if moved {
			fields = append(fields, "order")
		}
		if len(fields) == 0 {
			continue
		}
		kind := "changed"
		if len(fields) == 1 && moved {
			kind = "moved"
		}
		report.Changes = append(report.Changes, RuleChange{Kind: kind, Left: copyEntry(entry), Right: copyEntry(right[j]), Fields: fields})
	}
	for i, entry := range right {
		if rightMatch[i] < 0 {
			report.Changes = append(report.Changes, RuleChange{Kind: "added", Right: copyEntry(entry)})
		}
	}
	report.Equal = len(report.Changes) == 0
	for _, entries := range [][]Entry{left, right} {
		for _, entry := range entries {
			if entry.Rule.Opaque || entry.Rule.Invalid != "" {
				report.Limitations = append(report.Limitations, "Opaque or invalid source rules use literal equality; runtime rules use reported fields. Equality does not prove equivalent matcher behavior.")
				return report
			}
		}
	}
	return report
}

// stableOrder finds an increasing subsequence of paired positions per section.
// Adding/removing an earlier rule does not turn every later rule into a move.
// Duplicate occurrences are paired deterministically from left to right.
func stableOrder(left []Entry, matches []int) map[int]bool {
	sections := map[string][]int{}
	for i, j := range matches {
		if j >= 0 {
			sections[left[i].Section] = append(sections[left[i].Section], i)
		}
	}
	stable := map[int]bool{}
	for _, indices := range sections {
		tails := []int{}
		previous := make([]int, len(indices))
		for position, index := range indices {
			j := matches[index]
			slot := sort.Search(len(tails), func(k int) bool { return matches[indices[tails[k]]] >= j })
			previous[position] = -1
			if slot > 0 {
				previous[position] = tails[slot-1]
			}
			if slot == len(tails) {
				tails = append(tails, position)
			} else {
				tails[slot] = position
			}
		}
		if len(tails) > 0 {
			for position := tails[len(tails)-1]; position >= 0; position = previous[position] {
				stable[indices[position]] = true
			}
		}
	}
	return stable
}

func comparisonLimits(reported bool) []string {
	limits := []string{"Comparison covers ordered rule declarations, not provider contents, policy implementations or observed traffic."}
	if reported {
		limits = append(limits, "Runtime comparison uses reported type, payload, policy and disabled state; options such as no-resolve are unavailable.")
	}
	return limits
}

func copyEntry(entry Entry) *Entry {
	entry.Rule.Options = append([]string(nil), entry.Rule.Options...)
	return &entry
}

func scopedKey(section, key string) string { return jsonKey([]any{section, key}) }
func jsonKey(value any) string             { data, _ := json.Marshal(value); return string(data) }

func selectorKey(rule Rule, reported bool) string {
	if !reported {
		return rule.SelectorKey()
	}
	if rule.LiteralOnly || rule.Invalid != "" || rule.Type == "" {
		return ""
	}
	// Runtime equality is an equality of exposed fields even for opaque kinds.
	return jsonKey([]any{reportedKind(rule.Type), rule.Payload, rule.SourceIP})
}

// These explicit aliases are the names emitted by Mihomo RuleType.String.
// Unknown future spellings remain distinct; removing all hyphens would imply
// relationships between rule types we do not know.
func reportedKind(kind string) string {
	kind = strings.ToUpper(kind)
	if known := reportedKindAliases[kind]; known != "" {
		return known
	}
	return kind
}

var reportedKindAliases = map[string]string{
	"DOMAINSUFFIX": "DOMAIN-SUFFIX", "DOMAINKEYWORD": "DOMAIN-KEYWORD", "DOMAINREGEX": "DOMAIN-REGEX", "DOMAINWILDCARD": "DOMAIN-WILDCARD",
	"SRCGEOIP": "SRC-GEOIP", "IPASN": "IP-ASN", "SRCIPASN": "SRC-IP-ASN", "IPCIDR": "IP-CIDR", "SRCIPCIDR": "SRC-IP-CIDR", "IPSUFFIX": "IP-SUFFIX", "SRCIPSUFFIX": "SRC-IP-SUFFIX",
	"SRCPORT": "SRC-PORT", "DSTPORT": "DST-PORT", "INPORT": "IN-PORT", "INUSER": "IN-USER", "INNAME": "IN-NAME", "INTYPE": "IN-TYPE",
	"PROCESSNAME": "PROCESS-NAME", "PROCESSPATH": "PROCESS-PATH", "PROCESSNAMEREGEX": "PROCESS-NAME-REGEX", "PROCESSPATHREGEX": "PROCESS-PATH-REGEX", "PROCESSNAMEWILDCARD": "PROCESS-NAME-WILDCARD", "PROCESSPATHWILDCARD": "PROCESS-PATH-WILDCARD",
	"REMATCHNAME": "REMATCH-NAME", "RULESET": "RULE-SET", "SUBRULES": "SUB-RULE",
}

func fullKey(rule Rule, reported bool) string {
	key := selectorKey(rule, reported)
	if key == "" {
		return jsonKey([]any{"literal", literalExpressionKey(rule, reported), rule.Disabled})
	}
	if reported {
		return jsonKey([]any{"reported", key, rule.Policy, rule.Disabled})
	}
	return jsonKey([]any{"canonical", key, rule.Policy, rule.NoResolve, append([]string{}, rule.Options...), rule.Disabled})
}

func literalExpressionKey(rule Rule, reported bool) string {
	raw := strings.TrimSpace(rule.Raw)
	if !reported {
		return raw
	}
	kind, remainder, comma := strings.Cut(raw, ",")
	if !comma {
		return raw
	}
	return reportedKind(strings.TrimSpace(kind)) + "," + remainder
}

func differences(left, right Rule, reported bool) []string {
	fields := []string{}
	if left.Policy != right.Policy {
		fields = append(fields, "policy")
	}
	if !reported && (left.NoResolve != right.NoResolve || !slices.Equal(left.Options, right.Options)) {
		fields = append(fields, "options")
	}
	if left.Disabled != right.Disabled {
		fields = append(fields, "enabled")
	}
	return fields
}
