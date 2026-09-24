package rulecheck

import (
	"reflect"
	"testing"
)

func entries(lines ...string) []Entry {
	rules := parsed(lines...)
	result := make([]Entry, len(rules))
	for i, rule := range rules {
		result[i] = Entry{Section: "rules", Rule: rule}
	}
	return result
}

func TestOrderedDiffInsertionAndRemovalDoNotMoveEveryRule(t *testing.T) {
	a := "DOMAIN,a.example,DIRECT"
	b := "DOMAIN,b.example,DIRECT"
	x := "DOMAIN,new.example,DIRECT"
	left, right := entries(a, b), entries(x, a, b)
	left[0].Rule.Index, left[1].Rule.Index = 90, 100
	got := CompareEntries(left, right, false)
	if got.Equal || len(got.Changes) != 1 || got.Changes[0].Kind != "added" || got.Changes[0].Right.Rule.Payload != "new.example" {
		t.Fatalf("insertion manufactured moves: %+v", got)
	}
	reverse := CompareEntries(right, left, false)
	if len(reverse.Changes) != 1 || reverse.Changes[0].Kind != "removed" {
		t.Fatalf("removal manufactured moves: %+v", reverse)
	}
}

func TestOrderedDiffPreservesDuplicateOccurrencesAndExactFirstPairing(t *testing.T) {
	a, b := "DOMAIN,same.example,DIRECT", "DOMAIN,same.example,PROXY"
	r := CompareEntries(entries(a, b), entries(b), false)
	if len(r.Changes) != 1 || r.Changes[0].Kind != "removed" || r.Changes[0].Left.Rule.Policy != "DIRECT" {
		t.Fatalf("same selector consumed an exact occurrence: %+v", r)
	}
	r = CompareEntries(entries(a, a), entries(a), false)
	if len(r.Changes) != 1 || r.Changes[0].Left.Rule.Index != 1 || r.Changes[0].Kind != "removed" {
		t.Fatalf("duplicate count lost: %+v", r)
	}
	r = CompareEntries(entries(a, b), entries(b, a), false)
	if len(r.Changes) != 1 || r.Changes[0].Kind != "moved" || !reflect.DeepEqual(r.Changes[0].Fields, []string{"order"}) {
		t.Fatalf("relative reorder not isolated: %+v", r)
	}
}

func TestDiffReportsPolicyModifiersAndEnabledChanges(t *testing.T) {
	left := entries("IP-CIDR,192.0.2.1/24,DIRECT")
	right := entries("IP-CIDR6,192.0.2.0/24,PROXY,no-resolve")
	right[0].Rule.Disabled = true
	r := CompareEntries(left, right, false)
	if len(r.Changes) != 1 || r.Changes[0].Kind != "changed" || !reflect.DeepEqual(r.Changes[0].Fields, []string{"policy", "options", "enabled"}) {
		t.Fatalf("lost changed fields: %+v", r)
	}
	r = CompareEntries(left, right, true)
	if len(r.Changes) != 1 || !reflect.DeepEqual(r.Changes[0].Fields, []string{"policy", "enabled"}) {
		t.Fatalf("runtime inferred unavailable modifiers: %+v", r)
	}
	alias := entries("IP-CIDR6,192.0.2.0/24,DIRECT")
	alias[0].Rule.Options = []string{}
	if !CompareEntries(left, alias, false).Equal {
		t.Fatal("safe canonical equality or nil/empty option equality was lost")
	}
}

func TestOpaqueSourceIsLiteralWhileRuntimeUsesReportedFields(t *testing.T) {
	left := entries("RULE-SET,remote,DIRECT")
	if !CompareEntries(left, entries("RULE-SET,remote,DIRECT"), false).Equal {
		t.Fatal("identical opaque literal was not comparable")
	}
	right := entries("RULE-SET,remote,PROXY")
	if got := CompareEntries(left, right, false); len(got.Changes) != 2 || len(got.Limitations) == 0 {
		t.Fatalf("opaque source semantics inferred: %+v", got)
	}
	if got := CompareEntries(left, right, true); len(got.Changes) != 1 || got.Changes[0].Kind != "changed" || !reflect.DeepEqual(got.Changes[0].Fields, []string{"policy"}) {
		t.Fatalf("runtime visible fields not compared: %+v", got)
	}
	if CompareEntries(entries("DOMAIN,example.com.,DIRECT"), entries("DOMAIN,example.com,DIRECT"), false).Equal {
		t.Fatal("opaque trailing-dot source silently normalized")
	}
}

func TestSectionsAndDeleteDirectivesRemainSeparate(t *testing.T) {
	left := entries("DOMAIN,example.com,DIRECT")
	right := entries("DOMAIN,example.com,DIRECT")
	left[0].Section, right[0].Section = "prepend", "append"
	if got := CompareEntries(left, right, false); len(got.Changes) != 2 {
		t.Fatalf("section movement was lost: %+v", got)
	}
	left[0].Section, right[0].Section = "delete", "delete"
	if !CompareEntries(left, right, false).Equal {
		t.Fatal("identical delete directives not compared")
	}
	right[0].Rule = ParseExisting("DOMAIN,EXAMPLE.COM,DIRECT", 0)
	if CompareEntries(left, right, false).Equal {
		t.Fatal("delete directive literal was incorrectly canonicalized")
	}
	right[0].Rule = ParseExisting("DOMAIN,other.example,DIRECT", 0)
	if got := CompareEntries(left, right, false); len(got.Changes) != 2 {
		t.Fatalf("delete directive changes lost: %+v", got)
	}
}

func TestSourceOpaqueProjectionRetainsKnownFullReportedFields(t *testing.T) {
	for _, tc := range []struct{ source, runtime, payload string }{
		{"DOMAIN-REGEX", "DomainRegex", "^a{1,2}$"},
		{"DOMAIN-REGEX", "DomainRegex", "^foo\\),bar$"},
		{"PROCESS-PATH-REGEX", "ProcessPathRegex", "^/foo\\(,bar$"},
		{"AND", "AND", "((DOMAIN,a.example),(NETWORK,tcp))"},
	} {
		source := entries(tc.source + "," + tc.payload + ",PROXY")
		runtime := []Entry{reportedOpaque(tc.runtime, tc.payload, "PROXY")}
		if source[0].Rule.Invalid != "" || source[0].Rule.Payload != tc.payload || source[0].Rule.Policy != "PROXY" || source[0].Rule.LiteralOnly {
			t.Fatalf("source opaque outer fields corrupted: %+v", source[0])
		}
		if got := CompareEntries(source, runtime, true); !got.Equal || len(got.Changes) != 0 {
			t.Fatalf("identical source/runtime opaque projection reported drift: %+v", got)
		}
	}
}

func TestMixedLiteralOnlySourceAndReportedRuntimeCompareFullExpression(t *testing.T) {
	source := entries("FUTURE-RULE,compound,with,commas,PROXY")
	if !source[0].Rule.LiteralOnly || source[0].Rule.Payload != "" || source[0].Rule.Policy != "" {
		t.Fatalf("unknown source fabricated field boundaries: %+v", source[0])
	}
	runtime := []Entry{reportedOpaque("FUTURE-RULE", "compound,with,commas", "PROXY")}
	for _, pair := range [][2][]Entry{{source, runtime}, {runtime, source}} {
		if got := CompareEntries(pair[0], pair[1], true); !got.Equal || len(got.Changes) != 0 {
			t.Fatalf("mixed serialized equality became changed policy: %+v", got)
		}
	}
	runtime[0] = reportedOpaque("FUTURE-RULE", "different,payload", "PROXY")
	if got := CompareEntries(source, runtime, true); got.Equal || len(got.Changes) != 2 || got.Changes[0].Kind != "removed" || got.Changes[1].Kind != "added" {
		t.Fatalf("unknown selector fields inferred for changed expression: %+v", got)
	}
	runtime[0] = reportedOpaque("FUTURE-RULE", "compound,with,commas", "PROXY")
	runtime[0].Rule.Disabled = true
	if got := CompareEntries(source, runtime, true); len(got.Changes) != 1 || !reflect.DeepEqual(got.Changes[0].Fields, []string{"enabled"}) {
		t.Fatalf("literal pairing lost observable enabled state: %+v", got)
	}
	duplicates := append(append([]Entry{}, source...), source...)
	runtime[0].Rule.Disabled = false
	if got := CompareEntries(duplicates, runtime, true); len(got.Changes) != 1 || got.Changes[0].Kind != "removed" {
		t.Fatalf("mixed literal duplicate occurrences collapsed: %+v", got)
	}
}
