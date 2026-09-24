package rulecheck

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLookupInputHasNoImplicitNetworkResolution(t *testing.T) {
	for _, tc := range []struct{ raw, kind, value string }{
		{"EXAMPLE.COM.", "domain", "example.com"}, {"192.0.2.7", "ip", "192.0.2.7"}, {"2001:0DB8::7", "ip", "2001:db8::7"},
	} {
		got, err := ParseLookup(tc.raw)
		if err != nil || got.Kind != tc.kind || got.Value != tc.value {
			t.Fatalf("%q: %+v %v", tc.raw, got, err)
		}
	}
	for _, raw := range []string{"", "https://example.com", "example.com:443", "192.0.2.0/24", "[2001:db8::7]:443", "fe80::1%en0", "::ffff:192.0.2.7"} {
		if _, err := ParseLookup(raw); err == nil {
			t.Fatalf("lookup accepted non-destination %q", raw)
		}
	}
}

func TestLookupKnownDomainOrderReturnsCandidateOnly(t *testing.T) {
	input, _ := ParseLookup("api.example.com")
	r := LookupEntries(entries("DOMAIN,other.example,DIRECT", "DOMAIN-SUFFIX,example.com,PROXY", "MATCH,DIRECT"), input)
	if r.Status != "candidate" || r.Winner == nil || r.Winner.Rule.Index != 1 || len(r.Steps) != 3 || r.Steps[0].Outcome != "miss" || r.Steps[1].Outcome != "match" || r.Steps[2].Outcome != "match" {
		t.Fatalf("ordered candidate incorrect: %+v", r)
	}
	raw, _ := json.Marshal(r)
	if !strings.Contains(string(raw), "first_candidate") || strings.Contains(string(raw), `"winner"`) {
		t.Fatal("output overstates static candidate as a route winner")
	}
}

func TestLookupRetainsLaterCoverageWithoutChangingFirstCandidate(t *testing.T) {
	input, _ := ParseLookup("api.example.com")
	r := LookupEntries(entries("DOMAIN,api.example.com,DIRECT", "RULE-SET,remote,PROXY", "DOMAIN-SUFFIX,example.com,PROXY", "MATCH,DIRECT"), input)
	if r.Status != "candidate" || r.Winner == nil || r.Winner.Rule.Index != 0 || len(r.Steps) != 4 {
		t.Fatalf("later coverage lost or later unknown invalidated first candidate: %+v", r)
	}
	for i, outcome := range []string{"match", "unknown", "match", "match"} {
		if r.Steps[i].Outcome != outcome || i > 0 && !strings.Contains(r.Steps[i].Reason, "follows the first confirmed candidate") {
			t.Fatalf("coverage step %d: %+v", i, r.Steps[i])
		}
	}
	uncertain := LookupEntries(entries("RULE-SET,remote,PROXY", "DOMAIN,api.example.com,DIRECT", "DOMAIN-SUFFIX,example.com,PROXY", "MATCH,DIRECT"), input)
	if uncertain.Status != "unknown" || uncertain.Winner != nil || len(uncertain.Steps) != 4 {
		t.Fatalf("later confirmed matches erased earlier uncertainty: %+v", uncertain)
	}
}

func TestLookupUnknownBeforeConfirmedMatchBlocksCandidate(t *testing.T) {
	for _, rule := range []string{"RULE-SET,remote,PROXY", "GEOSITE,cn,PROXY", "PROCESS-NAME,app,PROXY", "SRC-IP-CIDR,192.0.2.0/24,PROXY", "IP-CIDR,192.0.2.0/24,PROXY,no-resolve", "DOMAIN,_tcp.local,PROXY"} {
		input, _ := ParseLookup("example.com")
		r := LookupEntries(entries(rule, "DOMAIN,example.com,DIRECT"), input)
		if r.Status != "unknown" || r.Winner != nil || len(r.Steps) != 2 || r.Steps[0].Outcome != "unknown" || r.Steps[1].Outcome != "match" {
			t.Fatalf("unknown %q bypassed: %+v", rule, r)
		}
	}
	ip, _ := ParseLookup("192.0.2.7")
	r := LookupEntries(entries("DOMAIN-SUFFIX,example.com,PROXY", "IP-CIDR,192.0.2.0/24,DIRECT"), ip)
	if r.Status != "unknown" || r.Winner != nil {
		t.Fatalf("IP lookup invented missing hostname: %+v", r)
	}
}

func TestLookupIPContainmentAndUnknownSourceIP(t *testing.T) {
	input, _ := ParseLookup("2001:db8::7")
	r := LookupEntries(entries("IP-CIDR,192.0.2.0/24,PROXY", "IP-CIDR6,2001:db8::/64,DIRECT,no-resolve"), input)
	if r.Status != "candidate" || r.Winner == nil || r.Winner.Rule.Index != 1 || r.Steps[0].Outcome != "miss" {
		t.Fatalf("IP family or prefix match incorrect: %+v", r)
	}
}

func TestLookupDisabledDeleteAndPASSContinue(t *testing.T) {
	input, _ := ParseLookup("example.com")
	list := entries("RULE-SET,opaque,PROXY", "DOMAIN,example.com,PROXY", "DOMAIN,example.com,PASS", "MATCH,PASS-RULE", "MATCH,DIRECT")
	list[0].Rule.Disabled = true
	list[1].Section = "delete"
	r := LookupEntries(list, input)
	if r.Status != "candidate" || r.Winner == nil || r.Winner.Rule.Index != 4 || len(r.Steps) != 5 {
		t.Fatalf("nonterminal entries interrupted lookup: %+v", r)
	}
	want := []string{"skipped", "skipped", "continued", "continued", "match"}
	for i, step := range r.Steps {
		if step.Outcome != want[i] {
			t.Fatalf("step %d: %s, want %s", i, step.Outcome, want[i])
		}
	}
}

func TestLookupExhaustionDistinguishesMissAndUnknown(t *testing.T) {
	input, _ := ParseLookup("example.com")
	if r := LookupEntries(entries("DOMAIN,other.example,DIRECT"), input); r.Status != "unmatched" || r.Winner != nil {
		t.Fatalf("known miss incorrectly uncertain: %+v", r)
	}
	if r := LookupEntries(entries("RULE-SET,remote,DIRECT"), input); r.Status != "unknown" || r.Winner != nil {
		t.Fatalf("opaque exhaustion claimed miss: %+v", r)
	}
}
