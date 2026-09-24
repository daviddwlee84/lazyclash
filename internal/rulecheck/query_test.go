package rulecheck

import (
	"reflect"
	"strings"
	"testing"
)

func TestQueryParserPreservesExistingLiteralScope(t *testing.T) {
	for _, raw := range []string{
		"DOMAIN,Example.COM.,DIRECT", "DOMAIN,_tcp.local,DIRECT", "DOMAIN-SUFFIX,.example.com,DIRECT", "RULE-SET,private,PROXY", "MATCH,DIRECT", "IP-CIDR,192.0.2.0/24,DIRECT,src,no-resolve", "AND,((DOMAIN,example.com),(NETWORK,tcp)),DIRECT", "DOMAIN-REGEX,^foo\\(,DIRECT", "DOMAIN-REGEX,^foo\\),DIRECT",
	} {
		query, err := ParseQuery(raw)
		if err != nil {
			t.Fatalf("existing query %q rejected: %v", raw, err)
		}
		if raw == "DOMAIN,Example.COM.,DIRECT" && (!query.Opaque || query.Payload != "example.com.") {
			t.Fatalf("query changed trailing-dot meaning: %+v", query)
		}
	}
	for _, raw := range []string{"DOMAIN", "DOMAIN,example.com", "DOMAIN,,DIRECT", "RULE-SET,private", "RULE-SET,,DIRECT", "AND,((DOMAIN,example.com),DIRECT", "- DOMAIN,a.example,DIRECT\n- DOMAIN,b.example,DIRECT", "rules: [a]"} {
		if _, err := ParseQuery(raw); err == nil {
			t.Fatalf("malformed query %q accepted", raw)
		}
	}
}

func TestFindSourceAlternativesAndAllOccurrences(t *testing.T) {
	query, _ := ParseQuery("IP-CIDR,192.0.2.0/24,DIRECT,no-resolve")
	list := entries("IP-CIDR,192.0.2.0/24,DIRECT", "IP-CIDR,192.0.2.0/24,PROXY,no-resolve", "IP-CIDR,192.0.2.0/24,DIRECT,no-resolve", "IP-CIDR,192.0.2.0/24,DIRECT,no-resolve")
	list[3].Section = "delete"
	r := FindEntries(list, query, false)
	if !r.Found || len(r.Matches) != 3 || r.Matches[0].Kind != "same_selector" || !reflect.DeepEqual(r.Matches[0].Differences, []string{"options"}) || !reflect.DeepEqual(r.Matches[1].Differences, []string{"policy"}) || r.Matches[2].Kind != "exact" {
		t.Fatalf("source matches or alternatives lost: %+v", r)
	}
	if FindEntries(list[:2], query, false).Found {
		t.Fatal("policy/option alternatives counted as requested rule presence")
	}
}

func TestFindRuntimePresenceIsReportedAndIncludesDisabled(t *testing.T) {
	query, _ := ParseQuery("IP-CIDR,192.0.2.0/24,DIRECT,no-resolve")
	list := entries("IP-CIDR,192.0.2.0/24,DIRECT")
	list[0].Rule.Disabled = true
	r := FindEntries(list, query, true)
	if !r.Found || len(r.Matches) != 1 || r.Matches[0].Kind != "reported" || !r.Matches[0].Entry.Rule.Disabled {
		t.Fatalf("disabled presence or reported scope lost: %+v", r)
	}
	if len(r.Limitations) < 2 {
		t.Fatal("runtime options limitation absent")
	}
}

func TestFindOpaqueDoesNotCollideOnEmptySelectorKeys(t *testing.T) {
	query, _ := ParseQuery("RULE-SET,wanted,DIRECT")
	list := entries("GEOSITE,cn,DIRECT", "RULE-SET,other,DIRECT")
	if got := FindEntries(list, query, false); got.Found || len(got.Matches) != 0 {
		t.Fatalf("opaque empty keys collided: %+v", got)
	}
	list = append(list, entries("RULE-SET,wanted,DIRECT")[0])
	if got := FindEntries(list, query, false); !got.Found || len(got.Matches) != 1 || got.Matches[0].Kind != "literal" {
		t.Fatalf("exact opaque literal not found: %+v", got)
	}
	dotted, _ := ParseQuery("DOMAIN,example.com.,DIRECT")
	if FindEntries(entries("DOMAIN,example.com,DIRECT"), dotted, false).Found {
		t.Fatal("query normalized away trailing-dot literal")
	}
}

func TestKnownRuntimeKindNamesMatchReportedFieldsOnly(t *testing.T) {
	for _, tc := range []struct{ source, runtime string }{
		{"PROCESS-NAME", "ProcessName"}, {"DOMAIN-REGEX", "DomainRegex"}, {"DOMAIN-WILDCARD", "DomainWildcard"}, {"PROCESS-PATH-REGEX", "ProcessPathRegex"}, {"SRC-PORT", "SrcPort"}, {"SUB-RULE", "SubRules"},
	} {
		query, err := ParseQuery(tc.source + ",literal,PROXY")
		if err != nil {
			t.Fatal(err)
		}
		list := entries(tc.runtime + ",literal,PROXY")
		got := FindEntries(list, query, true)
		if !got.Found || len(got.Matches) != 1 || got.Matches[0].Kind != "reported" {
			t.Fatalf("known runtime type %q missed: %+v", tc.runtime, got)
		}
		if FindEntries(list, query, false).Found {
			t.Fatalf("reported type alias %q leaked into source literal matching", tc.runtime)
		}
		if !CompareEntries(entries(tc.source+",literal,PROXY"), list, true).Equal {
			t.Fatalf("reported type alias %q differs", tc.runtime)
		}
	}
	unknown, _ := ParseQuery("FUTURE-RULE,literal,PROXY")
	if FindEntries(entries("FutureRule,literal,PROXY"), unknown, true).Found || CompareEntries(entries("FUTURE-RULE,literal,PROXY"), entries("FutureRule,literal,PROXY"), true).Equal {
		t.Fatal("invented an alias for unknown future rule types")
	}
}

func reportedOpaque(kind, payload, policy string) Entry {
	return Entry{Section: "rules", Rule: Rule{Index: 0, Type: strings.ToUpper(kind), Payload: payload, Policy: policy, Raw: strings.ToUpper(kind) + "," + payload + "," + policy, Opaque: true}}
}

func TestQueryPreservesKnownCommaPayloadBeforeFinalPolicy(t *testing.T) {
	for _, tc := range []struct{ source, runtime, payload string }{
		{"DOMAIN-REGEX", "DomainRegex", "^foo,(bar|baz)$"},
		{"DOMAIN-REGEX", "DomainRegex", "^a{1,2}$"},
		{"PROCESS-NAME-REGEX", "ProcessNameRegex", "^foo\\),bar$"},
		{"PROCESS-PATH-REGEX", "ProcessPathRegex", "^/foo\\(,bar$"},
		{"AND", "AND", "((DOMAIN,a.example),(NETWORK,tcp))"},
		{"SUB-RULE", "SubRules", "(DOMAIN,a.example)"},
	} {
		query, err := ParseQuery(tc.source + "," + tc.payload + ",PROXY")
		if err != nil || query.Payload != tc.payload || query.Policy != "PROXY" || len(query.Options) != 0 || query.LiteralOnly {
			t.Fatalf("query lost comma-bearing outer fields: %+v %v", query, err)
		}
		correct := reportedOpaque(tc.runtime, tc.payload, "PROXY")
		if got := FindEntries([]Entry{correct}, query, true); !got.Found || len(got.Matches) != 1 || got.Matches[0].Kind != "reported" {
			t.Fatalf("full reported payload did not match: %+v", got)
		}
		parts := strings.Split(tc.payload, ",")
		if len(parts) > 1 {
			truncated := reportedOpaque(tc.runtime, parts[0], parts[1])
			if got := FindEntries([]Entry{truncated}, query, true); got.Found || len(got.Matches) != 0 {
				t.Fatalf("truncated payload/policy collided: %+v", got)
			}
		}
	}
	// Regex kinds have no parameters in Mihomo's outer grammar: the last
	// field is always the policy, even when it resembles an IP modifier.
	query, err := ParseQuery("DOMAIN-REGEX,^foo,bar$,PROXY,no-resolve")
	if err != nil || query.Payload != "^foo,bar$,PROXY" || query.Policy != "no-resolve" || len(query.Options) != 0 {
		t.Fatalf("regex invented a no-resolve parameter: %+v %v", query, err)
	}
}

func TestUnknownQueryGrammarUsesFullLiteralWithoutSelectorInference(t *testing.T) {
	query, err := ParseQuery("FUTURE-RULE,compound,with,commas,PROXY")
	if err != nil || !query.LiteralOnly || query.Payload != "" || query.Policy != "" || selectorKey(query, true) != "" {
		t.Fatalf("unknown grammar manufactured fields: %+v %v", query, err)
	}
	correct := reportedOpaque("FUTURE-RULE", "compound,with,commas", "PROXY")
	got := FindEntries([]Entry{correct}, query, true)
	if !got.Found || len(got.Matches) != 1 || got.Matches[0].Kind != "reported_literal" {
		t.Fatalf("full unknown expression was not found: %+v", got)
	}
	wrong := reportedOpaque("FUTURE-RULE", "compound", "with")
	if got := FindEntries([]Entry{wrong}, query, true); got.Found || len(got.Matches) != 0 {
		t.Fatalf("unknown truncated fields collided: %+v", got)
	}
	otherPolicy := reportedOpaque("FUTURE-RULE", "compound,with,commas", "DIRECT")
	if got := FindEntries([]Entry{otherPolicy}, query, true); got.Found || len(got.Matches) != 0 {
		t.Fatalf("unknown syntax inferred selector alternatives: %+v", got)
	}
}

func TestReportedLiteralFallbackNormalizesOnlyKnownKindPrefix(t *testing.T) {
	query := Rule{Index: -1, Type: "DOMAIN-REGEX", Raw: "DOMAIN-REGEX,^foo,bar\\)$,PROXY", Opaque: true, LiteralOnly: true}
	entry := reportedOpaque("DomainRegex", "^foo,bar\\)$", "PROXY")
	if got := FindEntries([]Entry{entry}, query, true); !got.Found || got.Matches[0].Kind != "reported_literal" {
		t.Fatalf("known prefix alias lost full literal match: %+v", got)
	}
	entry.Rule.Payload, entry.Rule.Raw = "^foo", "DOMAINREGEX,^foo,PROXY"
	if got := FindEntries([]Entry{entry}, query, true); got.Found {
		t.Fatalf("literal fallback truncated remainder: %+v", got)
	}
	unknown, _ := ParseQuery("FUTURE-RULE,a,b,PROXY")
	if FindEntries([]Entry{reportedOpaque("FutureRule", "a,b", "PROXY")}, unknown, true).Found {
		t.Fatal("literal fallback invented an unknown type alias")
	}
}

func TestRawQueryKeepsYAMLMarkerTextLiteral(t *testing.T) {
	for _, payload := range []string{"^prefix: value$", "^prefix # literal$", "^prefix: value # literal,a{1,2}$"} {
		raw := "DOMAIN-REGEX," + payload + ",PROXY"
		query, err := ParseQuery(raw)
		if err != nil || query.Payload != payload || query.Policy != "PROXY" || query.Raw != raw {
			t.Fatalf("raw rule was decoded as YAML: %+v %v", query, err)
		}
		if result := FindEntries(entries(raw), query, false); !result.Found || len(result.Matches) != 1 || result.Matches[0].Kind != "literal" {
			t.Fatalf("raw source and query lost literal equality: %+v", result)
		}
		for _, yamlForm := range []string{"'" + raw + "'", "- '" + raw + "'"} {
			quoted, err := ParseQuery(yamlForm)
			if err != nil || quoted.Raw != raw || quoted.Payload != payload {
				t.Fatalf("explicit quoted YAML no longer supported: %+v %v", quoted, err)
			}
		}
	}
	for _, raw := range []string{"DOMAIN-REGEX,^prefix\nvalue,PROXY", "DOMAIN-REGEX,^prefix\tvalue,PROXY", "DOMAIN-REGEX,^prefix,value,PROXY\r"} {
		if _, err := ParseQuery(raw); err == nil {
			t.Fatalf("raw multiline/control query accepted: %q", raw)
		}
	}
}
