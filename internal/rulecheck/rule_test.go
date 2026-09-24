package rulecheck

import (
	"strings"
	"testing"
)

func TestParseCanonicalCommonRules(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"DOMAIN,EXAMPLE.COM.,DIRECT", "DOMAIN,example.com,DIRECT"},
		{"- DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,DIRECT", "DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,DIRECT"},
		{"'DOMAIN-KEYWORD,GitHub,My Policy'", "DOMAIN-KEYWORD,github,My Policy"},
		{"- \"DOMAIN-SUFFIX,EXAMPLE.COM.,DIRECT\" # keep comments out of input", "DOMAIN-SUFFIX,example.com,DIRECT"},
		{"IP-CIDR,203.0.113.7/24,DIRECT", "IP-CIDR,203.0.113.0/24,DIRECT"},
		{"IP-CIDR,2001:0DB8::7/64,DIRECT,no-resolve", "IP-CIDR6,2001:db8::/64,DIRECT,no-resolve"},
		{"IP-CIDR6,203.0.113.7/24,DIRECT", "IP-CIDR,203.0.113.0/24,DIRECT"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			r, err := Parse(tc.input)
			if err != nil || r.String() != tc.want || r.Index != -1 {
				t.Fatalf("got %+v, %v; want %s", r, err, tc.want)
			}
			again, err := Parse(r.String())
			if err != nil || !again.Equal(r) {
				t.Fatalf("canonical rule did not round trip: %+v %v", again, err)
			}
		})
	}
}

func TestParseRejectsUnsupportedOrMalformedInput(t *testing.T) {
	for _, input := range []string{
		"", "rules: [DOMAIN,example.com,DIRECT]", "- DOMAIN,a.example,DIRECT\n- DOMAIN,b.example,DIRECT", "DOMAIN,a.example,DIRECT\n---\nDOMAIN,b.example,DIRECT",
		",example.com,DIRECT", "DOMAIN,example.com", "DOMAIN,example.com,", "DOMAIN,https://example.com,DIRECT", "DOMAIN,127.0.0.1,DIRECT", "DOMAIN,-bad.example,DIRECT", "DOMAIN,例子.example,DIRECT", "DOMAIN,_tcp.local,DIRECT", "DOMAIN-SUFFIX,_tcp.local,DIRECT",
		"DOMAIN-KEYWORD,,DIRECT", "DOMAIN-KEYWORD,hello,DIRECT,no-resolve", "DOMAIN-SUFFIX,example.com,DIRECT,src",
		"IP-CIDR,203.0.113.7,DIRECT", "IP-CIDR,::ffff:203.0.113.7/128,DIRECT", "IP-CIDR,203.0.113.7/32,DIRECT,src", "IP-CIDR,203.0.113.7/32,DIRECT,no-resolve,no-resolve",
		"IP-CIDR,203.0.113.7/32,DIRECT,no-resolve,", "DOMAIN,example.com,DIRECT,unknown", "MATCH,DIRECT", "RULE-SET,remote,DIRECT", "AND,((DOMAIN,a.example)),DIRECT",
		"\"DOMAIN,example.com,PR\\nOXY\"",
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := Parse(input); err == nil {
				t.Fatalf("accepted %q", input)
			}
		})
	}
}

func TestExistingOpaqueRulesAndSourceIPRemainDistinct(t *testing.T) {
	for _, raw := range []string{
		"RULE-SET,remote,DIRECT", "GEOSITE,cn,DIRECT", "AND,((DOMAIN,example.com),(NETWORK,tcp)),DIRECT", "FUTURE-RULE,expression,PROXY", "DOMAIN,example.com,DIRECT,new-option",
	} {
		r := ParseExisting(raw, 7)
		if !r.Opaque || r.Invalid != "" || r.Index != 7 || r.SelectorKey() != "" || r.String() != raw {
			t.Fatalf("opaque rule misrepresented: %+v", r)
		}
	}
	source := ParseExisting("IP-CIDR,203.0.113.8/24,DIRECT,src,no-resolve", 4)
	alias := ParseExisting("SRC-IP-CIDR,203.0.113.0/24,DIRECT", 5)
	dest := ParseExisting("IP-CIDR,203.0.113.0/24,DIRECT,no-resolve", 6)
	if source.Opaque || source.Invalid != "" || !source.SourceIP || !source.NoResolve || !source.Equal(alias) || source.Equal(dest) || source.SelectorKey() == dest.SelectorKey() {
		t.Fatalf("source-IP semantics lost: source=%+v alias=%+v dest=%+v", source, alias, dest)
	}
	if r := ParseExisting("DOMAIN,example.com", 9); r.Invalid == "" || r.Opaque {
		t.Fatalf("malformed common rule is not an error: %+v", r)
	}
}

func TestSelectorIdentityDiffersFromFullRuleIdentity(t *testing.T) {
	plain, _ := Parse("IP-CIDR,192.0.2.1/24,DIRECT")
	noResolve, _ := Parse("IP-CIDR6,192.0.2.0/24,DIRECT,no-resolve")
	if plain.SelectorKey() != noResolve.SelectorKey() || plain.Equal(noResolve) {
		t.Fatal("no-resolve must preserve a common selector but different full rule identity")
	}
	if plain.NoResolve || strings.Contains(plain.String(), "no-resolve") {
		t.Fatal("parser silently added no-resolve")
	}
}

func TestExistingDomainLiteralsPreserveCoreSemantics(t *testing.T) {
	for _, kind := range []string{"DOMAIN", "DOMAIN-SUFFIX"} {
		for _, literal := range []string{"_TCP.local", "Example.COM.", ".example.com", "例子.example", "127.0.0.1", "-bad.example"} {
			raw := kind + "," + literal + ",DIRECT"
			r := ParseExisting(raw, 3)
			if r.Invalid != "" || !r.Opaque || r.Payload != strings.ToLower(literal) || r.SelectorKey() != "" || r.String() != raw {
				t.Fatalf("existing core literal was rejected or rewritten: %+v", r)
			}
			if report := Analyze([]Rule{r}, map[string]bool{"DIRECT": true}); report.HasErrors() || report.Stats.Opaque != 1 {
				t.Fatalf("opaque literal blocks unrelated work: %+v", report)
			}
		}
		existing := ParseExisting(kind+",example.com.,DIRECT", 0)
		candidate, err := Parse(kind + ",example.com,DIRECT")
		if err != nil || existing.Equal(candidate) || candidate.Equal(existing) {
			t.Fatalf("trailing-dot source falsely equals new normalized rule: %+v %+v %v", existing, candidate, err)
		}
		if r := ParseExisting(kind+",,DIRECT", 2); r.Invalid == "" {
			t.Fatalf("empty existing payload escaped syntax validation: %+v", r)
		}
		plain := ParseExisting(kind+",EXAMPLE.COM,DIRECT", 1)
		if !plain.Equal(candidate) || plain.Opaque || plain.Invalid != "" {
			t.Fatalf("safe lowercase identity lost: %+v", plain)
		}
	}
}
