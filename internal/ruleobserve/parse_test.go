package ruleobserve

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/core"
)

func TestParseMihomoEvidence(t *testing.T) {
	at := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, level, payload, kind, host, policy, rule, process, errKind string
		ip                                                               bool
		port                                                             int
	}{
		{"fallback", "warning", "[TCP] dial Final (match Match/) 127.0.0.1:42321(curl) --> API.Example.COM.:443 error: dial tcp 203.0.113.1:443: i/o timeout", KindDialError, "api.example.com", "Final", "Match", "curl", "timeout", false, 443},
		{"group spaces", "warning", "[UDP] dial My Final Group (match DomainSuffix/example.com) [::1]:4123(browser, uid=501) --> dns.example.com:53 error: connection refused", KindDialError, "dns.example.com", "My Final Group", "DomainSuffix", "browser", "refused", false, 53},
		{"IPv6", "error", "[TCP] dial DIRECT (match IPCIDR6/2001:db8::/32) 127.0.0.1:12 --> [2001:db8::1]:443 error: network is unreachable", KindDialError, "2001:db8::1", "DIRECT", "IPCIDR6", "", "unreachable", true, 443},
		{"unmatched", "warning", "[TCP] dial My Direct Group 127.0.0.1:1234(Test App) --> example.com:80 error: EOF", KindDialError, "example.com", "My Direct Group", "", "Test App", "eof", false, 80},
		{"inner", "warning", "[TCP] dial DIRECT mihomo --> example.com:80 error: DNS resolution failed", KindDialError, "example.com", "DIRECT", "", "", "dns", false, 80},
		{"success", "info", "[TCP] 127.0.0.1:12(curl) --> api.example.com:443 match Match using Final[DIRECT]", KindDialSuccess, "api.example.com", "Final", "Match", "curl", "", false, 443},
		{"success payload", "info", "[UDP] [::1]:12(uid=501) --> 203.0.113.8:53 match IPCIDR(203.0.113.0/24) using DIRECT", KindDialSuccess, "203.0.113.8", "DIRECT", "IPCIDR", "", "", true, 53},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, ok := Parse(core.Object{"type": tc.level, "payload": tc.payload}, at)
			if !ok || e.Kind != tc.kind || e.Host != tc.host || e.Policy != tc.policy || e.Rule != tc.rule || e.Process != tc.process || e.ErrorKind != tc.errKind || e.IsIP != tc.ip || e.Port != tc.port || e.At != at {
				t.Fatalf("unexpected evidence: %+v %t", e, ok)
			}
		})
	}
}

func TestUnrecognizedWarningsNeverGuessDestinations(t *testing.T) {
	for _, payload := range []string{
		"error asking https://example.com/private?token=SECRET",
		"[TCP] dial DIRECT (match Match/) invalid-source --> example.com:443 error: timeout",
		"[TCP] dial DIRECT (match Match/) 127.0.0.1:3 --> evil.example/path:443 error: timeout",
		"[TCP] dial DIRECT (match Match/) 127.0.0.1:3 --> example.com:70000 error: timeout",
		"[TCP] dial DIRECT (match Match/) 127.0.0.1:3 --> example.com:443",
		strings.Repeat("x", 65<<10),
	} {
		e, ok := Parse(core.Object{"type": "warning", "payload": payload}, time.Now())
		if !ok || e.Kind != KindOtherWarning || e.Host != "" || e.ErrorKind != "unparsed" {
			t.Fatalf("guessed evidence for %q: %+v", payload[:min(80, len(payload))], e)
		}
	}
	for _, level := range []string{"info", "debug", "silent", "invalid"} {
		if _, ok := Parse(core.Object{"type": level, "payload": "other event"}, time.Now()); ok {
			t.Fatalf("irrelevant %s retained", level)
		}
	}
}

func TestErrorPrivacyDoesNotDependOnRecognizingCredentialNames(t *testing.T) {
	secret := "opaque-entirely-unknown-value"
	payload := "[TCP] dial DIRECT (match Match/) 127.0.0.1:3 --> example.com:443 error: timeout https://user:pass@example.com/path?unknown=" + secret + " Authorization: Bearer abc password=def\x1b]52;c;PRIVATE\a"
	e, ok := Parse(core.Object{"type": "warning", "payload": payload}, time.Now())
	if !ok || e.ErrorKind != "timeout" {
		t.Fatalf("parse: %+v", e)
	}
	data, _ := json.Marshal(e)
	for _, bad := range []string{secret, "user:pass", "Bearer", "password=", "PRIVATE", "/path"} {
		if strings.Contains(string(data), bad) {
			t.Fatalf("sensitive free-form error persisted: %s", data)
		}
	}
}

func TestCandidateRequiresExplicitDestinationAndPolicy(t *testing.T) {
	for _, tc := range []struct {
		host   string
		suffix bool
		want   string
	}{
		{"API.Example.com.", false, "DOMAIN,api.example.com,Chosen"},
		{"api.example.com", true, "DOMAIN-SUFFIX,api.example.com,Chosen"},
		{"203.0.113.8", false, "IP-CIDR,203.0.113.8/32,Chosen,no-resolve"},
		{"2001:db8::1", false, "IP-CIDR6,2001:db8::1/128,Chosen,no-resolve"},
	} {
		got, err := Candidate(tc.host, "Chosen", tc.suffix)
		if err != nil || got != tc.want {
			t.Fatalf("%q: %q %v", tc.host, got, err)
		}
	}
	for _, tc := range []struct {
		host, policy string
		suffix       bool
	}{
		{"", "Chosen", false}, {"https://example.com", "Chosen", false}, {"example.com", "", false}, {"example.com", "PROXY,DIRECT", false}, {"example.com", "PROXY\nDIRECT", false}, {"203.0.113.1", "Chosen", true},
	} {
		if _, err := Candidate(tc.host, tc.policy, tc.suffix); err == nil {
			t.Fatalf("invalid candidate accepted: %+v", tc)
		}
	}
}
