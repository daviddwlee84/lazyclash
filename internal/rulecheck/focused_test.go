package rulecheck

import (
	"fmt"
	"strings"
	"testing"
)

func TestFocusedFindsLateOverlapWithoutGlobalPairBudget(t *testing.T) {
	request, err := Parse("DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,DIRECT")
	if err != nil {
		t.Fatal(err)
	}
	rules := make([]Rule, 0, 1200)
	for i := 0; i < 1000; i++ {
		rules = append(rules, ParseExisting(fmt.Sprintf("DOMAIN,unrelated%d.example,PROXY", i), i))
	}
	rules = append(rules, ParseExisting("DOMAIN-SUFFIX,githubcopilot.com,PROXY", 1000))
	rules = append(rules, ParseExisting("DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,PROXY", 1001))
	report := AnalyzeFocused(rules, request, -1, nil)
	if overlap := finding(report, "overlap", 1000); overlap == nil || overlap.RelatedIndex == nil || *overlap.RelatedIndex != -1 {
		t.Fatal("late focused overlap missing", report)
	}
	if conflict := finding(report, "selector_conflict", 1001); conflict == nil || conflict.Severity != "error" {
		t.Fatal("late focused conflict missing", report)
	}
	if strings.Contains(strings.Join(report.Limitations, " "), "size limit") {
		t.Fatal("linear pair scan inherited the full-list comparison limit", report)
	}
}

func TestFocusedRetainedDuplicateKeepsPositionAndStillConflicts(t *testing.T) {
	rules := parsed(
		"DOMAIN-SUFFIX,example.com,PROXY",
		"DOMAIN,api.example.com,DIRECT",
		"DOMAIN,api.example.com,PROXY",
	)
	request, _ := Parse("DOMAIN,api.example.com,DIRECT")
	report := AnalyzeFocused(rules, request, 1, nil)
	if shadow := finding(report, "shadowed", 1); shadow == nil || shadow.RelatedIndex == nil || *shadow.RelatedIndex != 0 {
		t.Fatal("retained occurrence was treated as prepended", report)
	}
	if conflict := finding(report, "selector_conflict", 2); conflict == nil || conflict.Severity != "error" || conflict.RelatedIndex == nil || *conflict.RelatedIndex != 1 {
		t.Fatal("identical occurrence hid a contradictory selector", report)
	} else if !strings.Contains(conflict.Message, `requested policy "DIRECT" differs from existing policy "PROXY"`) {
		t.Fatal("conflict message lost requested/existing policy direction", conflict)
	}
	if !AnalyzeFocused(rules, request, 0, nil).HasErrors() {
		t.Fatal("incorrect retained occurrence accepted")
	}
}

func TestFocusedWarningLimitDoesNotHideExactConflict(t *testing.T) {
	request, _ := Parse("DOMAIN-SUFFIX,example.com,DIRECT")
	rules := make([]Rule, 0, 1200)
	for i := 0; i < 1100; i++ {
		rules = append(rules, ParseExisting(fmt.Sprintf("DOMAIN,h%d.example.com,PROXY", i), i))
	}
	rules = append(rules, ParseExisting("DOMAIN-SUFFIX,example.com,PROXY", 1100))
	report := AnalyzeFocused(rules, request, -1, nil)
	if len(report.Findings) != 1001 || finding(report, "selector_conflict", 1100) == nil || !report.HasErrors() {
		t.Fatal("bounded warning output hid exact conflict", report)
	}
	if !strings.Contains(strings.Join(report.Limitations, " "), "warning output reached") {
		t.Fatal("warning truncation not disclosed")
	}
}

func TestFocusedIgnoresUnrelatedAndDisabledFindings(t *testing.T) {
	rules := parsed("DOMAIN,unrelated.example,DIRECT", "DOMAIN,unrelated.example,PROXY", "DOMAIN,request.example,PROXY", "RULE-SET,opaque,PROXY")
	rules[2].Disabled = true
	request, _ := Parse("DOMAIN,request.example,DIRECT")
	report := AnalyzeFocused(rules, request, -1, nil)
	if len(report.Findings) != 0 || !strings.Contains(strings.Join(report.Limitations, " "), "opaque rules are unknown") {
		t.Fatal("unrelated/disabled conflict blocked the request or opaque coverage was hidden", report)
	}
	report = AnalyzeFocused(rules, request, -1, map[string]bool{"PROXY": true})
	if !report.HasErrors() || finding(report, "policy_missing", -1) == nil {
		t.Fatal("requested policy not validated", report)
	}
}

func TestFocusedPreservesModifiersPASSAndFallbackRelations(t *testing.T) {
	for _, test := range []struct {
		request string
		rules   []Rule
		at      int
		code    string
	}{
		{"IP-CIDR,192.0.2.0/24,DIRECT,no-resolve", parsed("IP-CIDR,192.0.2.0/24,DIRECT"), -1, "overlap"},
		{"DOMAIN,api.example.com,DIRECT", parsed("DOMAIN-SUFFIX,example.com,PASS", "DOMAIN,api.example.com,DIRECT"), 1, "overlap"},
		{"DOMAIN,api.example.com,DIRECT", parsed("MATCH,PROXY", "DOMAIN,api.example.com,DIRECT"), 1, "unreachable"},
		{"DOMAIN,api.example.com,DIRECT", parsed("MATCH,PASS", "DOMAIN,api.example.com,DIRECT"), 1, ""},
	} {
		request, err := Parse(test.request)
		if err != nil {
			t.Fatal(err)
		}
		report := AnalyzeFocused(test.rules, request, test.at, nil)
		if report.HasErrors() || test.code == "" && len(report.Findings) != 0 || test.code != "" && (len(report.Findings) != 1 || report.Findings[0].Code != test.code) {
			t.Fatal(test.request, test.code, report)
		}
	}
}
