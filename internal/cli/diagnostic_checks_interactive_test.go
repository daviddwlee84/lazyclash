package cli

import (
	"reflect"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

func TestSavedCheckMenuRequiresExplicitRunAndKeepsReadOnlyPassive(t *testing.T) {
	for _, tc := range []struct {
		count    int
		readOnly bool
		want     []string
	}{
		{0, false, []string{"list", "add"}},
		{2, false, []string{"list", "run-all", "run", "add", "edit", "remove"}},
		{0, true, []string{"list"}},
		{2, true, []string{"list"}},
	} {
		choices := savedCheckMenuChoices(tc.count, tc.readOnly)
		var got []string
		for _, choice := range choices {
			got = append(got, choice.Value)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("count=%d read-only=%v: choices=%v", tc.count, tc.readOnly, got)
		}
	}
}

func TestSavedCheckStatusDraftParsing(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  []int
	}{
		{"", nil},
		{"  ", nil},
		{"200, 204,302", []int{200, 204, 302}},
		{"100,599", []int{100, 599}},
	} {
		got, err := parseSavedCheckStatuses(tc.input)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%q: %v %v", tc.input, got, err)
		}
		if formatted := savedCheckStatuses(got); formatted != "" {
			roundtrip, err := parseSavedCheckStatuses(formatted)
			if err != nil || !reflect.DeepEqual(roundtrip, got) {
				t.Fatalf("status form value lost: %s", formatted)
			}
		}
	}
	for _, input := range []string{"200,200", "99", "600", "2xx", "200,", "200 204", "200,ok"} {
		if _, err := parseSavedCheckStatuses(input); err == nil {
			t.Fatalf("accepted invalid expected statuses %q", input)
		}
	}
}

func TestEditingSavedCheckRetainsStableIDAndPrefillsDefinition(t *testing.T) {
	check := config.DiagnosticCheck{ID: "claude", Name: "Claude", URL: "https://claude.ai", Via: "PROXY", ExpectedStatuses: []int{200, 302}}
	for _, editing := range []bool{false, true} {
		fields := savedCheckFields(check, editing)
		got := map[string]string{}
		for _, field := range fields {
			got[field.Key] = field.Value
		}
		if _, hasID := got["id"]; hasID == editing {
			t.Fatal("editing exposed an ID rename or adding omitted the ID")
		}
		if got["url"] != check.URL || got["name"] != check.Name || got["via"] != check.Via || got["statuses"] != "200,302" {
			t.Fatalf("saved definition was not prefilled: %v", got)
		}
	}
}
