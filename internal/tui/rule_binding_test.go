package tui

import (
	"github.com/daviddwlee84/lazyclash/internal/config"
	"testing"
)

func TestTargetDraftClearsRuleSourceOnTransportChange(t *testing.T) {
	for _, tc := range []struct {
		name            string
		field           int
		value           string
		temporary, keep bool
	}{
		{"controller", 2, "http://other.invalid:9090", false, false},
		{"ssh", 3, "other-host", false, false},
		{"temporary save", 1, "Renamed", true, false},
		{"credentials", 4, "NEW_SECRET", false, true},
		{"name", 1, "Renamed", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testModel(t)
			target := config.Target{ID: "test", Controller: "http://127.0.0.1:9090", TransportOverride: tc.temporary, RuleSource: &config.RuleSource{Kind: "verge", Version: "2.5.2", DataDir: "/verge", ProfileUID: "selected"}}
			m.startTargetEdit(target)
			m.form.fields[tc.field].value = tc.value
			draft := m.draftTarget()
			if draft.TransportOverride || (draft.RuleSource != nil) != tc.keep {
				t.Fatalf("unsafe saved draft: %+v", draft)
			}
			if target.RuleSource == nil {
				t.Fatal("editing draft mutated original target")
			}
		})
	}
}
