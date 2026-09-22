package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/daviddwlee84/lazyclash/internal/config"
)

func TestSavedConnectivityChecksVisibleButtonAndManualHandoff(t *testing.T) {
	for _, width := range []int{20, 36, 80, 120} {
		m := toolModel(t)
		m.page = overview
		m.Update(tea.WindowSizeMsg{Width: width, Height: 32})
		view := ansi.Strip(m.View().Content)
		want := "Saved connectivity checks"
		if width == 20 {
			want = "Saved checks"
		}
		if !strings.Contains(view, want) {
			t.Fatalf("%d columns hides saved checks entrypoint:\n%s", width, view)
		}
		if m.toolPending {
			t.Fatal("rendering started a check")
		}
		hit := findHit(t, m, "action", "tool-checks")
		line := strings.Split(view, "\n")[hit.y]
		if !strings.Contains(strings.ToLower(ansi.Cut(line, hit.x, hit.x+hit.w)), "checks") {
			t.Fatalf("checks hit region misses the visible button: %+v %q", hit, line)
		}
		if cmd := click(m, hit); cmd == nil || !m.toolPending || m.overlay != "external-tool" || m.status != "Saved connectivity checks" {
			t.Fatal("click did not hand the terminal to the shared checks workflow")
		}
	}
}

func TestSavedConnectivityChecksShortcutAndEligibility(t *testing.T) {
	for _, state := range []string{"normal", "read-only", "transient", "transport-override", "no-target", "pending", "no-command"} {
		t.Run(state, func(t *testing.T) {
			m := toolModel(t)
			m.page = overview
			switch state {
			case "read-only":
				m.options.ReadOnly = true
			case "transient":
				m.target.Transient = true
			case "transport-override":
				m.target.TransportOverride = true
			case "no-target":
				m.target.ID = ""
			case "pending":
				m.pending = "a core write"
			case "no-command":
				m.options.RunCommand = nil
			}
			cmd := sendKey(m, "C")
			want := state == "normal" || state == "read-only"
			if (cmd != nil) != want || m.toolPending != want {
				t.Fatalf("unexpected checks handoff for %s", state)
			}
		})
	}
}

func TestSavedChecksSettingsCloneDoesNotShareStatusSlices(t *testing.T) {
	original := config.Config{Targets: []config.Target{{ID: "a", Checks: []config.DiagnosticCheck{{ID: "website", URL: "https://example.com", ExpectedStatuses: []int{200}}}}}}
	copy := cloneSettings(original)
	copy.Targets[0].Checks[0].URL = "https://other.example"
	copy.Targets[0].Checks[0].ExpectedStatuses[0] = 204
	if original.Targets[0].Checks[0].URL != "https://example.com" || original.Targets[0].Checks[0].ExpectedStatuses[0] != 200 {
		t.Fatal("dashboard draft mutated the caller's saved check definition")
	}
}
