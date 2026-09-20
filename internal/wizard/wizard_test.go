package wizard

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

func press(m *form, code rune) { m.Update(tea.KeyPressMsg{Code: code}) }
func TestDraftTypingPasteAndSecretRedaction(t *testing.T) {
	spec := Spec{Title: "fixture", Fields: []Field{{Key: "text", Label: "Name"}, {Key: "secret", Label: "Password", Value: "secret-value", Kind: Secret}, {Key: "multi", Label: "Nodes", Kind: Multiline}}}
	m := newForm(spec)
	m.Init()
	m.Update(tea.PasteMsg{Content: "qjkh/中文"})
	if m.values()["text"] != "qjkh/中文" {
		t.Fatal(m.values())
	}
	m.focus(1)
	if strings.Contains(m.View().Content, "secret-value") {
		t.Fatal("secret displayed")
	}
	m.focus(2)
	m.Update(tea.PasteMsg{Content: "line one\nline two"})
	if m.values()["multi"] != "line one\nline two" {
		t.Fatal(m.values())
	}
	if spec.Fields[0].Value != "" {
		t.Fatal("draft changed caller before submit")
	}
}
func TestQuickReviewValidatesWithoutTraversingFields(t *testing.T) {
	m := newForm(Spec{Fields: []Field{{Key: "required", Label: "Required", Required: true}, {Key: "prefill", Value: "done"}}})
	m.Init()
	m.submit()
	if m.submitted || m.index != 0 || m.err == "" {
		t.Fatal("missing required accepted")
	}
	m.Update(tea.PasteMsg{Content: "ready"})
	m.submit()
	if !m.submitted || m.values()["prefill"] != "done" {
		t.Fatal("quick review lost field")
	}
}
func TestSelectionSearchSurvivesResizeAndMouseCancelDoesNotSubmit(t *testing.T) {
	m := newForm(Spec{SubmitLabel: "Review", Fields: []Field{{Key: "target", Kind: Select, Options: []Choice{{"a", "Alpha"}, {"b", "Beta"}}}}})
	m.Init()
	press(m, '/')
	m.Update(tea.PasteMsg{Content: "Beta"})
	m.Update(tea.WindowSizeMsg{Width: 60, Height: 20})
	if !m.searching || m.search.Value() != "Beta" || m.values()["target"] != "b" {
		t.Fatal("resize discarded search")
	}
	_, hits := m.layout()
	var cancel hit
	for _, h := range hits {
		if h.index == -3 {
			cancel = h
		}
	}
	m.Update(tea.MouseClickMsg{Button: tea.MouseLeft, X: cancel.x, Y: cancel.y})
	_, cmd := m.Update(tea.MouseReleaseMsg{Button: tea.MouseLeft, X: cancel.x, Y: cancel.y})
	if cmd == nil || m.submitted {
		t.Fatal("cancel submitted")
	}
}
func TestResizeBetweenMousePressAndReleaseInvalidates(t *testing.T) {
	m := newForm(Spec{Fields: []Field{{Key: "x", Value: "ready"}}})
	m.Init()
	_, hits := m.layout()
	var submit hit
	for _, h := range hits {
		if h.index == -1 {
			submit = h
		}
	}
	m.Update(tea.MouseClickMsg{Button: tea.MouseLeft, X: submit.x, Y: submit.y})
	m.Update(tea.WindowSizeMsg{Width: 30, Height: 10})
	m.Update(tea.MouseReleaseMsg{Button: tea.MouseLeft, X: submit.x, Y: submit.y})
	if m.submitted {
		t.Fatal("stale mouse activated submit")
	}
	for _, size := range []tea.WindowSizeMsg{{Width: 1, Height: 1}, {Width: 30, Height: 10}, {Width: 80, Height: 24}} {
		m.Update(size)
		for _, line := range strings.Split(m.View().Content, "\n") {
			if ansi.StringWidth(line) > size.Width {
				t.Fatalf("overflow %q", line)
			}
		}
	}
}

func TestNoMatchingSearchCannotSubmitHiddenSelection(t *testing.T) {
	m := newForm(Spec{Fields: []Field{{Key: "choice", Kind: Select, Options: []Choice{{"a", "Alpha"}, {"b", "Beta"}}}}})
	m.Init()
	press(m, '/')
	m.Update(tea.PasteMsg{Content: "no matching choice"})
	m.submit()
	if m.submitted {
		t.Fatal("hidden stale selection submitted")
	}
	m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.submitted || !m.searching {
		t.Fatal("empty search accepted")
	}
	m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if m.searching || len(m.choices()) != 2 {
		t.Fatal("cancel search did not restore choices")
	}
}

func TestReviewMouseCannotApplyClippedOrStaleButton(t *testing.T) {
	for _, size := range []tea.WindowSizeMsg{{Width: 80, Height: 2}, {Width: 10, Height: 24}, {Width: 20, Height: 24}} {
		m := &review{}
		m.Init()
		m.Update(size)
		m.Update(tea.MouseClickMsg{Button: tea.MouseLeft, X: 15, Y: size.Height - 2})
		m.Update(tea.MouseReleaseMsg{Button: tea.MouseLeft, X: 15, Y: size.Height - 2})
		if m.accepted {
			t.Fatalf("clipped Apply activated at %+v", size)
		}
	}
	m := &review{width: 80, height: 24}
	m.Init()
	m.Update(tea.MouseClickMsg{Button: tea.MouseLeft, X: 15, Y: 22})
	m.Update(tea.WindowSizeMsg{Width: 81, Height: 24})
	m.Update(tea.MouseReleaseMsg{Button: tea.MouseLeft, X: 15, Y: 22})
	if m.accepted {
		t.Fatal("stale review mouse accepted")
	}
}
