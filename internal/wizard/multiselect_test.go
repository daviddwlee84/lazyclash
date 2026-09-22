package wizard

import (
	"reflect"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

func TestMultiSelectionSearchAndBackRetainExactNames(t *testing.T) {
	m := newMultiPicker(MultiSpec{Choices: []Choice{{"A, 東京", "A, 東京"}, {"qjkh/", "qjkh/"}}, Back: true})
	m.Update(tea.KeyPressMsg{Code: ' '})
	m.Update(tea.KeyPressMsg{Code: '/'})
	m.Update(tea.PasteMsg{Content: "qjkh/"})
	if m.query.Value() != "qjkh/" || m.submitted {
		t.Fatal("paste escaped input ownership")
	}
	m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m.Update(tea.KeyPressMsg{Code: ' '})
	if !reflect.DeepEqual(m.values(), []string{"A, 東京", "qjkh/"}) {
		t.Fatal(m.values())
	}
	m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if !m.back || m.submitted {
		t.Fatal("Back submitted or discarded selection")
	}
}

func TestMultiEmptySearchAndCancelDoNotSubmit(t *testing.T) {
	m := newMultiPicker(MultiSpec{Choices: []Choice{{"a", "Alpha"}}, Selected: []string{"a"}, Back: true})
	m.Update(tea.KeyPressMsg{Code: '/'})
	m.Update(tea.PasteMsg{Content: "no match"})
	m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.submitted || m.err == "" {
		t.Fatal("hidden selection submitted")
	}
	m.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if m.back || m.submitted {
		t.Fatal("Ctrl+C treated as Back or submit")
	}
	for _, size := range []tea.WindowSizeMsg{{Width: 1, Height: 1}, {Width: 35, Height: 10}, {Width: 80, Height: 24}} {
		m.Update(size)
		lines := strings.Split(m.View().Content, "\n")
		if len(lines) > size.Height {
			t.Fatal("height overflow")
		}
		for _, line := range lines {
			if ansi.StringWidth(line) > size.Width {
				t.Fatal("width overflow")
			}
		}
	}
}

func TestBackFormRetainsDraftAndReviewInterruptIsDistinct(t *testing.T) {
	m := newForm(Spec{Back: true, Fields: []Field{{Key: "input", Kind: Multiline}}})
	m.Init()
	m.Update(tea.PasteMsg{Content: "keep\nthis"})
	m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if !m.back || m.values()["input"] != "keep\nthis" {
		t.Fatal("Back lost draft")
	}
	r := &review{}
	r.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if !r.interrupted || r.accepted {
		t.Fatal("review interrupt misclassified")
	}
	m = newForm(Spec{Back: true, Fields: []Field{{Key: "draft", Value: "saved"}}})
	m.Init()
	_, hits := m.layout()
	for _, hit := range hits {
		if hit.index == -3 {
			m.Update(tea.MouseClickMsg{Button: tea.MouseLeft, X: hit.x, Y: hit.y})
			m.Update(tea.MouseReleaseMsg{Button: tea.MouseLeft, X: hit.x, Y: hit.y})
		}
	}
	if !m.back || m.values()["draft"] != "saved" {
		t.Fatal("mouse Back lost draft")
	}
}
