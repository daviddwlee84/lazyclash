package tui

import (
	"errors"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/config"
)

type field struct{ label, value string }
type formState struct {
	kind, title, original string
	fields                []field
	index                 int
	err                   string
	target                config.Target
}

// Quick save is for local settings forms. Other workflows retain their named
// preview/diagnose/confirm actions; Ctrl+S never applies a core mutation.
func (f *formState) canQuickSave() bool {
	if f == nil {
		return false
	}
	return f.kind == "target" || f.kind == "config" || f.kind == "work-source"
}

func (m *Model) quickSaveForm() tea.Cmd {
	f := m.form
	if m.overlay != "form" || !f.canQuickSave() {
		return nil
	}
	if f.index < len(f.fields) {
		f.fields[f.index].value = m.input.Value()
	}
	cmd := m.submitForm()
	if m.overlay != "form" {
		m.input.Blur()
		m.invalidateTargetTest()
	}
	return cmd
}

func (m *Model) startForm(kind, title, original string, fields []field) tea.Cmd {
	m.invalidateTargetTest()
	m.form = &formState{kind: kind, title: title, original: original, fields: fields}
	return m.beginInput("form", fields[0].value)
}
func (m *Model) startTargetForm(edit bool) tea.Cmd {
	if edit {
		return m.startTargetEdit(m.target)
	}
	return m.startTargetEdit(config.Target{})
}
func (m *Model) startTargetEdit(t config.Target) tea.Cmd {
	title := "Add target"
	if t.ID != "" {
		title = "Edit target"
	}
	cmd := m.startForm("target", title, t.ID, []field{{"ID", t.ID}, {"Display name (optional)", t.Name}, {"Controller URL (http://host:port or unix:///path)", t.Controller}, {"SSH host alias (optional)", t.SSHHost}, {"Secret environment variable (optional)", t.SecretEnv}, {"Secret file: absolute local path (optional)", t.SecretFile}, {"Custom CA: absolute local path (optional)", t.CAFile}, {"Source YAML: absolute core host path (optional)", t.SourceConfig}, {"Data proxy URL (explicit port, optional)", t.ProbeProxy}, {"Data proxy username (optional)", t.ProbeUsername}, {"Data proxy password env (optional)", t.ProbePasswordEnv}, {"Data proxy password file (absolute, optional)", t.ProbePasswordFile}, {"Data proxy CA file (absolute, optional)", t.ProbeCAFile}})
	m.form.target = t
	return cmd
}
func (m *Model) startConfigForm(edit bool) tea.Cmd {
	c := config.CoreConfig{}
	title := "Register complete YAML"
	if edit {
		title = "Edit registered YAML"
		r, ok := m.selectedRow()
		if !ok {
			return nil
		}
		for _, existing := range m.target.Configs {
			if existing.ID == r.id {
				c = existing
				break
			}
		}
	}
	return m.startForm("config", title, c.ID, []field{{"ID", c.ID}, {"Display name (optional)", c.Name}, {"Complete YAML: absolute path on core host", c.Path}})
}
func (m *Model) formKey(msg tea.KeyPressMsg) tea.Cmd {
	f := m.form
	if f == nil {
		m.overlay = ""
		return nil
	}
	switch msg.String() {
	case "ctrl+s":
		return m.quickSaveForm()
	case "ctrl+t":
		if f.kind == "target" {
			return m.testDraft()
		}
		return nil
	case "esc":
		m.retainQuickRuleDraft()
		m.invalidateTargetTest()
		m.overlay = ""
		m.form = nil
		m.input.Blur()
		return nil
	case "shift+tab":
		if f.index < len(f.fields) {
			f.fields[f.index].value = m.input.Value()
		}
		f.index = max(0, f.index-1)
		return m.beginInput("form", f.fields[f.index].value)
	case "tab", "enter":
		if f.index == len(f.fields) {
			return m.submitForm()
		}
		f.fields[f.index].value = m.input.Value()
		f.index++
		if f.index == len(f.fields) {
			m.input.Blur()
			return nil
		}
		return m.beginInput("form", f.fields[f.index].value)
	}
	if f.index == len(f.fields) {
		return nil
	}
	return m.inputUpdate(msg)
}
func (m *Model) submitForm() tea.Cmd {
	f := m.form
	value := func(i int) string { return strings.TrimSpace(f.fields[i].value) }
	switch f.kind {
	case "work-rule-quick":
		m.quickRuleDraft = value(0)
		if m.quickRuleDraft == "" {
			f.err = "Enter one routing rule, for example DOMAIN-SUFFIX,example.com,DIRECT"
			return nil
		}
		return m.startQuickRuleTargets(WorkRequest{Kind: "quick-rule-preview", Rule: m.quickRuleDraft})
	case "work-url":
		if value(2) != "true" && value(2) != "false" {
			f.err = "Observe only must be true or false"
			return nil
		}
		return m.launchWork(WorkRequest{Kind: "url", Source: m.target.ID, URL: value(0), Via: value(1), ObserveOnly: value(2) == "true"})
	case "work-rule":
		return m.launchWork(WorkRequest{Kind: "rule-preview", Source: m.target.ID, URL: value(0), Via: value(1)})
	case "work-receipt":
		req := WorkRequest{Source: m.target.ID, Receipt: value(0), Kind: "rule-" + value(1)}
		if value(1) == "restore" {
			return m.ask("Restore rule source", "Restore receipt "+value(0)+" on "+m.target.ID+"; current-file changes will be checked.", func() tea.Cmd { return m.launchWork(req) })
		}
		if value(1) != "verify" {
			f.err = "Action must be verify or restore"
			return nil
		}
		return m.launchWork(req)
	case "work-source":
		return m.submitRuleSourceForm(value)
	case "ssh":
		host := value(0)
		if host == "" {
			f.err = "SSH host alias is required"
			return nil
		}
		m.overlay = ""
		m.form = nil
		m.status = "Discovering controllers through SSH…"
		return m.discover(host)
	case "target":
		t := m.draftTarget()
		c := cloneSettings(m.settings)
		found := false
		for i, existing := range c.Targets {
			if existing.ID == f.original {
				c.Targets[i] = t
				found = true
				break
			}
		}
		if !found {
			c.Targets = append(c.Targets, t)
		}
		if c.DefaultTarget == f.original && f.original != "" {
			c.DefaultTarget = t.ID
		}
		if err := config.Validate(c); err != nil {
			f.err = safeError(err)
			return nil
		}
		return m.save(c, t.ID)
	case "config":
		cc := config.CoreConfig{ID: value(0), Name: value(1), Path: value(2)}
		c := cloneSettings(m.settings)
		for i := range c.Targets {
			if c.Targets[i].ID != m.target.ID {
				continue
			}
			found := false
			for j, existing := range c.Targets[i].Configs {
				if existing.ID == f.original {
					c.Targets[i].Configs[j] = cc
					found = true
					break
				}
			}
			if !found {
				c.Targets[i].Configs = append(c.Targets[i].Configs, cc)
			}
		}
		if err := config.Validate(c); err != nil {
			f.err = safeError(err)
			return nil
		}
		return m.save(c, m.target.ID)
	}
	return nil
}
func (m *Model) save(settings config.Config, selected string) tea.Cmd {
	if m.options.SaveTargets == nil {
		m.status = "Saving target settings is unavailable"
		return nil
	}
	if err := config.Validate(settings); err != nil {
		m.status = "Invalid settings: " + safeError(err)
		return nil
	}
	m.status = "Saving settings…"
	m.overlay = "saving"
	save := m.options.SaveTargets
	return func() tea.Msg {
		err := save(settings)
		if err != nil {
			return savedMsg{err: errors.New(safeError(err))}
		}
		return savedMsg{settings: settings, selected: selected}
	}
}

func (m *Model) draftTarget() config.Target {
	f := m.form
	t := f.target
	value := func(i int) string {
		if i >= len(f.fields) {
			return ""
		}
		return strings.TrimSpace(f.fields[i].value)
	}
	t.ID, t.Name, t.Controller, t.SSHHost = value(0), value(1), value(2), value(3)
	t.SecretEnv, t.SecretFile, t.CAFile, t.SourceConfig = value(4), value(5), value(6), value(7)
	t.ProbeProxy, t.ProbeUsername, t.ProbePasswordEnv, t.ProbePasswordFile, t.ProbeCAFile = value(8), value(9), value(10), value(11), value(12)
	if f.target.TransportOverride || t.Controller != f.target.Controller || t.SSHHost != f.target.SSHHost {
		t.RuleSource = nil
		t.ConfigSource = nil
		t.Service = nil
		t.ManagedCoreID = ""
	}
	t.Transient = false
	t.TransportOverride = false
	if t.SecretEnv != f.target.SecretEnv || t.SecretFile != f.target.SecretFile || t.SourceConfig != f.target.SourceConfig {
		t.Secret = ""
	}
	return t
}
