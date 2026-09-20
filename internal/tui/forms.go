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

func (m *Model) startForm(kind, title, original string, fields []field) tea.Cmd {
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
	cmd := m.startForm("target", title, t.ID, []field{{"ID", t.ID}, {"Display name (optional)", t.Name}, {"Controller URL (http://host:port or unix:///path)", t.Controller}, {"SSH host alias (optional)", t.SSHHost}, {"Secret environment variable (optional)", t.SecretEnv}, {"Secret file: absolute local path (optional)", t.SecretFile}, {"Custom CA: absolute local path (optional)", t.CAFile}, {"Source YAML: absolute core host path (optional)", t.SourceConfig}})
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
	case "esc":
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
		t := f.target
		t.ID = value(0)
		t.Name = value(1)
		t.Controller = value(2)
		t.SSHHost = value(3)
		t.SecretEnv = value(4)
		t.SecretFile = value(5)
		t.CAFile = value(6)
		t.SourceConfig = value(7)
		t.Transient = false
		// A changed credential source must not retain a secret copied from discovery.
		if t.SecretEnv != f.target.SecretEnv || t.SecretFile != f.target.SecretFile || t.SourceConfig != f.target.SourceConfig {
			t.Secret = ""
		}
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
