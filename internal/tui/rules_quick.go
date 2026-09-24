package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/config"
)

func ruleKeys(p page, key string) []string {
	if p == rules {
		return []string{key}
	}
	return nil
}

func (m *Model) startQuickRuleForm() tea.Cmd {
	return m.startForm("work-rule-quick", "Quick apply routing rule", "", []field{{"Rule (optional YAML '- ' prefix)", m.quickRuleDraft}})
}

func (m *Model) retainQuickRuleDraft() {
	if m.form == nil || m.form.kind != "work-rule-quick" {
		return
	}
	if m.form.index < len(m.form.fields) {
		m.form.fields[m.form.index].value = m.input.Value()
	}
	m.quickRuleDraft = m.form.fields[0].value
}

func (m *Model) startQuickRuleTargets(req WorkRequest) tea.Cmd {
	title := "Quick rule · choose targets"
	summary := req.Rule + "\nChoose the saved target(s) to inspect. No changes are made before preview and confirmation."
	if req.Kind == "rule-healthcheck" {
		title = "Rules healthcheck · choose targets"
		summary = "Inspect persistent and runtime routing rules without changing them."
	}
	w := &workState{request: req, phase: "rule-target", checked: map[string]bool{}, result: WorkResult{Title: title, Summary: summary}}
	for _, t := range m.settings.Targets {
		if t.Transient {
			continue
		}
		label := t.Label()
		if t.ID == m.target.ID {
			label += " [current]"
		}
		w.result.Rows = append(w.result.Rows, WorkRow{ID: "target:" + t.ID, Label: label, Detail: t.Controller + " via " + defaultString(t.SSHHost, "local")})
		if t.ID == m.target.ID {
			w.index = len(w.result.Rows) - 1
		}
	}
	if len(w.result.Rows) > 0 {
		detail := "Every saved target is preflighted; unavailable targets are reported separately. Requested-selector conflicts and invalid candidates block the batch; unrelated existing health warnings do not."
		if req.Kind == "rule-healthcheck" {
			detail = "Inspect every saved target without changing its routing configuration. Unavailable views are reported separately."
		}
		w.result.Rows = append(w.result.Rows, WorkRow{ID: "all", Label: fmt.Sprintf("All saved targets (%d)", len(w.result.Rows)), Detail: detail})
	} else {
		w.result.Summary += "\nSave a target to use this operation."
	}
	for i, r := range w.result.Rows {
		if r.ID == m.quickRuleScope {
			w.index = i
		}
	}
	m.work = w
	m.overlay = "work"
	m.form = nil
	m.input.Blur()
	return nil
}

func (m *Model) invalidateRuleWorkTarget(id string) {
	if s := m.states[id]; s != nil {
		for _, key := range []string{"config", "proxies", "rules", "proxyProviders", "ruleProviders"} {
			snap := s.snap(key)
			snap.err = errors.New("rule operation finished; awaiting refresh")
			snap.serial++
			snap.loading = false
		}
	}
}

func (m *Model) startRuleSourceReuse() tea.Cmd {
	if m.options.ReadOnly || m.options.Workbench == nil || m.options.SaveTargets == nil {
		return nil
	}
	source, err := config.RuleSourceFromConfigSource(m.target)
	if err != nil {
		m.status = safeError(err)
		return nil
	}
	cfg := cloneSettings(m.settings)
	var target config.Target
	found := false
	for i := range cfg.Targets {
		if cfg.Targets[i].ID == m.target.ID && !cfg.Targets[i].Transient && !m.target.TransportOverride {
			cfg.Targets[i].RuleSource = source
			target = cfg.Targets[i]
			found = true
			break
		}
	}
	if !found {
		m.status = "Save this target before binding a rule source"
		return nil
	}
	details := []string{"Target: " + target.ID, "Owner: " + source.Kind}
	for _, value := range []string{source.ConfigID, source.HostPath, source.DataDir, source.ProfileUID} {
		if value != "" {
			details = append(details, value)
		}
	}
	details = append(details, "Inspect the existing node/group source and save a separate rule-write binding.")
	m.ask("Reuse source for routing rules", strings.Join(details, "\n"), func() tea.Cmd {
		m.overlay = "saving"
		m.status = "Checking rule owner before saving binding…"
		run, save, ctx := m.options.Workbench, m.options.SaveTargets, m.ctx
		return func() tea.Msg {
			inspectCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			_, err := run(inspectCtx, WorkRequest{Kind: "source-inspect", Source: target.ID, Target: target})
			if err == nil {
				err = save(cfg)
			}
			return savedMsg{settings: cfg, selected: target.ID, err: err}
		}
	})
	m.confirm.defaultNegative = true
	return nil
}
