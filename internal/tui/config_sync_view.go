package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

func configSyncText(text string, width, height, offset int) []string {
	lines := strings.Split(ansi.Wrap(core.Sanitize(text), max(1, width), ""), "\n")
	offset = min(max(0, offset), max(0, len(lines)-height))
	return fitLines(strings.Join(lines[offset:], "\n"), max(1, width), max(0, height))
}

func (m *configSyncModel) selected(id string) bool {
	for _, item := range m.draft[m.targetID()].Selections {
		if item.ID == id {
			return true
		}
	}
	return false
}

func (m *configSyncModel) selectorBody(width, height int) []string {
	rows := m.rows()
	listWidth, detailWidth := width, 0
	if width >= 88 {
		listWidth = width * 42 / 100
		detailWidth = width - listWidth - 3
	}
	var list []string
	start := max(0, m.index-max(0, (height-2)/2))
	category := ""
	for i := start; i < len(rows) && len(list) < height; i++ {
		item := rows[i]
		if item.Category != category {
			category = item.Category
			list = append(list, fit("── "+core.Sanitize(category)+" ──", listWidth))
			if len(list) >= height {
				break
			}
		}
		mark := "[ ]"
		if m.selected(item.ID) {
			mark = "[x]"
		} else if item.DisabledReason != "" {
			mark = "[-]"
		}
		cursor := "  "
		if i == m.index {
			cursor = "> "
		}
		list = append(list, fit(core.Sanitize(cursor+mark+" "+item.Action+" "+item.Label), listWidth))
	}
	if len(rows) == 0 {
		list = append(list, "No matching objects. r refresh / Esc back.")
	}
	detail := m.catalogs[m.targetID()].Summary
	if len(rows) > 0 {
		item := rows[min(m.index, len(rows)-1)]
		detail = item.Category + " · " + item.Label + "\nAction: " + item.Action + "\n"
		if item.DisabledReason != "" {
			detail += "Read-only: " + item.DisabledReason + "\n"
		}
		if item.Action == "replace" {
			detail += "Selection replaces the entire destination object, including its credentials and omitted fields.\n"
		}
		detail += "\n" + item.MaskedDetail
	}
	if width < 88 {
		if m.focus == 1 {
			return configSyncText(detail, width, height, m.offset)
		}
		return fitLines(strings.Join(list, "\n"), width, height)
	}
	left := fitLines(strings.Join(list, "\n"), listWidth, height)
	right := configSyncText(detail, detailWidth, height, m.offset)
	for i := range left {
		left[i] += " │ " + right[i]
	}
	return left
}

func (m *configSyncModel) View() tea.View {
	width, height := max(1, m.width), max(1, m.height)
	if m.help {
		text := "Configuration sync help\n\nEvery destination starts unselected and retains its own draft.\n\n↑↓ or j/k: select an object. Space: toggle the whole object or rule occurrence. Replacement rows replace the complete definition. [-] rows are read-only.\n\nTab: switch object/detail focus. h/l or ←→: change destination. /: filter; typing owns every printable key. Enter accepts a filter without acting.\n\ng: attach a selected proxy to existing destination groups. o: choose anchored/prepend rule placement and acknowledge a complete local Verge rules override.\n\nr: refresh the selected target. c: clear its selected objects, dependency choices and attachments.\n\np: preflight all independently selected targets. Dependency collisions require an explicit reuse/replace choice; no replacement is selected by default.\n\nReview: h/l changes target, ↑↓ scrolls details, Tab chooses Back/Apply, Enter activates. Back is always the default.\n\nEsc keeps the draft when returning from options, decisions or review. Esc at object selection cancels. After apply starts, cancellation waits for the outcome; completed writes are retained.\n\nSecrets remain masked in definitions and diffs. Receipts report persistence and native activation separately."
		lines := configSyncText(text, width, max(0, height-1), m.helpOffset)
		lines = append(lines, fit("↑↓/jk scroll · Esc / ? close", width))
		v := tea.NewView(strings.Join(lines, "\n"))
		v.AltScreen = true
		return v
	}
	lines := []string{"Sync source configuration · " + core.Sanitize(m.opts.SourceLabel), core.Sanitize(m.selectionSummary())}
	bodyHeight := max(0, height-6)
	foot := ""
	switch m.phase {
	case "select":
		focus := []string{"OBJECTS", "DETAIL"}[m.focus]
		lines = append(lines, fit(fmt.Sprintf("Destination %d/%d: %s · %s", m.target+1, len(m.opts.Targets), m.opts.Targets[m.target].Label, focus), width))
		if m.search {
			lines[len(lines)-1] = m.query.View()
		} else if m.query.Value() != "" {
			lines[len(lines)-1] += " · Filter: " + m.query.Value()
		}
		lines = append(lines, m.selectorBody(width, bodyHeight)...)
		foot = "Space select · p preview · ? help · Tab detail · h/l target · / filter · g groups · o options · Esc cancel"
	case "groups":
		lines = append(lines, "Attach selected proxy to destination groups")
		var text []string
		chosen := m.draft[m.targetID()].AttachGroups[m.attachProxy]
		for i, group := range m.catalogs[m.targetID()].Groups {
			mark := "[ ]"
			for _, name := range chosen {
				if name == group.Name {
					mark = "[x]"
				}
			}
			cursor := "  "
			if i == m.groupIndex {
				cursor = "> "
			}
			text = append(text, cursor+mark+" "+group.Name)
		}
		if len(text) == 0 {
			text = append(text, "No existing destination groups are available.")
		}
		text = append(text, "\nMembership is appended in the same reviewed candidate. A group also selected for whole replacement must be resolved before applying.")
		lines = append(lines, configSyncText(strings.Join(text, "\n"), width, bodyHeight, max(0, m.groupIndex-bodyHeight/2))...)
		foot = "↑↓/jk choose · Space toggle · Enter/Esc back (retain attachments)"
	case "options":
		d := m.draft[m.targetID()]
		lines = append(lines, "Options · "+core.Sanitize(m.opts.Targets[m.target].Label))
		marks := []string{"  ", "  "}
		marks[m.option] = "> "
		override := "[ ]"
		if d.AllowVergeRulesOverride {
			override = "[x]"
		}
		text := marks[0] + "Rule placement: " + d.RulePlacement + "\n" + marks[1] + override + " Permit complete local rules override for Verge\n\nAnchored preserves selected source order around destination anchors. Prepend puts selected rules before the destination list.\n\nVerge override stores a complete rules list in this profile's Merge companion. Subscription rule updates are masked until that override is removed. This is an explicit acknowledgement, not a generic force option."
		lines = append(lines, configSyncText(text, width, bodyHeight, 0)...)
		foot = "↑↓/jk choose · Space/Enter change · Esc back (retain choices)"
	case "decisions", "choice":
		lines = append(lines, "Resolve dependency collisions · no default replacement")
		var fixed []string
		detail := ""
		if len(m.preview.Decisions) > 0 {
			d := m.preview.Decisions[min(m.decision, len(m.preview.Decisions)-1)]
			detail = d.TargetID + " · " + d.Label + "\n\n" + d.MaskedDetail
		}
		if m.phase == "choice" {
			fixed = append(fixed, "Choose explicitly:")
			for i, label := range []string{"Leave unresolved", "Reuse the destination definition", "Replace with the source definition"} {
				cursor := "  "
				if m.choice == i {
					cursor = "> "
				}
				fixed = append(fixed, cursor+label)
			}
			foot = "↑↓/jk choose · PgUp/PgDn detail · Enter retain decision · Esc back"
		} else {
			count := min(5, max(1, bodyHeight/3))
			start := max(0, m.decision-count+1)
			for i := start; i < len(m.preview.Decisions) && i < start+count; i++ {
				d := m.preview.Decisions[i]
				cursor := "  "
				if i == m.decision {
					cursor = "> "
				}
				choice := m.draft[d.TargetID].Dependencies[d.ID]
				if choice == "" {
					choice = "unresolved"
				}
				fixed = append(fixed, cursor+d.TargetID+" · "+d.Label+" → "+choice)
			}
			foot = "↑↓/jk · Tab list/detail · Enter choose · p preview again · e edit selection · Esc back"
		}
		fixed = fitLines(strings.Join(fixed, "\n"), width, min(len(fixed), bodyHeight))
		lines = append(lines, fixed...)
		lines = append(lines, configSyncText(detail, width, max(0, bodyHeight-len(fixed)), m.offset)...)
	case "review":
		lines = append(lines, "Review selected changes · default action is Back")
		text := m.preview.Summary
		if len(m.preview.Targets) > 0 {
			target := m.preview.Targets[min(m.reviewTarget, len(m.preview.Targets)-1)]
			text = fmt.Sprintf("Target %d/%d: %s\n%s\n\n%s\n\n%s", m.reviewTarget+1, len(m.preview.Targets), target.TargetID, target.Summary, target.MaskedDiff, text)
		}
		if m.preview.Digest != "" {
			text += "\nReviewed digest: " + m.preview.Digest
		}
		lines = append(lines, configSyncText(text, width, bodyHeight, m.offset)...)
		buttons := "> Back    Apply"
		if m.accept {
			buttons = "  Back  > Apply"
		}
		if !m.preview.Ready || m.opts.ReadOnly {
			buttons = "> Back    Apply unavailable"
		}
		foot = buttons + " · Tab choose · Enter activate · h/l target · ↑↓ scroll · Esc back"
	case "result":
		lines = append(lines, core.Sanitize(m.outcome.Title))
		lines = append(lines, configSyncText(m.outcome.Summary, width, bodyHeight, m.offset)...)
		foot = "↑↓/jk scroll · e edit draft and prepare a new preview · Enter/Esc finish"
	default:
		lines = append(lines, core.Sanitize(m.message))
		lines = append(lines, configSyncText(m.preview.Summary, width, bodyHeight, 0)...)
		foot = "Esc cancels waiting; applied writes are not rolled back"
	}
	lines = fitLines(strings.Join(lines, "\n"), width, max(0, height-2))
	lines = append(lines, fit(core.Sanitize(m.message), width), fit(core.Sanitize(foot), width))
	if len(lines) > height {
		lines = lines[:height]
	}
	v := tea.NewView(strings.Join(lines, "\n"))
	v.AltScreen = true
	return v
}
