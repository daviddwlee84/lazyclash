package cli

import (
	"fmt"

	"github.com/daviddwlee84/lazyclash/internal/analytics"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
)

// analyticsSourceDraft uses stored values for an existing source and overlays
// only explicitly supplied flags. The same draft feeds preview and the form.
func analyticsSourceDraft(saved, requested analytics.SourceConfig, changed func(string) bool) analytics.SourceConfig {
	for _, field := range []struct {
		name  string
		value string
		to    *string
	}{
		{"kind", requested.Kind, &saved.Kind}, {"interface", requested.Interface, &saved.Interface},
		{"path", requested.Path, &saved.Path}, {"format", requested.Format, &saved.Format},
		{"source-timezone", requested.Timezone, &saved.Timezone}, {"binary", requested.Binary, &saved.Binary},
		{"address", requested.Address, &saved.Address}, {"server-id", requested.ServerID, &saved.ServerID},
		{"host-id", requested.HostID, &saved.HostID},
	} {
		if changed(field.name) {
			*field.to = field.value
		}
	}
	if changed("enabled") {
		saved.Enabled = requested.Enabled
	}
	if changed("poll-seconds") {
		saved.PollSeconds = requested.PollSeconds
	}
	return saved
}

func analyticsSourceFormatChoices() []wizard.Choice {
	return []wizard.Choice{
		{Value: "", Label: "Default for source type"},
		{Value: "xray", Label: "Xray"},
		{Value: "v2ray", Label: "V2Ray JSON / access log"},
		{Value: "v2ctl", Label: "V2Ray 4 v2ctl (Stats only)"},
	}
}

// An ID typed into an unpopulated creation form must not overwrite an existing
// source using defaults the user never reviewed as edits. Reopen that ID with
// --source to get its actual values; no configuration has been written yet.
func analyticsSourceFromForm(sources []analytics.SourceConfig, draft analytics.SourceConfig, prefilledID string, values map[string]string) (analytics.SourceConfig, error) {
	for _, existing := range sources {
		if existing.ID == values["id"] && existing.ID != prefilledID {
			return analytics.SourceConfig{}, fmt.Errorf("source %q already exists; reopen with analytics setup --source %s --interactive to edit its saved settings", existing.ID, existing.ID)
		}
	}
	for _, field := range []struct {
		name string
		to   *string
	}{
		{"id", &draft.ID}, {"kind", &draft.Kind}, {"target", &draft.Target},
		{"interface", &draft.Interface}, {"path", &draft.Path}, {"format", &draft.Format},
		{"source-timezone", &draft.Timezone}, {"binary", &draft.Binary}, {"address", &draft.Address},
	} {
		if value, ok := values[field.name]; ok {
			*field.to = value
		}
	}
	if value, ok := values["enabled"]; ok {
		draft.Enabled = value == "true"
	}
	return draft, nil
}
