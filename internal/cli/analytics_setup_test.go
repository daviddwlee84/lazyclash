package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/analytics"
)

func TestAnalyticsSourceEditPreservesUnshownFieldsAndExplicitFlags(t *testing.T) {
	saved := analytics.SourceConfig{ID: "proxy", Kind: "xray-stats", Scope: "server", Enabled: true, Target: "keep-target", Format: "v2ctl", Timezone: "UTC", Binary: "/usr/bin/v2ctl", Address: "127.0.0.1:10085", PollSeconds: 45, ServerID: "deployment", HostID: "vm"}
	flags := analytics.SourceConfig{ID: saved.ID, PollSeconds: 60, Enabled: false}
	draft := analyticsSourceDraft(saved, flags, func(name string) bool { return name == "poll-seconds" })
	if !draft.Enabled || draft.Format != "v2ctl" || draft.Timezone != "UTC" || draft.Target != saved.Target || draft.PollSeconds != 60 {
		t.Fatal("explicit flags replaced unsupplied saved values", draft)
	}
	result, err := analyticsSourceFromForm([]analytics.SourceConfig{saved}, draft, saved.ID, map[string]string{"id": "proxy", "kind": "xray-stats", "binary": "/opt/v2ctl", "enabled": "true", "format": "v2ctl"})
	if err != nil {
		t.Fatal(err)
	}
	if result.PollSeconds != 60 || result.ServerID != saved.ServerID || result.HostID != saved.HostID || result.Timezone != saved.Timezone || result.Target != saved.Target || result.Binary != "/opt/v2ctl" {
		t.Fatal("form discarded hidden settings or flag overrides", result)
	}
	if err := analytics.ValidateSource(result); err != nil {
		t.Fatal("valid V2Ray 4 stats form rejected", err)
	}
	disabled := analyticsSourceDraft(saved, flags, func(name string) bool { return name == "enabled" })
	if disabled.Enabled || disabled.PollSeconds != saved.PollSeconds {
		t.Fatal("explicit false flag not respected")
	}
	cleared := analyticsSourceDraft(saved, analytics.SourceConfig{ID: "proxy"}, func(name string) bool { return name == "source-timezone" })
	if cleared.Timezone != "" || cleared.Format != saved.Format {
		t.Fatal("explicitly empty string flag not respected")
	}
}

func TestAnalyticsUnpopulatedFormCannotOverwriteExistingIdentity(t *testing.T) {
	existing := analytics.SourceConfig{ID: "desktop", Kind: "mihomo", Scope: "client", Target: "original", Enabled: true, PollSeconds: 20, HostID: "device"}
	sources := []analytics.SourceConfig{existing}
	values := map[string]string{"id": "desktop", "kind": "mihomo", "target": "default-other", "enabled": "false"}
	for _, prefilled := range []string{"", "another-source"} {
		_, err := analyticsSourceFromForm(sources, analytics.SourceConfig{}, prefilled, values)
		if err == nil || !strings.Contains(err.Error(), "--source desktop --interactive") {
			t.Fatal("unpopulated form was allowed to retarget an existing source", err)
		}
		if !reflect.DeepEqual(sources, []analytics.SourceConfig{existing}) {
			t.Fatal("failed submission mutated saved configuration")
		}
	}
	created, err := analyticsSourceFromForm(sources, analytics.SourceConfig{ServerID: "flag-server"}, "", map[string]string{"id": "new-source", "kind": "interface", "interface": "eth0", "enabled": "true"})
	if err != nil || created.ServerID != "flag-server" || created.Interface != "eth0" || !created.Enabled {
		t.Fatal("new source form lost flags", created, err)
	}
}

func TestAnalyticsWizardFormatsMatchStatsAndAccessValidation(t *testing.T) {
	seen := map[string]bool{}
	for _, choice := range analyticsSourceFormatChoices() {
		seen[choice.Value] = true
		stats := analytics.SourceConfig{ID: "stats", Kind: "xray-stats", Format: choice.Value}
		if err := analytics.ValidateSource(stats); err != nil {
			t.Fatal("wizard offers unsupported Stats format", choice.Value, err)
		}
		access := analytics.SourceConfig{ID: "access", Kind: "xray-access", Path: "/var/log/access.log", Format: choice.Value}
		err := analytics.ValidateSource(access)
		if (choice.Value == "v2ctl") != (err != nil) {
			t.Fatal("v2ctl must remain Stats-only", choice.Value, err)
		}
	}
	for _, value := range []string{"", "xray", "v2ray", "v2ctl"} {
		if !seen[value] {
			t.Fatal("missing Stats format choice", value)
		}
	}
}
