package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/tui"
	"go.yaml.in/yaml/v3"
)

func TestConfigSyncUIDraftPreservesPerTargetReplacementAndAttachments(t *testing.T) {
	selections := map[string]configwork.StructuralSelection{
		"a": {Objects: []configwork.ObjectSelection{{ID: "/proxies/a", Replace: true}}, Dependencies: []configwork.DependencyDecision{{ID: "/proxies/dep", Action: "reuse"}}, RulePlacement: "anchored", AttachGroups: []configwork.GroupAttachment{{ProxyID: "/proxies/a", Groups: []string{"Route"}}}},
		"b": {Objects: []configwork.ObjectSelection{{ID: "/rules/0"}}, RulePlacement: "prepend", AllowVergeRulesOverride: true},
	}
	draft := configSyncUIDraft(selections)
	if !reflect.DeepEqual(configSyncSelections(draft), selections) {
		t.Fatalf("lost structural decisions: %+v", configSyncSelections(draft))
	}
	draft["a"].AttachGroups["/proxies/a"][0] = "edited"
	if selections["a"].AttachGroups[0].Groups[0] != "Route" {
		t.Fatal("draft mutated caller's attachment slice")
	}
}

func TestConfigSyncUICatalogWholeActionsReadOnlyAndMaskedDetails(t *testing.T) {
	secret := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "PRIVATE_MUST_NOT_DISPLAY"}
	proxy := configwork.ConfigObject{ID: "/proxies/p", Kind: "proxy", Name: "p", Selectable: true, Value: map[string]any{"password": "[masked]"}, Node: secret}
	diff := configwork.ConfigDiff{Objects: []configwork.ObjectDiff{
		{ID: proxy.ID, SourceID: proxy.ID, Kind: "proxy", Section: "proxies", Name: "p", Status: "changed", Selectable: true, ReplacementRequired: true, Before: &proxy, After: &proxy, Unified: "- password: [masked]\n+ password: [masked]"},
		{ID: "/proxies/add", SourceID: "/proxies/add", Kind: "proxy", Section: "proxies", Name: "add", Status: "added", Selectable: true},
		{ID: "/proxies/dest", Kind: "proxy", Section: "proxies", Name: "dest", Status: "destination_only"},
		{ID: "/dns", Kind: "section", Section: "dns", Name: "dns", Status: "changed", After: &configwork.ConfigObject{ReadOnlyReason: "Host settings are comparison-only."}},
	}}
	catalog := configSyncUICatalog(configwork.ConfigSnapshot{TargetID: "target", Objects: []configwork.ConfigObject{{Kind: "group", Name: "Route"}}}, diff)
	if len(catalog.Items) != 4 || catalog.Items[0].Action != "replace" || catalog.Items[1].Action != "add" || catalog.Items[2].DisabledReason == "" || catalog.Items[3].DisabledReason == "" || len(catalog.Groups) != 1 {
		t.Fatalf("incorrect selector actions: %+v", catalog)
	}
	for _, row := range catalog.Items {
		if strings.Contains(row.MaskedDetail, "PRIVATE_MUST_NOT_DISPLAY") {
			t.Fatal("displayed raw definition credentials")
		}
	}
	if !strings.Contains(catalog.Items[0].MaskedDetail, "whole destination definition") || !strings.Contains(catalog.Items[0].MaskedDetail, "Unified diff") {
		t.Fatal("replacement was not disclosed")
	}
}

func TestConfigSyncUIPreviewKeepsBlockingDependencyChoicesAndDiff(t *testing.T) {
	var sourceNode, destNode yaml.Node
	if err := yaml.Unmarshal([]byte("name: dep\ntype: trojan\npassword: SECRET_SOURCE\n"), &sourceNode); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte("name: dep\ntype: trojan\npassword: SECRET_DEST\n"), &destNode); err != nil {
		t.Fatal(err)
	}
	source := configwork.ConfigSnapshot{TargetID: "source", Complete: true, Objects: []configwork.ConfigObject{{ID: "/proxies/dep", Kind: "proxy", Section: "proxies", Name: "dep", Selectable: true, Value: map[string]any{"password": "[masked]"}, Node: sourceNode.Content[0]}}}
	destination := source
	destination.TargetID = "target"
	destination.Objects = append([]configwork.ConfigObject(nil), source.Objects...)
	destination.Objects[0].Node = destNode.Content[0]
	composition := configwork.StructuralComposition{SourceSnapshot: &source, DestinationSnapshot: &destination, Blockers: []configwork.StructuralBlocker{{Code: "dependency_conflict", DependencyID: "/proxies/dep", Message: "Choose a definition"}, {Code: "dependency_conflict", DependencyID: "/proxies/dep", Message: "Second requiring object"}, {Code: "rule_placement_ambiguous", Message: "Choose prepend"}}}
	plan := configwork.ChangeSetBatchPlan{Status: "blocked", Digest: strings.Repeat("d", 64), Targets: []configwork.ChangeSetTargetPlan{{TargetID: "target", Status: "blocked", Plan: &configwork.ChangeSetPlan{Composition: composition}}}}
	preview := configSyncUIPreview(plan)
	if preview.Ready || len(preview.Decisions) != 1 || preview.Decisions[0].ID != "/proxies/dep" || len(preview.Targets) != 1 {
		t.Fatalf("lost blocked decisions: %+v", preview)
	}
	text := preview.Decisions[0].MaskedDetail
	if strings.Contains(text, "SECRET_SOURCE") || strings.Contains(text, "SECRET_DEST") || !strings.Contains(text, "Source (masked)") {
		t.Fatalf("unsafe dependency detail: %s", text)
	}
	if !strings.Contains(preview.Summary, "rule_placement_ambiguous") {
		t.Fatal("nondependency blocker was discarded")
	}
	if selected := configSyncSelections(tui.ConfigSyncDraft{}); len(selected) != 0 {
		t.Fatal("unselected draft granted actions")
	}
}
