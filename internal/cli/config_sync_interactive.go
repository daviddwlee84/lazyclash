package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/tui"
	"github.com/spf13/cobra"
)

func (o *options) runConfigSyncInteractive(cmd *cobra.Command, source config.Target, targets []config.Target, initial map[string]configwork.StructuralSelection) error {
	opts := o.configWorkOptions(cmd)
	all, e := cmd.Flags().GetBool("all")
	if e != nil {
		all = len(targets) > 1
	}
	ui := tui.ConfigSyncOptions{SourceLabel: source.Label(), ReadOnly: o.readOnly, Initial: configSyncUIDraft(initial)}
	byID := map[string]config.Target{}
	for _, target := range targets {
		byID[target.ID] = target
		ui.Targets = append(ui.Targets, tui.ConfigSyncTarget{ID: target.ID, Label: target.Label()})
	}
	ui.Load = func(ctx context.Context, id string) (tui.ConfigSyncCatalog, error) {
		readOpts := opts
		readOpts.ReadOnly = true
		left, err := configwork.SnapshotConfig(ctx, source, readOpts)
		if err != nil {
			return tui.ConfigSyncCatalog{TargetID: id}, err
		}
		right, err := configwork.SnapshotConfig(ctx, byID[id], readOpts)
		if err != nil {
			return tui.ConfigSyncCatalog{TargetID: id}, err
		}
		return configSyncUICatalog(right, configwork.CompareConfig(left, right)), nil
	}
	ui.Preview = func(ctx context.Context, draft tui.ConfigSyncDraft) (tui.ConfigSyncPreview, error) {
		req := configSyncRequest(source, targets, configSyncSelections(draft), all)
		plan, err := configwork.PreviewChangeSetBatch(ctx, req, opts)
		return configSyncUIPreview(plan), err
	}
	ui.Apply = func(ctx context.Context, draft tui.ConfigSyncDraft, digest string) (tui.ConfigSyncOutcome, error) {
		req := configSyncRequest(source, targets, configSyncSelections(draft), all)
		result, err := configwork.ApplyChangeSetBatch(ctx, req, digest, opts)
		return configSyncUIOutcome(result), err
	}
	outcome, err := tui.RunConfigSync(cmd.Context(), ui, cmd.InOrStdin(), cmd.OutOrStdout())
	if outcome.Result != nil {
		if _, e := fmt.Fprintln(cmd.OutOrStdout(), core.Sanitize(outcome.Title+"\n"+outcome.Summary)); e != nil {
			return e
		}
	}
	return err
}

func configSyncUIOutcome(result configwork.ChangeSetBatchResult) tui.ConfigSyncOutcome {
	var lines []string
	for _, target := range result.Results {
		lines = append(lines, target.TargetID+" · "+target.Status)
		if target.Message != "" {
			lines = append(lines, target.Message)
		}
		if target.Receipt != nil {
			receipt := target.Receipt
			lines = append(lines, "Receipt: "+receipt.ID)
			if receipt.Message != "" && receipt.Message != target.Message {
				lines = append(lines, receipt.Message)
			}
			for _, change := range receipt.Changes {
				lines = append(lines, "  "+change.Status+": "+change.Path)
			}
		}
		lines = append(lines, "")
	}
	return tui.ConfigSyncOutcome{Title: "Configuration sync · " + result.Status, Summary: strings.Join(lines, "\n"), Result: result}
}

func configSyncUIDraft(selections map[string]configwork.StructuralSelection) tui.ConfigSyncDraft {
	draft := tui.ConfigSyncDraft{}
	for id, selection := range selections {
		d := tui.ConfigSyncTargetDraft{RulePlacement: selection.RulePlacement, AllowVergeRulesOverride: selection.AllowVergeRulesOverride, Dependencies: map[string]string{}, AttachGroups: map[string][]string{}}
		for _, item := range selection.Objects {
			d.Selections = append(d.Selections, tui.ConfigSyncSelection{ID: item.ID, Replace: item.Replace})
		}
		for _, decision := range selection.Dependencies {
			d.Dependencies[decision.ID] = decision.Action
		}
		for _, attachment := range selection.AttachGroups {
			d.AttachGroups[attachment.ProxyID] = append([]string(nil), attachment.Groups...)
		}
		draft[id] = d
	}
	return draft
}
func configSyncSelections(draft tui.ConfigSyncDraft) map[string]configwork.StructuralSelection {
	result := map[string]configwork.StructuralSelection{}
	for id, d := range draft {
		selection := configwork.StructuralSelection{RulePlacement: d.RulePlacement, AllowVergeRulesOverride: d.AllowVergeRulesOverride}
		for _, item := range d.Selections {
			selection.Objects = append(selection.Objects, configwork.ObjectSelection{ID: item.ID, Replace: item.Replace})
		}
		keys := make([]string, 0, len(d.Dependencies))
		for key := range d.Dependencies {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if d.Dependencies[key] != "" {
				selection.Dependencies = append(selection.Dependencies, configwork.DependencyDecision{ID: key, Action: d.Dependencies[key]})
			}
		}
		keys = nil
		for key := range d.AttachGroups {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if len(d.AttachGroups[key]) > 0 {
				selection.AttachGroups = append(selection.AttachGroups, configwork.GroupAttachment{ProxyID: key, Groups: append([]string(nil), d.AttachGroups[key]...)})
			}
		}
		result[id] = selection
	}
	return result
}

func configSyncUICatalog(destination configwork.ConfigSnapshot, diff configwork.ConfigDiff) tui.ConfigSyncCatalog {
	catalog := tui.ConfigSyncCatalog{TargetID: destination.TargetID, Owner: destination.Owner, Summary: strings.Join(diff.Warnings, "\n")}
	for _, object := range destination.Objects {
		if object.Kind == "group" {
			catalog.Groups = append(catalog.Groups, tui.ConfigSyncGroup{Name: object.Name})
		}
	}
	for _, object := range diff.Objects {
		action := "inspect"
		switch object.Status {
		case "added":
			action = "add"
		case "changed":
			action = "replace"
		case "equal":
			action = "unchanged"
		}
		id := object.SourceID
		if id == "" {
			id = object.ID
		}
		item := tui.ConfigSyncItem{ID: id, Kind: object.Kind, Category: object.Section, Label: object.Name, Action: action, MaskedDetail: configSyncObjectDetail(object)}
		if !object.Selectable {
			item.DisabledReason = "This row is comparison-only."
			if object.Status == "destination_only" {
				item.DisabledReason = "Destination-only objects are retained; sync does not delete them."
			}
			if object.After != nil && object.After.ReadOnlyReason != "" {
				item.DisabledReason = object.After.ReadOnlyReason
			}
		}
		catalog.Items = append(catalog.Items, item)
	}
	// Categories stay together while occurrence order inside rules is retained.
	order := map[string]int{"proxies": 0, "proxy-groups": 1, "rules": 2, "proxy-providers": 3, "rule-providers": 4}
	sort.SliceStable(catalog.Items, func(i, j int) bool {
		a, aok := order[catalog.Items[i].Category]
		b, bok := order[catalog.Items[j].Category]
		if !aok {
			a = 5
		}
		if !bok {
			b = 5
		}
		if a != b {
			return a < b
		}
		if a == 5 {
			return catalog.Items[i].Category < catalog.Items[j].Category
		}
		return false
	})
	return catalog
}

func configSyncObjectDetail(object configwork.ObjectDiff) string {
	lines := []string{"Status: " + object.Status}
	if object.ReplacementRequired {
		lines = append(lines, "Selecting this row explicitly replaces the whole destination definition.")
	}
	if object.OrderChanged {
		lines = append(lines, "Order differs; the preview checks rule anchors and occurrence order.")
	}
	if object.Before != nil {
		lines = append(lines, "Destination (masked):\n"+workJSON(object.Before.Value))
		if object.Before.ResourceStatus != "" {
			lines = append(lines, "Destination provider data: "+object.Before.ResourceStatus+" · SHA256 "+object.Before.ResourceSHA256)
		}
	}
	if object.After != nil {
		lines = append(lines, "Source (masked):\n"+workJSON(object.After.Value))
		if object.After.ResourceStatus != "" {
			lines = append(lines, "Source provider data: "+object.After.ResourceStatus+" · SHA256 "+object.After.ResourceSHA256)
		}
	}
	if object.Unified != "" {
		lines = append(lines, "Unified diff (masked):\n"+object.Unified)
	}
	return strings.Join(lines, "\n\n")
}

func configSyncUIPreview(plan configwork.ChangeSetBatchPlan) tui.ConfigSyncPreview {
	view := tui.ConfigSyncPreview{Digest: plan.Digest, Ready: plan.Status == "ready", Summary: configwork.FormatChangeSetBatch(plan)}
	seen := map[string]bool{}
	for _, target := range plan.Targets {
		row := tui.ConfigSyncPreviewTarget{TargetID: target.TargetID, Summary: target.Status + "\n" + target.Message}
		if target.Plan != nil {
			p := target.Plan
			row.MaskedDiff = configwork.FormatConfigDiff(p.Composition.Diff, "unified")
			row.Summary += fmt.Sprintf("\nSelected: %d · added dependencies: %d · reused dependencies: %d", len(p.Composition.Selected), len(p.Composition.AutoSelected), len(p.Composition.Reused))
			label := func(id string) string {
				if p.Composition.SourceSnapshot != nil {
					for _, object := range p.Composition.SourceSnapshot.Objects {
						if object.ID == id {
							return object.Kind + " " + object.Name
						}
					}
				}
				return id
			}
			requiredBy := func(id string) string {
				var names []string
				for _, required := range p.Composition.RequiredBy[id] {
					names = append(names, label(required))
				}
				return strings.Join(names, ", ")
			}
			for _, id := range p.Composition.AutoSelected {
				row.Summary += "\nDependency: " + label(id)
				if names := requiredBy(id); names != "" {
					row.Summary += " · required by " + names
				}
			}
			for _, resource := range p.Resources {
				row.Summary += fmt.Sprintf("\nProvider snapshot: %s · %d bytes · %s\nSHA256: %s", resource.Provider, resource.Bytes, resource.Path, resource.SHA256)
			}
			var choices configwork.ConfigDiff
			if p.Composition.SourceSnapshot != nil && p.Composition.DestinationSnapshot != nil {
				choices = configwork.CompareConfig(*p.Composition.SourceSnapshot, *p.Composition.DestinationSnapshot)
			}
			for _, blocker := range p.Composition.Blockers {
				if blocker.Code != "dependency_conflict" || blocker.DependencyID == "" {
					continue
				}
				key := target.TargetID + "\x00" + blocker.DependencyID
				if seen[key] {
					continue
				}
				seen[key] = true
				decision := tui.ConfigSyncDecision{ID: blocker.DependencyID, TargetID: target.TargetID, Label: blocker.DependencyID, MaskedDetail: blocker.Message}
				if names := requiredBy(blocker.DependencyID); names != "" {
					decision.MaskedDetail += "\nRequired by: " + names
				}
				for _, object := range choices.Objects {
					if object.SourceID == blocker.DependencyID {
						decision.Label = object.Kind + " " + object.Name
						decision.MaskedDetail += "\n\n" + configSyncObjectDetail(object)
						break
					}
				}
				view.Decisions = append(view.Decisions, decision)
			}
		}
		view.Targets = append(view.Targets, row)
	}
	return view
}
