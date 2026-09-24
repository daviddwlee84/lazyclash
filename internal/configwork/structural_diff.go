package configwork

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
	"go.yaml.in/yaml/v3"
)

// CompareConfig describes copying selected source objects into destination.
// Equality uses private typed values before any masking is applied.
func CompareConfig(source, destination ConfigSnapshot) ConfigDiff {
	result := ConfigDiff{SourceTargetID: source.TargetID, DestinationTargetID: destination.TargetID, SourceShape: source.Shape, DestinationShape: destination.Shape, Complete: source.Complete && destination.Complete, Equal: true, Objects: []ObjectDiff{}}
	for _, warnings := range [][]string{source.Warnings, destination.Warnings} {
		for _, warning := range warnings {
			appendUnique(&result.Warnings, warning)
		}
	}
	pairs := structuralObjectPairs(source.Objects, destination.Objects)
	used := map[int]bool{}
	moved := structuralMovedRules(source.Objects, destination.Objects)
	for i := range source.Objects {
		object := source.Objects[i]
		var before *ConfigObject
		if j, ok := pairs[i]; ok {
			copy := destination.Objects[j]
			before = &copy
			used[j] = true
		}
		row := structuralObjectDiff(before, &object)
		if object.Kind == "rule" && moved[object.Index] {
			row.OrderChanged = true
			if row.Status == "equal" {
				row.Status, row.Selectable = "changed", object.Selectable
			}
			row.Unified += "# Relative rule order differs.\n"
		}
		if row.Status != "equal" {
			result.Equal = false
		}
		result.Objects = append(result.Objects, row)
	}
	for j := range destination.Objects {
		if !used[j] {
			copy := destination.Objects[j]
			row := structuralObjectDiff(&copy, nil)
			result.Objects = append(result.Objects, row)
			result.Equal = false
		}
	}
	return result
}

func structuralObjectPairs(source, destination []ConfigObject) map[int]int {
	pairs, used := map[int]int{}, map[int]bool{}
	named := map[string]int{}
	for i, object := range destination {
		if object.Kind != "rule" {
			named[object.ID] = i
		}
	}
	for i, object := range source {
		if object.Kind != "rule" {
			if j, ok := named[object.ID]; ok {
				pairs[i], used[j] = j, true
			}
		}
	}
	for _, exact := range []bool{true, false} {
		queues := map[string][]int{}
		for j, object := range destination {
			if object.Kind == "rule" && !used[j] {
				if key := structuralRuleKey(object, exact); key != "" {
					queues[key] = append(queues[key], j)
				}
			}
		}
		for i, object := range source {
			if object.Kind != "rule" {
				continue
			}
			if _, paired := pairs[i]; paired {
				continue
			}
			key := structuralRuleKey(object, exact)
			if key == "" || len(queues[key]) == 0 {
				continue
			}
			j := queues[key][0]
			queues[key] = queues[key][1:]
			pairs[i], used[j] = j, true
		}
	}
	return pairs
}

func structuralRuleKey(object ConfigObject, exact bool) string {
	if object.Node == nil {
		return ""
	}
	rule := rulecheck.ParseExisting(object.Node.Value, object.Index)
	key := rule.SelectorKey()
	if key == "" {
		if exact {
			return "literal:" + object.Node.Value
		}
		return ""
	}
	if !exact {
		return key
	}
	return hashJSON([]any{key, rule.Policy, rule.NoResolve, append([]string{}, rule.Options...)})
}

func structuralMovedRules(source, destination []ConfigObject) map[int]bool {
	entries := func(objects []ConfigObject) []rulecheck.Entry {
		result := []rulecheck.Entry{}
		for _, object := range objects {
			if object.Kind == "rule" {
				result = append(result, rulecheck.Entry{Section: "rules", Rule: rulecheck.ParseExisting(object.Node.Value, object.Index)})
			}
		}
		return result
	}
	result := map[int]bool{}
	for _, change := range rulecheck.CompareEntries(entries(destination), entries(source), false).Changes {
		if change.Right == nil {
			continue
		}
		for _, field := range change.Fields {
			if field == "order" {
				result[change.Right.Rule.Index] = true
			}
		}
	}
	return result
}

func structuralObjectDiff(before, after *ConfigObject) ObjectDiff {
	object := before
	if after != nil {
		object = after
	}
	r := ObjectDiff{ID: object.ID, Kind: object.Kind, Name: object.Name, Section: object.Section, Before: before, After: after, Status: "equal", Fields: []StructuralFieldChange{}}
	var a, b *yaml.Node
	if before != nil {
		r.DestinationID, a = before.ID, before.Node
	}
	if after != nil {
		r.SourceID, b = after.ID, after.Node
		r.Selectable = after.Selectable
	}
	equal := typedFingerprint(a) == typedFingerprint(b)
	if before != nil && after != nil && object.Kind == "rule" {
		equal = structuralRuleKey(*before, true) == structuralRuleKey(*after, true)
	}
	resourceDifferent := false
	if before != nil && after != nil && (structuralFileProvider(*before) || structuralFileProvider(*after)) {
		resourceDifferent = before.ResourceStatus != "available" || after.ResourceStatus != "available" || before.ResourceSHA256 != after.ResourceSHA256
		equal = equal && !resourceDifferent
	}
	switch {
	case after == nil:
		r.Status, r.Selectable = "destination_only", false
	case before == nil:
		r.Status = "added"
	case !equal:
		r.Status, r.ReplacementRequired = "changed", after.Selectable
	}
	if r.Status != "equal" {
		kind := object.Kind
		if strings.HasPrefix(object.ID, "/_shape/") {
			kind = "rule"
		} // generated nonsecret shape labels
		structuralFieldDiff("", structuralNormalized(a), structuralNormalized(b), kind, object.Section, &r.Fields)
		if resourceDifferent {
			field := StructuralFieldChange{Path: "/@resource", Operation: "changed", BeforePresent: before.ResourceStatus == "available", AfterPresent: after.ResourceStatus == "available", BeforeType: "file-content", AfterType: "file-content", Before: before.ResourceSHA256, After: after.ResourceSHA256}
			if !field.BeforePresent || !field.AfterPresent {
				field.Operation = "not_compared"
				if !field.BeforePresent {
					field.Before = "[unavailable]"
				}
				if !field.AfterPresent {
					field.After = "[unavailable]"
				}
			}
			r.Fields = append(r.Fields, field)
		}
		r.Unified = structuralUnified(before, after, r.Fields)
	}
	return r
}

func structuralFieldDiff(path string, before, after *yaml.Node, kind, section string, changes *[]StructuralFieldChange) {
	if typedFingerprint(before) == typedFingerprint(after) {
		return
	}
	if (before == nil || before.Kind == yaml.MappingNode) && (after == nil || after.Kind == yaml.MappingNode) && (before != nil || after != nil) {
		keys := map[string]bool{}
		for _, node := range []*yaml.Node{before, after} {
			if node != nil {
				for i := 0; i+1 < len(node.Content); i += 2 {
					keys[node.Content[i].Value] = true
				}
			}
		}
		ordered := make([]string, 0, len(keys))
		for key := range keys {
			ordered = append(ordered, key)
		}
		sort.Strings(ordered)
		for _, key := range ordered {
			structuralFieldDiff(path+"/"+structuralPointer(key), get(before, key), get(after, key), kind, section, changes)
		}
		return
	}
	r := StructuralFieldChange{Path: path, Operation: "changed", BeforePresent: before != nil, AfterPresent: after != nil, BeforeType: structuralNodeType(before), AfterType: structuralNodeType(after)}
	if before == nil {
		r.Operation = "added"
	}
	if after == nil {
		r.Operation = "removed"
	}
	if path == "" {
		r.Path = "/"
	}
	// Traverse the original schema path when deciding display permissions;
	// a safe-looking child inside an unknown/credential container stays hidden.
	allowed, key := kind != "section" || structuralSafeScalar(section) || structuralSafeContainer(section), section
	for _, segment := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if segment == "" {
			continue
		}
		key = strings.ReplaceAll(strings.ReplaceAll(segment, "~1", "/"), "~0", "~")
		allowed = allowed && (structuralSafeScalar(key) || structuralSafeContainer(key))
	}
	if kind == "rule" {
		allowed = true
	}
	var ma, mb bool
	r.Before, ma = structuralMask(before, key, allowed, kind == "rule-provider")
	r.After, mb = structuralMask(after, key, allowed, kind == "rule-provider")
	r.Masked = ma || mb
	*changes = append(*changes, r)
}

func structuralNodeType(node *yaml.Node) string {
	if node == nil {
		return "absent"
	}
	if node.Kind == yaml.MappingNode {
		return "mapping"
	}
	if node.Kind == yaml.SequenceNode {
		return "sequence"
	}
	return node.Tag
}

func structuralUnified(before, after *ConfigObject, fields []StructuralFieldChange) string {
	show := func(object *ConfigObject) []string {
		if object == nil {
			return nil
		}
		raw, err := encode(mapNode(object.Value))
		if err != nil {
			return []string{"[display unavailable]"}
		}
		return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	}
	a, b := show(before), show(after)
	var out strings.Builder
	left, right := "/dev/null", "/dev/null"
	if before != nil {
		left = "destination" + before.ID
	}
	if after != nil {
		right = "source" + after.ID
	}
	fmt.Fprintf(&out, "--- %s\n+++ %s\n", left, right)
	if strings.Join(a, "\n") != strings.Join(b, "\n") {
		fmt.Fprintf(&out, "@@ -1,%d +1,%d @@\n", len(a), len(b))
		for _, line := range structuralLineDiff(a, b) {
			out.WriteString(line + "\n")
		}
	}
	for _, field := range fields {
		if field.Path == "/@resource" {
			fmt.Fprintf(&out, "# Authoritative provider content: %s (%v -> %v)\n", field.Operation, field.Before, field.After)
		}
		if field.Masked {
			fmt.Fprintf(&out, "# %s: %s (values hidden; compared before masking)\n", field.Path, field.Operation)
		}
		if field.BeforeType != field.AfterType {
			fmt.Fprintf(&out, "# %s type: %s -> %s\n", field.Path, field.BeforeType, field.AfterType)
		}
	}
	return core.Sanitize(out.String())
}

func structuralLineDiff(a, b []string) []string {
	if len(a)*len(b) > 250000 {
		out := []string{}
		for _, line := range a {
			out = append(out, "-"+line)
		}
		for _, line := range b {
			out = append(out, "+"+line)
		}
		return out
	}
	width := len(b) + 1
	dp := make([]int, (len(a)+1)*width)
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i*width+j] = dp[(i+1)*width+j+1] + 1
			} else {
				dp[i*width+j] = max(dp[(i+1)*width+j], dp[i*width+j+1])
			}
		}
	}
	out := []string{}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			out = append(out, " "+a[i])
			i++
			j++
		case i < len(a) && (j == len(b) || dp[(i+1)*width+j] >= dp[i*width+j+1]):
			out = append(out, "-"+a[i])
			i++
		default:
			out = append(out, "+"+b[j])
			j++
		}
	}
	return out
}

func FormatConfigDiff(diff ConfigDiff, format string) string {
	var out strings.Builder
	fmt.Fprintf(&out, "%s -> %s | source declarations | equal=%t\n", diff.SourceTargetID, diff.DestinationTargetID, diff.Equal)
	for _, row := range diff.Objects {
		if row.Status == "equal" {
			continue
		}
		label := row.Status
		if !row.Selectable {
			label += "; compare-only"
		}
		fmt.Fprintf(&out, "\n%s %s [%s]\n", row.Kind, row.Name, label)
		if format == "unified" {
			out.WriteString(row.Unified)
			continue
		}
		fmt.Fprintf(&out, "  ID: %s\n", row.ID)
		for _, field := range row.Fields {
			a, _ := json.Marshal(field.Before)
			b, _ := json.Marshal(field.After)
			fmt.Fprintf(&out, "  %s [%s] %s (%s) -> %s (%s)\n", field.Path, field.Operation, a, field.BeforeType, b, field.AfterType)
		}
		if row.OrderChanged {
			out.WriteString("  Relative rule order differs.\n")
		}
	}
	seenWarnings := map[string]bool{}
	for _, warning := range diff.Warnings {
		if seenWarnings[warning] {
			continue
		}
		seenWarnings[warning] = true
		fmt.Fprintf(&out, "Warning: %s\n", warning)
	}
	return core.Sanitize(out.String())
}
