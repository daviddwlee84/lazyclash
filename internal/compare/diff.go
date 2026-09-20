package compare

import (
	"context"
	"slices"
	"sort"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

// Diff compares general runtime settings and group member sets. Health records,
// leaf-node attributes and automatic groups' changing choices are omitted.
// Redacted fields are reported as not compared, never claimed to be equal.
func Diff(ctx context.Context, source, destination config.Target, opts Options) (DiffResult, error) {
	result := DiffResult{Fields: []FieldDiff{}, Groups: []GroupDiff{}, NotCompared: []string{}}
	if err := validatePair(source, destination); err != nil {
		return result, err
	}
	src, err := open(ctx, source, true, opts)
	if err != nil {
		return result, err
	}
	defer src.close()
	dst, err := open(ctx, destination, true, opts)
	if err != nil {
		return result, err
	}
	defer dst.close()
	result.Source, err = read(ctx, src.client, source)
	if err != nil {
		return result, err
	}
	result.Destination, err = read(ctx, dst.client, destination)
	if err != nil {
		return result, err
	}
	result.NotCompared = uniqueSorted(append(append([]string{}, result.Source.RedactedFields...), result.Destination.RedactedFields...))
	diffFields("", map[string]any(result.Source.General), true, map[string]any(result.Destination.General), true, &result.Fields, &result.NotCompared)
	left, right := groupsByName(result.Source.Groups), groupsByName(result.Destination.Groups)
	names := map[string]bool{}
	for name := range left {
		names[name] = true
	}
	for name := range right {
		names[name] = true
	}
	for _, name := range sortedKeys(names) {
		sourceGroup, sourceOK := left[name]
		destinationGroup, destinationOK := right[name]
		difference := GroupDiff{Name: name, Differences: []string{}}
		if sourceOK {
			difference.Source = &sourceGroup
		}
		if destinationOK {
			difference.Destination = &destinationGroup
		}
		if !sourceOK || !destinationOK {
			difference.Differences = append(difference.Differences, "presence")
		} else {
			if sourceGroup.Type != destinationGroup.Type {
				difference.Differences = append(difference.Differences, "type")
			}
			if !slices.Equal(sourceGroup.Members, destinationGroup.Members) {
				difference.Differences = append(difference.Differences, "members")
			}
			if sourceGroup.Selected != destinationGroup.Selected {
				difference.Differences = append(difference.Differences, "selected")
			}
		}
		if len(difference.Differences) > 0 {
			result.Groups = append(result.Groups, difference)
		}
	}
	result.NotCompared = uniqueSorted(result.NotCompared)
	result.Equal = result.Source.Version == result.Destination.Version && len(result.Fields) == 0 && len(result.Groups) == 0
	return result, nil
}

func diffFields(path string, a any, aOK bool, b any, bOK bool, changes *[]FieldDiff, excluded *[]string) {
	if a == "[redacted]" || b == "[redacted]" {
		*excluded = append(*excluded, path)
		return
	}
	am, aMap := a.(map[string]any)
	bm, bMap := b.(map[string]any)
	if (aMap && (bMap || !bOK)) || (bMap && !aOK) {
		keys := map[string]bool{}
		for key := range am {
			keys[key] = true
		}
		for key := range bm {
			keys[key] = true
		}
		for _, key := range sortedKeys(keys) {
			av, ap := am[key]
			bv, bp := bm[key]
			diffFields(pointer(path, key), av, ap, bv, bp, changes, excluded)
		}
		return
	}
	var nested []string
	collectRedacted(a, path, &nested)
	collectRedacted(b, path, &nested)
	if len(nested) > 0 {
		*excluded = append(*excluded, path)
		return
	}
	if aOK != bOK || !equalJSON(a, b) {
		*changes = append(*changes, FieldDiff{Path: path, Source: a, Destination: b, SourcePresent: aOK, DestinationPresent: bOK})
	}
}

func groupsByName(groups []Group) map[string]Group {
	result := make(map[string]Group, len(groups))
	for _, group := range groups {
		result[group.Name] = group
	}
	return result
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
