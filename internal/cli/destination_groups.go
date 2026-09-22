package cli

import (
	"fmt"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
)

// One toggle per raw source group gives a real multi-selection without parsing
// display names as comma-separated text (names can themselves contain commas).
func destinationGroupFields(c configwork.Catalog, selected, create []string, allowCreate bool) []wizard.Field {
	wanted := map[string]bool{}
	for _, name := range selected {
		wanted[name] = true
	}
	fields := []wizard.Field{}
	for i, group := range c.Groups {
		value := "false"
		if wanted[group.Name] {
			value = "true"
			delete(wanted, group.Name)
		}
		fields = append(fields, wizard.Field{Key: fmt.Sprintf("destination_%d", i), Label: group.Name + " (" + group.Type + ")", Kind: wizard.Toggle, Value: value, Help: "Include these nodes in this existing group; provider references and filters are preserved."})
	}
	// Preserve an invalid supplied name so it receives a preview diagnostic,
	// instead of silently dropping a caller's requested destination.
	var unknown []string
	for _, name := range selected {
		if wanted[name] {
			unknown = append(unknown, name)
			delete(wanted, name)
		}
	}
	if len(unknown) > 0 {
		fields = append(fields, wizard.Field{Key: "unknown_groups", Label: "Unavailable requested groups (remove or correct)", Kind: wizard.Multiline, Value: strings.Join(unknown, "\n")})
	}
	if allowCreate {
		fields = append(fields, wizard.Field{Key: "create_groups", Label: "New select groups (one name per line; optional)", Kind: wizard.Multiline, Value: strings.Join(create, "\n"), Help: "Create groups containing these nodes in the same reviewed change. Use Groups → Edit for advanced group types; routing rules remain unchanged."})
	}
	return fields
}

func destinationGroupValues(c configwork.Catalog, values map[string]string) ([]string, []string) {
	var groups []string
	for i, g := range c.Groups {
		if values[fmt.Sprintf("destination_%d", i)] == "true" {
			groups = append(groups, g.Name)
		}
	}
	groups = append(groups, groupLines(values["unknown_groups"])...)
	return groups, groupLines(values["create_groups"])
}

func groupLines(value string) []string {
	var result []string
	for _, line := range strings.Split(value, "\n") {
		if name := strings.TrimSpace(line); name != "" {
			result = append(result, name)
		}
	}
	return result
}
