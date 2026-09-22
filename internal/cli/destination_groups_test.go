package cli

import (
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"testing"
)

func TestDestinationGroupSelectionPreservesNamesAndMissingInputs(t *testing.T) {
	c := configwork.Catalog{Groups: []configwork.Definition{{Name: "東京, private", Type: "select"}, {Name: "Auto", Type: "url-test"}}}
	fields := destinationGroupFields(c, []string{"東京, private", "missing"}, []string{"New, group"}, true)
	values := map[string]string{}
	for _, f := range fields {
		values[f.Key] = f.Value
	}
	groups, create := destinationGroupValues(c, values)
	if len(groups) != 2 || groups[0] != "東京, private" || groups[1] != "missing" || len(create) != 1 || create[0] != "New, group" {
		t.Fatal(groups, create)
	}
	values["destination_0"] = "false"
	values["destination_1"] = "true"
	values["unknown_groups"] = ""
	groups, _ = destinationGroupValues(c, values)
	if len(groups) != 1 || groups[0] != "Auto" {
		t.Fatal(groups)
	}
}
