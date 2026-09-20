package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
	"strconv"
	"strings"
)

func (o *options) groupsCommand() *cobra.Command {
	group := &cobra.Command{Use: "groups", Short: "Inspect and persistently edit raw policy-group definitions"}
	group.AddCommand(&cobra.Command{Use: "list", Short: "List source groups without flattening providers or filters", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		defer connection.CloseAuthentications()
		t, e := o.configWorkTarget(cmd)
		if e != nil {
			return e
		}
		var catalog configwork.Catalog
		e = o.authenticatedDiagnostic(cmd, t, func() error {
			var err error
			catalog, err = configwork.Inspect(cmd.Context(), t, o.configWorkOptions(cmd))
			return err
		})
		if e != nil {
			return e
		}
		return o.output(cmd, map[string]any{"groups": catalog.Groups, "warnings": catalog.Warnings})
	}}, o.sourceMutationCommand("group", "add"), o.sourceMutationCommand("group", "edit"), o.sourceMutationCommand("group", "duplicate"))
	return group
}

// Common fields are a view onto the original YAML, not a lossy replacement
// struct. An explicit advanced editor remains available in the same flow.
func (o *options) groupWizard(cmd *cobra.Command, t config.Target, req configwork.Request, catalog configwork.Catalog) error {
	base := req.Input
	if req.Action == "edit" || req.Action == "duplicate" {
		definition, err := configwork.ReadDefinition(cmd.Context(), t, "group", req.Name, o.configWorkOptions(cmd))
		if err != nil {
			return err
		}
		original, err := definition.Raw()
		if err != nil {
			return err
		}
		if len(base) == 0 {
			base = original
		} else {
			var patch map[string]any
			if yaml.Unmarshal(base, &patch) != nil {
				return usage("invalid group YAML")
			}
			base, err = configwork.PatchDefinition(original, patch, nil)
			if err != nil {
				return err
			}
		}
	}
	var values map[string]any
	if len(base) > 0 {
		if yaml.Unmarshal(base, &values) != nil || values == nil {
			return usage("group input must be a YAML mapping")
		}
	}
	if values == nil {
		values = map[string]any{}
	}
	text := func(key string) string {
		if values[key] == nil {
			return ""
		}
		return fmt.Sprint(values[key])
	}
	mode, err := wizard.Choose(cmd.Context(), "Group editor", []wizard.Choice{{Value: "fields", Label: "Common group fields"}, {Value: "raw", Label: "Advanced YAML (all fields)"}}, cmd.InOrStdin(), cmd.OutOrStdout())
	if err != nil {
		return err
	}
	if mode == "raw" {
		return o.rawGroupWizard(cmd, t, req, base)
	}
	name := text("name")
	if req.Action == "add" && req.Name != "" {
		name = req.Name
	}
	if req.Action == "duplicate" {
		name = req.NewName
		if name == "" {
			name = req.Name + " copy"
		}
	}
	typ := text("type")
	if typ == "" {
		typ = "select"
	}
	choices := []wizard.Choice{{Value: "select", Label: "Manual select"}, {Value: "url-test", Label: "Automatic latency"}, {Value: "fallback", Label: "Ordered failover"}, {Value: "load-balance", Label: "Load balance"}}
	if typ == "relay" {
		choices = append(choices, wizard.Choice{Value: "relay", Label: "Existing relay (legacy)"})
	}
	members := func(key string) string {
		var list []string
		switch v := values[key].(type) {
		case []any:
			for _, n := range v {
				list = append(list, fmt.Sprint(n))
			}
		case []string:
			list = v
		}
		return strings.Join(list, "\n")
	}
	fields := []wizard.Field{
		{Key: "name", Label: "Name", Value: name, Required: true, Help: "Existing group names stay fixed; use Duplicate for a new group."},
		{Key: "type", Label: "Group type", Kind: wizard.Select, Value: typ, Options: choices, Required: true},
		{Key: "proxies", Label: "Ordered proxies / groups (one per line)", Kind: wizard.Multiline, Value: members("proxies"), Help: "Order is preserved. Known: " + strings.Join(configwork.SortedNames(catalog.Proxies), ", ")},
		{Key: "use", Label: "Providers (one per line)", Kind: wizard.Multiline, Value: members("use"), Help: "Provider names remain references; expanded runtime membership is never written here."},
		{Key: "filter", Label: "Include regex", Value: text("filter")},
		{Key: "exclude-filter", Label: "Exclude regex", Value: text("exclude-filter")},
		{Key: "exclude-type", Label: "Excluded node types", Value: text("exclude-type")},
		{Key: "url", Label: "Latency test URL", Value: text("url")},
		{Key: "interval", Label: "Test interval (seconds)", Value: text("interval")},
		{Key: "timeout", Label: "Test timeout (milliseconds)", Value: text("timeout")},
		{Key: "tolerance", Label: "URL-test tolerance (milliseconds)", Value: text("tolerance")},
		{Key: "strategy", Label: "Load-balance strategy", Value: text("strategy"), Help: "round-robin, consistent-hashing, sticky-sessions; leave blank for the core default."},
	}
	description := "Only edited common fields change. Unknown YAML options and comments remain. Raw YAML is available from Back / re-enter editor."
	for {
		draft, e := wizard.Edit(cmd.Context(), wizard.Spec{Title: strings.Title(req.Action) + " group", Description: description, SubmitLabel: "Preview", Fields: fields}, cmd.InOrStdin(), cmd.OutOrStdout())
		if e != nil {
			return e
		}
		for i := range fields {
			fields[i].Value = draft[fields[i].Key]
		}
		candidate, e := commonGroupDraft(base, values, draft)
		if e != nil {
			description = e.Error()
			continue
		}
		next := req
		next.Input = candidate
		next.Replace = true
		if req.Action == "duplicate" {
			next.NewName = draft["name"]
		} else if req.Action == "add" {
			next.Name = draft["name"]
		}
		plan, e := configwork.Preview(cmd.Context(), t, next, o.configWorkOptions(cmd))
		if e != nil {
			description = e.Error()
			continue
		}
		accepted, e := wizard.Confirm(cmd.Context(), "Review persistent group change", configwork.WarningsText(plan), cmd.InOrStdin(), cmd.OutOrStdout())
		if e != nil {
			return e
		}
		if !accepted {
			return wizard.ErrCanceled
		}
		if e = o.writable(); e != nil {
			return e
		}
		receipt, e := configwork.Apply(cmd.Context(), t, next, plan.Digest, o.configWorkOptions(cmd))
		if e != nil && receipt.ID == "" {
			description = e.Error()
			continue
		}
		if receipt.ID != "" {
			if outputErr := o.output(cmd, receipt); outputErr != nil {
				return outputErr
			}
		}
		return e
	}
}
func commonGroupDraft(base []byte, original map[string]any, draft map[string]string) ([]byte, error) {
	fields := map[string]any{}
	var remove []string
	for _, key := range []string{"name", "type", "proxies", "use", "filter", "exclude-filter", "exclude-type", "url", "interval", "timeout", "tolerance", "strategy"} {
		value := draft[key]
		var next any
		switch key {
		case "name", "type":
			if value == "" {
				return nil, fmt.Errorf("%s is required", key)
			}
			next = value
		case "proxies", "use":
			var names []string
			for _, line := range strings.Split(value, "\n") {
				if line = strings.TrimSpace(line); line != "" {
					names = append(names, line)
				}
			}
			if len(names) == 0 {
				if _, ok := original[key]; ok {
					remove = append(remove, key)
				}
				continue
			}
			next = names
		case "interval", "timeout", "tolerance":
			if value == "" {
				if _, ok := original[key]; ok {
					remove = append(remove, key)
				}
				continue
			}
			number, e := strconv.Atoi(value)
			if e != nil || number < 0 {
				return nil, fmt.Errorf("%s must be a non-negative integer", key)
			}
			next = number
		default:
			if value == "" {
				if _, ok := original[key]; ok {
					remove = append(remove, key)
				}
				continue
			}
			next = value
		}
		if key == "strategy" && value != "" {
			switch value {
			case "round-robin", "consistent-hashing", "sticky-sessions":
			default:
				return nil, errors.New("unsupported load-balance strategy; use Advanced YAML for core-specific options")
			}
		}
		a, _ := json.Marshal(original[key])
		b, _ := json.Marshal(next)
		if string(a) != string(b) {
			fields[key] = next
		}
	}
	return configwork.PatchDefinition(base, fields, remove)
}
func (o *options) rawGroupWizard(cmd *cobra.Command, t config.Target, req configwork.Request, base []byte) error {
	fields := []wizard.Field{{Key: "yaml", Label: "Complete group YAML", Kind: wizard.Multiline, Value: string(base), Required: true}}
	if req.Action == "duplicate" {
		fields = append(fields, wizard.Field{Key: "name", Label: "New name", Value: req.NewName, Required: true})
	}
	description := "The complete YAML replaces this group only; unrelated source definitions remain."
	for {
		draft, e := wizard.Edit(cmd.Context(), wizard.Spec{Title: "Advanced group editor", Description: description, SubmitLabel: "Preview", Fields: fields}, cmd.InOrStdin(), cmd.OutOrStdout())
		if e != nil {
			return e
		}
		for i := range fields {
			fields[i].Value = draft[fields[i].Key]
		}
		req.Input = []byte(draft["yaml"])
		req.Replace = true
		if req.Action == "duplicate" {
			req.NewName = draft["name"]
		}
		plan, e := configwork.Preview(cmd.Context(), t, req, o.configWorkOptions(cmd))
		if e != nil {
			description = e.Error()
			continue
		}
		accepted, e := wizard.Confirm(cmd.Context(), "Review persistent group change", configwork.WarningsText(plan), cmd.InOrStdin(), cmd.OutOrStdout())
		if e != nil {
			return e
		}
		if !accepted {
			return wizard.ErrCanceled
		}
		if e = o.writable(); e != nil {
			return e
		}
		receipt, e := configwork.Apply(cmd.Context(), t, req, plan.Digest, o.configWorkOptions(cmd))
		if e != nil && receipt.ID == "" {
			description = e.Error()
			continue
		}
		if receipt.ID != "" {
			if outputErr := o.output(cmd, receipt); outputErr != nil {
				return outputErr
			}
		}
		return e
	}
}
