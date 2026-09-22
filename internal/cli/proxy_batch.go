package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/spf13/cobra"
)

func readDestinations(cmd *cobra.Command, path string) ([]configwork.Destination, error) {
	if path == "-" {
		return nil, usage("--destinations requires a file; stdin is reserved for node input")
	}
	raw, err := boundedInput(cmd, path, "")
	if err != nil {
		return nil, err
	}
	var destinations []configwork.Destination
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&destinations) != nil || len(destinations) == 0 {
		return nil, usage("destinations must be a nonempty JSON array of target, groups and create_groups")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, usage("destinations must contain one JSON array")
	}
	seen := map[string]bool{}
	for _, d := range destinations {
		if d.TargetID == "" || seen[d.TargetID] {
			return nil, usage("destinations require unique nonempty target IDs")
		}
		seen[d.TargetID] = true
	}
	return destinations, nil
}

func (o *options) resolveDestinations(cmd *cobra.Command, req configwork.Request, destinations []configwork.Destination) (configwork.BatchRequest, error) {
	result := configwork.BatchRequest{Request: req}
	if globalChanged(cmd, "controller") || globalChanged(cmd, "ssh") {
		return result, usage("imports require saved targets; temporary connection overrides cannot be used")
	}
	if o.target == "" && (globalChanged(cmd, "secret-file") || globalChanged(cmd, "secret-env") || globalChanged(cmd, "ca-cert")) {
		return result, usage("credential overrides require --target; other destinations use their own saved credentials")
	}
	cfg, _, err := o.load(cmd)
	if err != nil {
		return result, err
	}
	for _, d := range destinations {
		i, err := targetIndex(cfg, d.TargetID)
		if err != nil {
			return result, err
		}
		d.Target = cfg.Targets[i]
		if d.TargetID == o.target {
			d.Target = o.overrideCredentials(d.Target)
		}
		result.Destinations = append(result.Destinations, d)
	}
	return result, nil
}

func (o *options) proxyBatchCommand(cmd *cobra.Command, req configwork.Request, path string, ui, yes bool, expected string) error {
	var destinations []configwork.Destination
	var err error
	if path != "" {
		destinations, err = readDestinations(cmd, path)
		if err != nil {
			return err
		}
	}
	if ui {
		if path != "" {
			if _, err := o.resolveDestinations(cmd, req, destinations); err != nil {
				return err
			}
		}
		return o.proxyImportWizard(cmd, req, destinations)
	}
	if len(req.Input) == 0 {
		return usage("import requires --file PATH, --uri LINK, or --interactive")
	}
	batch, err := o.resolveDestinations(cmd, req, destinations)
	if err != nil {
		return err
	}
	if yes {
		if err = o.writable(); err != nil {
			return err
		}
		// Never wrap a multi-write apply in authentication retry.
		r, err := configwork.ApplyBatch(cmd.Context(), batch, expected, o.configWorkOptions(cmd))
		if e := o.output(cmd, r); e != nil {
			return e
		}
		return err
	}
	p, err := o.previewImportBatch(cmd, batch)
	if err != nil {
		return err
	}
	return o.output(cmd, p)
}

// Several SSH hosts can independently require authentication. Retry only the
// read-only preview, and offer at most one authentication handoff per host.
func (o *options) previewImportBatch(cmd *cobra.Command, batch configwork.BatchRequest) (configwork.BatchPlan, error) {
	var p configwork.BatchPlan
	read := func() error {
		var err error
		p, err = configwork.PreviewBatch(cmd.Context(), batch, o.configWorkOptions(cmd))
		return err
	}
	err := read()
	attempted := map[string]bool{}
	for connection.IsAuthRequired(err) && !o.json && o.deps.Terminal(cmd.InOrStdin(), cmd.ErrOrStderr()) {
		var required *connection.AuthRequiredError
		if !errors.As(err, &required) || attempted[required.Host] {
			break
		}
		attempted[required.Host] = true
		initial, first := err, true
		err = o.authenticatedDiagnostic(cmd, config.Target{SSHHost: required.Host}, func() error {
			if first {
				first = false
				return initial
			}
			return read()
		})
	}
	return p, err
}

func validateImportDraft(req configwork.Request) error {
	defs, diagnostics, err := configwork.ParseImport(req.Input)
	if err != nil {
		return err
	}
	if len(diagnostics) > 0 {
		var messages []string
		for _, d := range diagnostics {
			messages = append(messages, fmt.Sprintf("line %d: %s", d.Index, d.Message))
		}
		return errors.New(strings.Join(messages, "; "))
	}
	if req.Action == "add" && len(defs) != 1 {
		return usage("add needs one node; use proxies import for several")
	}
	return nil
}

// This orchestrator owns drafts across individual terminal forms. Each form
// closes before a read, authentication handoff, or the next form starts.
func (o *options) proxyImportWizard(cmd *cobra.Command, req configwork.Request, initial []configwork.Destination) error {
	if err := o.writable(); err != nil {
		return err
	}
	if globalChanged(cmd, "controller") || globalChanged(cmd, "ssh") {
		return usage("save the target before importing its configuration")
	}
	if o.target == "" && (globalChanged(cmd, "secret-file") || globalChanged(cmd, "secret-env") || globalChanged(cmd, "ca-cert")) {
		return usage("credential overrides require --target; other destinations use their own saved credentials")
	}
	if o.target != "" {
		cfg, _, err := o.load(cmd)
		if err != nil {
			return err
		}
		if _, err = targetIndex(cfg, o.target); err != nil {
			return err
		}
	}
	drafts := map[string]configwork.Destination{}
	selected := []string{}
	for _, d := range initial {
		drafts[d.TargetID] = d
		selected = append(selected, d.TargetID)
	}
	if len(initial) == 0 && o.target != "" {
		selected = append(selected, o.target)
	}
	commonGroups, commonCreate := req.Groups, req.CreateGroups
	req.Groups, req.CreateGroups = nil, nil
	stage, pos := 0, 0
	problem := ""
	for {
		if err := cmd.Context().Err(); err != nil {
			return err
		}
		switch stage {
		case 0:
			fields := []wizard.Field{{Key: "input", Label: "Share links or YAML/JSON (contains credentials)", Kind: wizard.Multiline, Value: string(req.Input), Required: true}}
			if req.Action == "add" {
				fields = append(fields, wizard.Field{Key: "name", Label: "Override name (optional)", Value: req.Name})
			}
			values, err := wizard.EditDraft(cmd.Context(), wizard.Spec{Title: "Import proxies · input", Description: problem, SubmitLabel: "Choose targets", Fields: fields}, cmd.InOrStdin(), cmd.OutOrStdout())
			if err != nil {
				return err
			}
			req.Input = []byte(values["input"])
			if req.Action == "add" {
				req.Name = values["name"]
			}
			if err = validateImportDraft(req); err != nil {
				problem = err.Error()
				continue
			}
			problem = ""
			stage = 1
		case 1:
			cfg, _, err := o.load(cmd)
			if err != nil {
				return err
			}
			choices := []wizard.Choice{}
			available := map[string]bool{}
			for _, t := range cfg.Targets {
				if t.Transient || t.TransportOverride {
					continue
				}
				label := t.ID + " · " + t.Label()
				if t.ConfigSource == nil {
					label += " · source not bound"
				}
				choices = append(choices, wizard.Choice{Value: t.ID, Label: label})
				available[t.ID] = true
			}
			if len(choices) == 0 {
				return usage("no saved targets; register one with targets add before importing")
			}
			for _, id := range selected {
				if !available[id] {
					choices = append(choices, wizard.Choice{Value: id, Label: id + " · unavailable; deselect to continue"})
				}
			}
			ids, err := wizard.MultiChoose(cmd.Context(), wizard.MultiSpec{Title: "Import proxies · targets", Description: problem, Choices: choices, Selected: selected, Back: true}, cmd.InOrStdin(), cmd.OutOrStdout())
			selected = ids
			if errors.Is(err, wizard.ErrBack) {
				stage = 0
				continue
			}
			if err != nil {
				return err
			}
			for _, id := range selected {
				if _, ok := drafts[id]; !ok {
					drafts[id] = configwork.Destination{TargetID: id, Groups: append([]string(nil), commonGroups...), CreateGroups: append([]string(nil), commonCreate...)}
				}
			}
			problem = ""
			stage, pos = 2, 0
		case 2:
			id := selected[pos]
			d := drafts[id]
			batch, err := o.resolveDestinations(cmd, req, []configwork.Destination{d})
			if err != nil {
				problem = err.Error()
				stage = 1
				continue
			}
			t := batch.Destinations[0].Target
			if t.ConfigSource == nil {
				choice, err := wizard.Choose(cmd.Context(), "Bind a source for "+id, []wizard.Choice{{Value: "bind", Label: "Bind configuration source"}, {Value: "back", Label: "Back to targets"}, {Value: "cancel", Label: "Cancel import"}}, cmd.InOrStdin(), cmd.OutOrStdout())
				if err != nil {
					return err
				}
				if choice == "cancel" {
					return wizard.ErrCanceled
				}
				if choice == "back" {
					stage = 1
					continue
				}
				if err = o.bindImportSource(cmd, id); err != nil {
					if errors.Is(err, wizard.ErrCanceled) {
						stage = 1
						continue
					}
					return err
				}
				continue
			}
			var catalog configwork.Catalog
			fmt.Fprintf(cmd.ErrOrStderr(), "Reading groups for %s…\n", core.Sanitize(id))
			err = o.authenticatedDiagnostic(cmd, t, func() error {
				var e error
				catalog, e = configwork.Inspect(cmd.Context(), t, o.configWorkOptions(cmd))
				return e
			})
			if err != nil {
				problem = err.Error()
				stage = 1
				continue
			}
			choices := []wizard.Choice{}
			found := map[string]bool{}
			for _, g := range catalog.Groups {
				choices = append(choices, wizard.Choice{Value: g.Name, Label: g.Name + " (" + g.Type + ")"})
				found[g.Name] = true
			}
			for _, name := range d.Groups {
				if !found[name] {
					choices = append(choices, wizard.Choice{Value: name, Label: name + " (unavailable; deselect or correct)"})
				}
			}
			groups, err := wizard.MultiChoose(cmd.Context(), wizard.MultiSpec{Title: "Import proxies · " + id + " · groups", Description: problem, Choices: choices, Selected: d.Groups, AllowEmpty: true, Back: true}, cmd.InOrStdin(), cmd.OutOrStdout())
			d.Groups = groups
			drafts[id] = d
			if errors.Is(err, wizard.ErrBack) {
				pos--
				if pos < 0 {
					stage = 1
				}
				continue
			}
			if err != nil {
				return err
			}
			values, err := wizard.EditDraft(cmd.Context(), wizard.Spec{Title: "Import proxies · " + id + " · new groups", Description: "Optional select groups. Parent groups and routing rules stay as configured.", SubmitLabel: "Next", Back: true, Fields: []wizard.Field{{Key: "create", Label: "New group names (one per line; optional)", Kind: wizard.Multiline, Value: strings.Join(d.CreateGroups, "\n")}}}, cmd.InOrStdin(), cmd.OutOrStdout())
			if values != nil {
				d.CreateGroups = groupLines(values["create"])
				drafts[id] = d
			}
			if errors.Is(err, wizard.ErrBack) {
				continue
			}
			if err != nil {
				return err
			}
			problem = ""
			pos++
			if pos == len(selected) {
				stage = 3
			}
		case 3:
			destinations := []configwork.Destination{}
			for _, id := range selected {
				destinations = append(destinations, drafts[id])
			}
			batch, err := o.resolveDestinations(cmd, req, destinations)
			if err != nil {
				problem = err.Error()
				stage = 1
				continue
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "Validating all destinations before review…")
			preview, err := o.previewImportBatch(cmd, batch)
			if err != nil {
				problem = err.Error()
				stage, pos = 2, len(selected)-1
				continue
			}
			accepted, err := wizard.ConfirmBack(cmd.Context(), "Apply proxy import to selected targets", configwork.BatchWarningsText(preview), cmd.InOrStdin(), cmd.OutOrStdout())
			if err != nil {
				return err
			}
			if !accepted {
				stage, pos = 2, len(selected)-1
				continue
			}
			// Reload registrations after review, retaining the reviewed digest.
			batch, err = o.resolveDestinations(cmd, req, destinations)
			if err != nil {
				return err
			}
			result, err := configwork.ApplyBatch(cmd.Context(), batch, preview.Digest, o.configWorkOptions(cmd))
			if e := o.output(cmd, result); e != nil {
				return e
			}
			return err
		}
	}
}

func (o *options) bindImportSource(cmd *cobra.Command, id string) error {
	_, path, err := o.load(cmd)
	if err != nil {
		return err
	}
	args := []string{"--config", path, "--target", id}
	if id == o.target {
		for _, flag := range []struct{ name, value string }{{"--secret-file", o.secretFile}, {"--secret-env", o.secretEnv}, {"--ca-cert", o.caFile}} {
			if flag.value != "" {
				args = append(args, flag.name, flag.value)
			}
		}
	}
	args = append(args, "configs", "source", "set", "--interactive")
	child := New(o.deps)
	child.SetArgs(args)
	child.SetIn(cmd.InOrStdin())
	child.SetOut(cmd.OutOrStdout())
	child.SetErr(cmd.ErrOrStderr())
	return child.ExecuteContext(cmd.Context())
}
