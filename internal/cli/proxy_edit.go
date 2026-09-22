package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/atotto/clipboard"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func boundedInput(cmd *cobra.Command, file, uri string) ([]byte, error) {
	if file != "" && uri != "" {
		return nil, usage("--file and --uri are mutually exclusive")
	}
	if uri != "" {
		return []byte(uri), nil
	}
	if file == "" {
		return nil, nil
	}
	var reader io.Reader
	if file == "-" {
		reader = cmd.InOrStdin()
	} else {
		f, e := os.Open(file)
		if e != nil {
			return nil, errors.New("cannot open definition input")
		}
		defer f.Close()
		reader = f
	}
	data, e := io.ReadAll(io.LimitReader(reader, configwork.MaxDocument+1))
	if e != nil {
		return nil, errors.New("cannot read definition input")
	}
	if len(data) > configwork.MaxDocument {
		return nil, usage("input exceeds 8 MiB")
	}
	return data, nil
}
func (o *options) definitionEditor(cmd *cobra.Command, data []byte) ([]byte, error) {
	if o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout()) {
		return nil, usage("--editor requires a terminal and cannot use --json")
	}
	value := os.Getenv("VISUAL")
	if strings.TrimSpace(value) == "" {
		value = os.Getenv("EDITOR")
	}
	if strings.TrimSpace(value) == "" {
		value = "vi"
	}
	args, e := editorArguments(value)
	if e != nil {
		return nil, e
	}
	binary, e := exec.LookPath(args[0])
	if e != nil {
		return nil, errors.New("editor executable is unavailable")
	}
	dir, e := os.MkdirTemp("", "lazyclash-definition-")
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(dir)
	_ = os.Chmod(dir, 0700)
	path := filepath.Join(dir, "definition.yaml")
	if e = os.WriteFile(path, data, 0600); e != nil {
		return nil, e
	}
	child := exec.CommandContext(cmd.Context(), binary, append(args[1:], path)...)
	child.Stdin, child.Stdout, child.Stderr = cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()
	if e = o.deps.RunEditor(child); e != nil {
		return nil, e
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, configwork.MaxDocument+1))
	if e != nil {
		return nil, e
	}
	if len(raw) > configwork.MaxDocument {
		return nil, usage("edited definition exceeds 8 MiB")
	}
	return raw, nil
}
func (o *options) sourceMutationCommand(kind, action string) *cobra.Command {
	var file, uri, newName, expected, destinations string
	var groups, createGroups []string
	var yes, interactive, editor, adoptExisting bool
	use := action + " [NAME]"
	if action == "import" {
		use = "import"
	}
	c := &cobra.Command{Use: use, Short: map[string]string{"add": "Add a persistent source definition", "import": "Import all nodes from share links or YAML/JSON", "edit": "Edit a persistent definition without dropping unknown fields", "duplicate": "Duplicate a raw source definition under a new name"}[action]}
	c.Args = func(cmd *cobra.Command, args []string) error {
		max := 1
		if action == "import" {
			max = 0
		}
		if len(args) > max {
			return usage("too many arguments")
		}
		return nil
	}
	c.RunE = func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if destinations != "" && (globalChanged(cmd, "target") || cmd.Flags().Changed("group") || cmd.Flags().Changed("create-group")) {
			return usage("--destinations supplies each target and its groups; it cannot be combined with --target, --group or --create-group")
		}
		if yes && expected == "" {
			return usage("--yes requires --expect DIGEST")
		}
		if !yes && expected != "" {
			return usage("--expect requires --yes")
		}
		if editor && action != "edit" {
			return usage("--editor is only supported by edit")
		}
		business := len(args) > 0
		cmd.LocalNonPersistentFlags().Visit(func(f *pflag.Flag) {
			if f.Name != "interactive" {
				business = true
			}
		})
		multi := kind == "proxy" && (action == "add" || action == "import")
		autoTargets := multi && destinations == "" && !globalChanged(cmd, "target") && !yes && expected == ""
		ui, e := o.sourceInteractive(cmd, interactive, !business || autoTargets)
		if e != nil {
			return e
		}
		input, e := boundedInput(cmd, file, uri)
		if e != nil {
			return e
		}
		req := configwork.Request{Kind: kind, Action: action, Input: input, NewName: newName, Groups: groups, CreateGroups: createGroups, AdoptExisting: adoptExisting}
		if len(args) > 0 {
			req.Name = args[0]
		}
		if multi && (ui || destinations != "") {
			return o.proxyBatchCommand(cmd, req, destinations, ui, yes, expected)
		}
		t, e := o.configWorkTarget(cmd)
		if e != nil {
			return e
		}
		var catalog configwork.Catalog
		// Noninteractive input reaches Preview's capability gate before source
		// discovery, so an incompatible classic core receives its real error.
		if ui || editor {
			e = o.authenticatedDiagnostic(cmd, t, func() error {
				var err error
				catalog, err = configwork.Inspect(cmd.Context(), t, o.configWorkOptions(cmd))
				return err
			})
			if e != nil {
				return e
			}
		}
		if (action == "edit" || action == "duplicate") && req.Name == "" {
			if !ui {
				return usage("%s requires NAME; use --interactive for a picker", action)
			}
			items := catalog.Proxies
			if kind == "group" {
				items = catalog.Groups
			}
			choices := []wizard.Choice{}
			for _, d := range items {
				choices = append(choices, wizard.Choice{Value: d.Name, Label: d.Name + " (" + d.Type + ")"})
			}
			if len(choices) == 0 {
				return usage("the bound source has no %s definitions", kind)
			}
			req.Name, e = wizard.Choose(cmd.Context(), "Select source "+kind, choices, cmd.InOrStdin(), cmd.OutOrStdout())
			if e != nil {
				return e
			}
		}
		if editor {
			d, e := configwork.ReadDefinition(cmd.Context(), t, kind, req.Name, o.configWorkOptions(cmd))
			if e != nil {
				return e
			}
			raw, e := d.Raw()
			if e != nil {
				return e
			}
			req.Input, e = o.definitionEditor(cmd, raw)
			if e != nil {
				return e
			}
			req.Replace = true
			ui = true
		}
		if !ui {
			if (action == "add" || action == "import" || action == "edit") && len(req.Input) == 0 {
				return usage("%s requires --file PATH (or - for stdin), --uri for a node link, or --interactive", action)
			}
			if action == "duplicate" && newName == "" {
				return usage("duplicate requires --name NEW_NAME")
			}
		}
		if ui && !editor && kind == "group" {
			return o.groupWizard(cmd, t, req, catalog)
		}
		if ui && !editor {
			if action == "edit" && len(req.Input) == 0 {
				d, e := configwork.ReadDefinition(cmd.Context(), t, kind, req.Name, o.configWorkOptions(cmd))
				if e != nil {
					return e
				}
				req.Input, e = d.Raw()
				if e != nil {
					return e
				}
				req.Replace = true
			}
			fields := []wizard.Field{}
			if action == "duplicate" {
				fields = append(fields, wizard.Field{Key: "name", Label: "New unique name", Value: req.NewName, Required: true})
			} else {
				fields = append(fields, wizard.Field{Key: "input", Label: "Share link or raw YAML/JSON (contains credentials)", Kind: wizard.Multiline, Value: string(req.Input), Required: true})
				if action == "add" {
					fields = append(fields, wizard.Field{Key: "name", Label: "Override name (optional)", Value: req.Name})
				}
			}
			if kind == "proxy" {
				fields = append(fields, destinationGroupFields(catalog, req.Groups, req.CreateGroups, action != "edit")...)
			}
			description := "Unknown YAML fields are preserved. Review contains names and fingerprints, never credential values."
			for {
				values, err := wizard.Edit(cmd.Context(), wizard.Spec{Title: strings.Title(action) + " " + kind, Description: description, SubmitLabel: "Preview", Fields: fields}, cmd.InOrStdin(), cmd.OutOrStdout())
				if err != nil {
					return err
				}
				for i := range fields {
					fields[i].Value = values[fields[i].Key]
				}
				if action == "duplicate" {
					req.NewName = values["name"]
				} else {
					req.Input = []byte(values["input"])
					if action == "add" {
						req.Name = values["name"]
					}
				}
				req.Groups, req.CreateGroups = destinationGroupValues(catalog, values)
				p, err := configwork.Preview(cmd.Context(), t, req, o.configWorkOptions(cmd))
				if err != nil {
					description = err.Error()
					continue
				}
				accepted, err := wizard.Confirm(cmd.Context(), "Apply persistent source change", configwork.WarningsText(p)+"\nDigest: "+p.Digest, cmd.InOrStdin(), cmd.OutOrStdout())
				if err != nil {
					return err
				}
				if !accepted {
					return wizard.ErrCanceled
				}
				if e = o.writable(); e != nil {
					return e
				}
				r, err := configwork.Apply(cmd.Context(), t, req, p.Digest, o.configWorkOptions(cmd))
				if err != nil && r.ID == "" {
					description = err.Error()
					continue
				}
				if r.ID != "" {
					if outErr := o.output(cmd, r); outErr != nil {
						return outErr
					}
				}
				return err
			}
		}
		p, e := configwork.Preview(cmd.Context(), t, req, o.configWorkOptions(cmd))
		for e != nil && editor {
			fmt.Fprintln(cmd.ErrOrStderr(), "Draft was not applied:", e)
			req.Input, e = o.definitionEditor(cmd, req.Input)
			if e != nil {
				return e
			}
			p, e = configwork.Preview(cmd.Context(), t, req, o.configWorkOptions(cmd))
		}
		if e != nil {
			return e
		}
		if editor {
			accept, err := wizard.Confirm(cmd.Context(), "Apply edited source definition", configwork.WarningsText(p), cmd.InOrStdin(), cmd.OutOrStdout())
			if err != nil {
				return err
			}
			if !accept {
				return wizard.ErrCanceled
			}
			yes = true
			expected = p.Digest
		}
		if !yes {
			return o.output(cmd, p)
		}
		if e = o.writable(); e != nil {
			return e
		}
		if p.Digest != expected {
			return usage("preview changed; review the current source")
		}
		r, e := configwork.Apply(cmd.Context(), t, req, expected, o.configWorkOptions(cmd))
		if e != nil && r.ID == "" && editor {
			if path, keepErr := retainDefinitionDraft(req.Input); keepErr == nil {
				return fmt.Errorf("%w (private draft retained at %s)", e, path)
			}
		}
		if r.ID != "" {
			if err := o.output(cmd, r); err != nil {
				return err
			}
		}
		return e
	}
	c.Flags().StringVar(&file, "file", "", "node/group YAML/JSON file or '-' for stdin")
	if kind == "proxy" {
		c.Flags().StringVar(&uri, "uri", "", "share link (prefer --file - to keep credentials out of shell history)")
		c.Flags().StringSliceVar(&groups, "group", nil, "existing source group(s) to include the new node")
		if action != "edit" {
			c.Flags().StringArrayVar(&createGroups, "create-group", nil, "new select group containing the imported nodes (repeatable)")
		}
		if action == "import" {
			c.Flags().BoolVar(&adoptExisting, "adopt-existing", false, "reuse identical existing nodes; differing definitions remain conflicts")
		}
		if action == "add" || action == "import" {
			c.Flags().StringVar(&destinations, "destinations", "", "JSON file of per-target groups for a reviewed batch import")
		}
	}
	c.Flags().StringVar(&newName, "name", "", "explicit new name for duplicate or add")
	c.Flags().BoolVar(&yes, "yes", false, "apply the reviewed digest")
	c.Flags().StringVar(&expected, "expect", "", "exact preview digest")
	c.Flags().BoolVar(&interactive, "interactive", false, "open a prefilled source editor and final review")
	if action == "edit" {
		c.Flags().BoolVar(&editor, "editor", false, "edit a private draft with VISUAL/EDITOR, then review")
	}
	return c
}
func splitNames(raw string) []string {
	var out []string
	for _, v := range strings.Split(raw, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
func (o *options) proxyEditCommands() []*cobra.Command {
	return []*cobra.Command{o.sourceMutationCommand("proxy", "add"), o.sourceMutationCommand("proxy", "import"), o.sourceMutationCommand("proxy", "edit"), o.sourceMutationCommand("proxy", "duplicate"), o.proxyCopyCommand(), o.proxyExportCommand()}
}
func (o *options) proxyCopyCommand() *cobra.Command {
	var newName, expected string
	var groups []string
	var yes, interactive bool
	c := &cobra.Command{Use: "copy [SOURCE DEST NAME]", Short: "Copy a raw source node across owners; selected-target wizard: copy NAME --interactive"}
	c.Args = func(cmd *cobra.Command, args []string) error {
		if len(args) > 3 {
			return usage("copy accepts SOURCE DEST NAME, or NAME --interactive")
		}
		return nil
	}
	c.RunE = func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if yes && expected == "" {
			return usage("--yes requires --expect DIGEST")
		}
		if !yes && expected != "" {
			return usage("--expect requires --yes")
		}
		ui, e := o.sourceInteractive(cmd, interactive, len(args) == 0 && !cmd.Flags().Changed("name") && !cmd.Flags().Changed("group") && !yes)
		if e != nil {
			return e
		}
		var from, to config.Target
		var name string
		if len(args) == 3 {
			from, to, e = o.comparisonTargets(cmd, args[:2])
			if e != nil {
				return e
			}
			name = args[2]
		} else {
			if !ui {
				return usage("copy requires SOURCE DEST NAME or --interactive")
			}
			from, e = o.configWorkTarget(cmd)
			if e != nil {
				return e
			}
			cfg, _, e := o.load(cmd)
			if e != nil {
				return e
			}
			choices := []wizard.Choice{}
			for _, t := range cfg.Targets {
				if t.ConfigSource != nil {
					choices = append(choices, wizard.Choice{Value: t.ID, Label: t.Label()})
				}
			}
			if len(choices) == 0 {
				return usage("bind a destination config source before copying")
			}
			id, e := wizard.Choose(cmd.Context(), "Copy destination", choices, cmd.InOrStdin(), cmd.OutOrStdout())
			if e != nil {
				return e
			}
			index, e := targetIndex(cfg, id)
			if e != nil {
				return e
			}
			to = cfg.Targets[index]
			if len(args) == 1 {
				name = args[0]
			} else if len(args) != 0 {
				return usage("interactive copy accepts one source node name")
			}
		}
		var source configwork.Catalog
		e = o.authenticatedDiagnostic(cmd, from, func() error {
			var err error
			source, err = configwork.Inspect(cmd.Context(), from, o.configWorkOptions(cmd))
			return err
		})
		if e != nil {
			return e
		}
		if name == "" {
			choices := []wizard.Choice{}
			for _, n := range source.Proxies {
				choices = append(choices, wizard.Choice{Value: n.Name, Label: n.Name + " (" + n.Type + ")"})
			}
			if len(choices) == 0 {
				return usage("source has no raw node definitions")
			}
			name, e = wizard.Choose(cmd.Context(), "Copy node", choices, cmd.InOrStdin(), cmd.OutOrStdout())
			if e != nil {
				return e
			}
		}
		var dest configwork.Catalog
		e = o.authenticatedDiagnostic(cmd, to, func() error {
			var err error
			dest, err = configwork.Inspect(cmd.Context(), to, o.configWorkOptions(cmd))
			return err
		})
		if e != nil {
			return e
		}
		description := "Source: " + from.ID + "; destination: " + to.ID + ". Existing names are never overwritten. Credential values remain hidden."
		if newName == "" {
			newName = name
			if from.ID == to.ID {
				newName = name + " copy"
			}
		}
		for {
			if ui {
				vals, err := wizard.Edit(cmd.Context(), wizard.Spec{Title: "Copy source node", Description: description, SubmitLabel: "Preview", Fields: []wizard.Field{{Key: "name", Label: "Destination name", Value: newName, Required: true}, {Key: "groups", Label: "Groups (comma-separated)", Value: strings.Join(groups, ","), Help: "Available: " + strings.Join(configwork.SortedNames(dest.Groups), ", ")}}}, cmd.InOrStdin(), cmd.OutOrStdout())
				if err != nil {
					return err
				}
				newName = vals["name"]
				groups = splitNames(vals["groups"])
			}
			p, req, err := configwork.PreviewCopy(cmd.Context(), from, to, name, newName, groups, o.configWorkOptions(cmd))
			if err != nil {
				if ui {
					description = err.Error()
					continue
				}
				return err
			}
			if ui {
				accepted, err := wizard.Confirm(cmd.Context(), "Copy persistent node", configwork.WarningsText(p), cmd.InOrStdin(), cmd.OutOrStdout())
				if err != nil {
					return err
				}
				if !accepted {
					return wizard.ErrCanceled
				}
				yes = true
				expected = p.Digest
			}
			if !yes {
				return o.output(cmd, p)
			}
			if err = o.writable(); err != nil {
				return err
			}
			if p.Digest != expected {
				return usage("source/destination changed; prepare a fresh copy preview")
			}
			r, err := configwork.Apply(cmd.Context(), to, req, expected, o.configWorkOptions(cmd))
			if err != nil && r.ID == "" && ui {
				description = err.Error()
				continue
			}
			if r.ID != "" {
				if e := o.output(cmd, r); e != nil {
					return e
				}
			}
			return err
		}
	}
	c.Flags().StringVar(&newName, "name", "", "new destination name")
	c.Flags().StringSliceVar(&groups, "group", nil, "destination source groups")
	c.Flags().BoolVar(&yes, "yes", false, "apply this copy")
	c.Flags().StringVar(&expected, "expect", "", "reviewed copy digest")
	c.Flags().BoolVar(&interactive, "interactive", false, "choose destination, node, membership and review")
	return c
}
func (o *options) proxyExportCommand() *cobra.Command {
	var format, output string
	var clip, qr, interactive bool
	c := &cobra.Command{Use: "export [NAME]", Short: "Explicitly export credential-bearing source node as YAML/JSON, URL or QR"}
	c.Args = func(cmd *cobra.Command, args []string) error {
		if len(args) > 1 {
			return usage("export accepts one node name")
		}
		return nil
	}
	c.RunE = func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if format != "yaml" && format != "json" && format != "url" {
			return usage("--format must be yaml, json or url")
		}
		if clip && output != "" {
			return usage("--clipboard and --output are mutually exclusive")
		}
		if qr && (format != "url" || clip || o.json) {
			return usage("--qr requires --format url and cannot use --clipboard or --json")
		}
		ui, e := o.sourceInteractive(cmd, interactive, len(args) == 0 && !cmd.Flags().Changed("format") && !clip && !qr && output == "")
		if e != nil {
			return e
		}
		if !ui && len(args) == 0 {
			return usage("export requires NAME or --interactive")
		}
		t, e := o.configWorkTarget(cmd)
		if e != nil {
			return e
		}
		name := ""
		if len(args) > 0 {
			name = args[0]
		}
		if name == "" {
			var catalog configwork.Catalog
			e = o.authenticatedDiagnostic(cmd, t, func() error {
				var err error
				catalog, err = configwork.Inspect(cmd.Context(), t, o.configWorkOptions(cmd))
				return err
			})
			if e != nil {
				return e
			}
			choices := []wizard.Choice{}
			for _, d := range catalog.Proxies {
				choices = append(choices, wizard.Choice{Value: d.Name, Label: d.Name + " (" + d.Type + ")"})
			}
			if len(choices) == 0 {
				return usage("source has no raw node definitions")
			}
			name, e = wizard.Choose(cmd.Context(), "Export node", choices, cmd.InOrStdin(), cmd.OutOrStdout())
			if e != nil {
				return e
			}
		}
		var d configwork.Definition
		e = o.authenticatedDiagnostic(cmd, t, func() error {
			var err error
			d, err = configwork.ReadDefinition(cmd.Context(), t, "proxy", name, o.configWorkOptions(cmd))
			return err
		})
		if e != nil {
			return e
		}
		if ui {
			destination := "terminal"
			if output != "" {
				destination = "file"
			}
			if clip {
				destination = "clipboard"
			}
			if qr {
				destination = "qr"
				if output != "" {
					destination = "png"
				}
			}
			description := "This action includes the node's credentials. QR/URL is offered only when every connection field can be represented."
			for {
				values, err := wizard.Edit(cmd.Context(), wizard.Spec{Title: "Export " + name, Description: description, SubmitLabel: "Export", Fields: []wizard.Field{
					{Key: "format", Label: "Format", Kind: wizard.Select, Value: format, Options: []wizard.Choice{{Value: "yaml", Label: "Mihomo YAML (preserves fields)"}, {Value: "json", Label: "Mihomo JSON"}, {Value: "url", Label: "Protocol share URL"}}},
					{Key: "destination", Label: "Destination", Kind: wizard.Select, Value: destination, Options: []wizard.Choice{{Value: "terminal", Label: "Show credential-bearing text"}, {Value: "clipboard", Label: "Copy to local clipboard"}, {Value: "file", Label: "Private file"}, {Value: "qr", Label: "Terminal QR (share URL)"}, {Value: "png", Label: "PNG QR file (share URL)"}}},
					{Key: "output", Label: "New output file", Value: output, Help: "Required for File or PNG; existing files are not overwritten."},
				}}, cmd.InOrStdin(), cmd.OutOrStdout())
				if err != nil {
					return err
				}
				format, destination, output = values["format"], values["destination"], values["output"]
				clip = destination == "clipboard"
				qr = destination == "qr" || destination == "png"
				if destination != "file" && destination != "png" {
					output = ""
				}
				if (destination == "file" || destination == "png") && output == "" {
					description = "Choose a new output file."
					continue
				}
				if qr {
					format = "url"
				}
				if _, err = configwork.Export(d, format); err != nil {
					description = err.Error()
					continue
				}
				break
			}
		}
		raw, e := configwork.Export(d, format)
		if e != nil {
			return e
		}
		if qr {
			code, err := qrcode.New(string(raw), qrcode.Medium)
			if err != nil {
				return errors.New("share URI is too large for a QR code; export it to a file")
			}
			if output != "" {
				raw, e = code.PNG(512)
				if e != nil {
					return e
				}
			} else {
				_, e = fmt.Fprint(cmd.OutOrStdout(), code.ToSmallString(false))
				return e
			}
		}
		if clip {
			if e = clipboard.WriteAll(string(raw)); e != nil {
				return errors.New("local clipboard is unavailable; use --output or explicit stdout")
			}
			return o.result(cmd, "Credential-bearing node copied to the local clipboard")
		}
		if output != "" {
			f, e := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return errors.New("export path exists or is not writable")
			}
			_, e = f.Write(raw)
			if e == nil {
				e = f.Sync()
			}
			ce := f.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return ce
			}
			return o.result(cmd, "Exported private node to "+output)
		}
		if o.json {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"format": format, "content": string(raw), "contains_credentials": true})
		}
		_, e = fmt.Fprintln(cmd.OutOrStdout(), string(raw))
		return e
	}
	c.Flags().StringVar(&format, "format", "yaml", "yaml, json or url; unsupported URI fields are never discarded")
	c.Flags().StringVar(&output, "output", "", "new private export file (PNG for --qr)")
	c.Flags().BoolVar(&clip, "clipboard", false, "copy credentials to the local clipboard")
	c.Flags().BoolVar(&qr, "qr", false, "show terminal QR, or save PNG with --output")
	c.Flags().BoolVar(&interactive, "interactive", false, "choose node, format and destination")
	return c
}

func retainDefinitionDraft(data []byte) (string, error) {
	f, err := os.CreateTemp("", "lazyclash-unapplied-*.yaml")
	if err != nil {
		return "", err
	}
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
