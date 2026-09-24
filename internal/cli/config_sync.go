package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/spf13/cobra"
)

func (o *options) configComparisonTargets(cmd *cobra.Command, args []string, all bool) (config.Target, []config.Target, error) {
	for _, name := range []string{"target", "controller", "ssh", "secret-file", "secret-env", "ca-cert"} {
		if globalChanged(cmd, name) {
			return config.Target{}, nil, usage("configs %s cannot use --%s; each saved target supplies its own connection settings", cmd.Name(), name)
		}
	}
	if all && len(args) != 1 || !all && len(args) != 2 {
		return config.Target{}, nil, usage("use configs %s SOURCE DEST, or configs %s SOURCE --all", cmd.Name(), cmd.Name())
	}
	cfg, _, err := o.load(cmd)
	if err != nil {
		return config.Target{}, nil, err
	}
	index, err := targetIndex(cfg, args[0])
	if err != nil {
		return config.Target{}, nil, err
	}
	source := cfg.Targets[index]
	var targets []config.Target
	if all {
		for _, t := range cfg.Targets {
			if t.ID != source.ID {
				targets = append(targets, t)
			}
		}
	} else {
		index, err = targetIndex(cfg, args[1])
		if err != nil {
			return source, nil, err
		}
		if cfg.Targets[index].ID == source.ID {
			return source, nil, usage("source and destination must be different targets")
		}
		targets = append(targets, cfg.Targets[index])
	}
	if len(targets) == 0 {
		return source, nil, usage("no other saved targets to compare")
	}
	return source, targets, nil
}

func (o *options) configSyncCommands() []*cobra.Command {
	var diffAll bool
	var format string
	diff := &cobra.Command{
		Use: "diff SOURCE [DEST]", Short: "Compare persistent rules, proxies, groups, providers and host settings",
		Long: "Compare typed configuration objects between saved source owners. Credentials are masked after comparison, so secret-only differences remain visible. Rules retain order and occurrence identity. Host settings are comparison-only. Use --format unified to pipe the sanitized YAML diff to delta.",
		Args: cobra.RangeArgs(1, 2), RunE: func(cmd *cobra.Command, args []string) error {
			defer connection.CloseAuthentications()
			if format != "tree" && format != "unified" {
				return usage("--format must be tree or unified")
			}
			source, targets, err := o.configComparisonTargets(cmd, args, diffAll)
			if err != nil {
				return err
			}
			opts := o.configWorkOptions(cmd)
			opts.ReadOnly = true
			report, err := configwork.DiffConfigs(cmd.Context(), source, targets, opts)
			if o.json {
				if e := o.output(cmd, report); e != nil {
					return e
				}
			} else if _, e := fmt.Fprint(cmd.OutOrStdout(), configwork.FormatConfigDiffReport(report, format)); e != nil {
				return e
			}
			return err
		},
	}
	diff.Flags().BoolVar(&diffAll, "all", false, "compare source against all other saved targets")
	diff.Flags().StringVar(&format, "format", "tree", "output format: tree or unified (both mask secrets)")
	_ = diff.RegisterFlagCompletionFunc("format", completionValues("tree", "unified"))

	var all, interactive, yes, dryRun bool
	var selectionFile, expected string
	sync := &cobra.Command{
		Use: "sync SOURCE [DEST]", Short: "Preview or apply explicitly selected configuration objects and their dependencies",
		Long:    "Select whole proxies, proxy groups and providers, or individual ordered rules. Preview is the default. --interactive opens a masked object selector; --selection reads credential-free decisions from JSON. Apply with --yes --expect DIGEST from a preview. Every destination is preflighted before the first write; a failure stops later targets and preserves receipts for completed changes. Destination-only objects are retained. Rules require an explicit rules source binding.",
		Example: "  lazyclash configs diff desktop server\n  lazyclash configs sync desktop server --interactive\n  lazyclash configs sync desktop server --selection selection.json\n  lazyclash configs sync desktop server --selection selection.json --yes --expect DIGEST",
		Args:    cobra.RangeArgs(1, 2), RunE: func(cmd *cobra.Command, args []string) error {
			defer connection.CloseAuthentications()
			if interactive && (yes || expected != "" || dryRun) {
				return usage("--interactive has its own preview and confirmation; omit --yes, --expect and --dry-run")
			}
			if yes && dryRun {
				return usage("--yes and --dry-run cannot be combined")
			}
			if yes && expected == "" {
				return usage("--yes requires --expect DIGEST from a configs sync preview")
			}
			if yes {
				if _, err := hex.DecodeString(expected); err != nil || len(expected) != 64 {
					return usage("--expect must be the 64-character hexadecimal digest from a configs sync preview")
				}
			}
			if !yes && cmd.Flags().Changed("expect") {
				return usage("--expect requires --yes; omit both to preview")
			}
			if _, err := o.sourceInteractive(cmd, interactive, false); err != nil {
				return err
			}
			if !interactive && selectionFile == "" {
				return usage("select objects with --selection FILE or --interactive; see configs sync --help")
			}
			source, targets, err := o.configComparisonTargets(cmd, args, all)
			if err != nil {
				return err
			}
			selections := map[string]configwork.StructuralSelection{}
			if selectionFile != "" {
				selections, err = readConfigSelection(selectionFile, targets)
				if err != nil {
					return usage("invalid selection: %s", err)
				}
			}
			if interactive {
				return o.runConfigSyncInteractive(cmd, source, targets, selections)
			}
			req := configSyncRequest(source, targets, selections, all)
			opts := o.configWorkOptions(cmd)
			if !yes {
				plan, err := configwork.PreviewChangeSetBatch(cmd.Context(), req, opts)
				if o.json {
					if e := o.output(cmd, plan); e != nil {
						return e
					}
				} else if _, e := fmt.Fprint(cmd.OutOrStdout(), configwork.FormatChangeSetBatch(plan)); e != nil {
					return e
				}
				return err
			}
			if err = o.writable(); err != nil {
				return err
			}
			result, err := configwork.ApplyChangeSetBatch(cmd.Context(), req, expected, opts)
			if e := o.output(cmd, result); e != nil {
				return e
			}
			return err
		},
	}
	sync.Flags().BoolVar(&all, "all", false, "consider every other saved target; selections remain per target")
	sync.Flags().BoolVar(&interactive, "interactive", false, "open the object selector and final review")
	sync.Flags().BoolVar(&yes, "yes", false, "apply the exact reviewed candidate identified by --expect")
	sync.Flags().BoolVar(&dryRun, "dry-run", false, "preview without writing (the default)")
	sync.Flags().StringVar(&selectionFile, "selection", "", "JSON object selections; no configuration values or credentials")
	sync.Flags().StringVar(&expected, "expect", "", "digest from the reviewed selection preview")
	_ = sync.MarkFlagFilename("selection", "json")
	return []*cobra.Command{diff, sync}
}

func completionValues(values ...string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

func configSyncRequest(source config.Target, targets []config.Target, selections map[string]configwork.StructuralSelection, all bool) configwork.ChangeSetBatchRequest {
	req := configwork.ChangeSetBatchRequest{Source: source, All: all}
	for _, t := range targets {
		req.Destinations = append(req.Destinations, configwork.ChangeSetDestination{Target: t, TargetID: t.ID, Selection: selections[t.ID]})
	}
	return req
}

// Single-target files can be a StructuralSelection. Multi-target files use
// {"destinations":[{"target":"id","selection":{...}}]}; omitted targets are
// deliberately unselected, never granted the first destination's choices.
func readConfigSelection(path string, targets []config.Target) (map[string]configwork.StructuralSelection, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot read selection file")
	}
	defer f.Close()
	const limit = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(raw) > limit {
		return nil, errors.New("selection file is unreadable or exceeds 1 MiB")
	}
	if err = checkSelectionJSON(raw); err != nil {
		return nil, err
	}
	var shape map[string]json.RawMessage
	if json.Unmarshal(raw, &shape) != nil || shape == nil {
		return nil, errors.New("selection must be a JSON object")
	}
	result := map[string]configwork.StructuralSelection{}
	if _, multi := shape["destinations"]; multi {
		var file struct {
			Destinations []configwork.ChangeSetDestination `json:"destinations"`
		}
		if err = decodeConfigSelection(raw, &file); err != nil {
			return nil, err
		}
		valid := map[string]bool{}
		for _, target := range targets {
			valid[target.ID] = true
		}
		for _, d := range file.Destinations {
			if !valid[d.TargetID] {
				return nil, errors.New("selection contains a target outside this invocation")
			}
			if _, exists := result[d.TargetID]; exists {
				return nil, errors.New("selection contains a duplicate destination")
			}
			result[d.TargetID] = d.Selection
		}
	} else {
		if len(targets) != 1 {
			return nil, errors.New("--all requires a destinations array with per-target selections")
		}
		var selection configwork.StructuralSelection
		if err = decodeConfigSelection(raw, &selection); err != nil {
			return nil, err
		}
		result[targets[0].ID] = selection
	}
	return result, nil
}

func decodeConfigSelection(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return errors.New("selection does not match the documented JSON schema (unknown fields are rejected)")
	}
	return nil
}

func checkSelectionJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return errors.New("selection JSON nesting exceeds limit")
		}
		token, err := dec.Token()
		if err != nil {
			return errors.New("invalid selection JSON")
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return errors.New("invalid selection JSON")
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate selection JSON field")
				}
				seen[name] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid selection JSON")
		}
		_, err = dec.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("selection must contain exactly one JSON value")
	}
	return nil
}
