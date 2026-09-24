package cli

import (
	"fmt"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"github.com/spf13/cobra"
)

func (o *options) ruleInspectionOptions(cmd *cobra.Command) rulework.Options {
	opts := o.ruleOptions(cmd)
	opts.ReadOnly = true
	opts.Open = o.comparisonOptions(cmd).Open
	return opts
}

func (o *options) ruleDiffTargets(cmd *cobra.Command, args []string, all bool) (config.Target, []config.Target, error) {
	for _, name := range []string{"target", "controller", "ssh", "secret-file", "secret-env", "ca-cert"} {
		if globalChanged(cmd, name) {
			return config.Target{}, nil, usage("rules diff cannot use --%s; select saved targets as positional arguments", name)
		}
	}
	if all && len(args) != 1 || !all && len(args) != 2 {
		return config.Target{}, nil, usage("use rules diff BASELINE DESTINATION, or rules diff BASELINE --all")
	}
	cfg, _, err := o.load(cmd)
	if err != nil {
		return config.Target{}, nil, err
	}
	index, err := targetIndex(cfg, args[0])
	if err != nil {
		return config.Target{}, nil, err
	}
	baseline := cfg.Targets[index]
	targets := []config.Target{}
	if all {
		for _, t := range cfg.Targets {
			if t.ID != baseline.ID {
				targets = append(targets, t)
			}
		}
	} else {
		index, err = targetIndex(cfg, args[1])
		if err != nil {
			return baseline, nil, err
		}
		if cfg.Targets[index].ID == baseline.ID {
			return baseline, nil, usage("baseline and destination must be different targets")
		}
		targets = append(targets, cfg.Targets[index])
	}
	if len(targets) == 0 {
		return baseline, nil, usage("no other saved targets to compare")
	}
	return baseline, targets, nil
}

func (o *options) ruleInspectCommands() []*cobra.Command {
	var diffAll bool
	var diffScope string
	diff := &cobra.Command{Use: "diff BASELINE [DESTINATION]", Short: "Compare ordered rules between two saved targets, or a baseline against --all", Args: func(_ *cobra.Command, args []string) error {
		if len(args) < 1 || len(args) > 2 {
			return usage("use rules diff BASELINE DESTINATION, or rules diff BASELINE --all")
		}
		return nil
	}, RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if _, err := rulework.NormalizeRulesScope(diffScope); err != nil {
			return usage("%s", err)
		}
		baseline, targets, err := o.ruleDiffTargets(cmd, args, diffAll)
		if err != nil {
			return err
		}
		report, err := rulework.DiffRules(cmd.Context(), baseline, targets, diffScope, o.ruleInspectionOptions(cmd))
		if o.json {
			if e := o.output(cmd, report); e != nil {
				return e
			}
		} else {
			if _, e := fmt.Fprint(cmd.OutOrStdout(), core.Sanitize(rulework.FormatRuleDiff(report))); e != nil {
				return e
			}
		}
		return err
	}}
	diff.Flags().BoolVar(&diffAll, "all", false, "compare the baseline against all other saved targets")
	diff.Flags().StringVar(&diffScope, "scope", "both", "rule evidence to compare: runtime, source or both")
	commands := []*cobra.Command{diff}
	for _, kind := range []string{"find", "lookup"} {
		var all bool
		var scope string
		use, description := "find RULE", "Find an exact rule or selector alternatives on saved targets"
		if kind == "lookup" {
			use, description = "lookup HOST_OR_IP", "Inspect static matching candidates without DNS or test traffic"
		}
		command := &cobra.Command{Use: use, Short: description, Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
			defer connection.CloseAuthentications()
			if _, err := rulework.NormalizeRulesScope(scope); err != nil {
				return usage("%s", err)
			}
			if kind == "find" {
				if _, err := rulecheck.ParseQuery(args[0]); err != nil {
					return usage("%s", err)
				}
			} else {
				if _, err := rulecheck.ParseLookup(args[0]); err != nil {
					return usage("%s", err)
				}
			}
			targets, err := o.quickRuleTargets(cmd, all)
			if err != nil {
				return err
			}
			opts := o.ruleInspectionOptions(cmd)
			if kind == "find" {
				report, e := rulework.FindRules(cmd.Context(), targets, args[0], scope, opts)
				if o.json {
					if err = o.output(cmd, report); err != nil {
						return err
					}
				} else {
					if _, err = fmt.Fprint(cmd.OutOrStdout(), core.Sanitize(rulework.FormatRuleFind(report))); err != nil {
						return err
					}
				}
				return e
			}
			report, e := rulework.LookupRules(cmd.Context(), targets, args[0], scope, opts)
			if o.json {
				if err = o.output(cmd, report); err != nil {
					return err
				}
			} else {
				if _, err = fmt.Fprint(cmd.OutOrStdout(), core.Sanitize(rulework.FormatRuleLookup(report))); err != nil {
					return err
				}
			}
			return e
		}}
		command.Flags().BoolVar(&all, "all", false, "inspect every saved target with its own connection settings")
		command.Flags().StringVar(&scope, "scope", "both", "rule evidence to inspect: runtime, source or both")
		command.ValidArgsFunction = func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		commands = append(commands, command)
	}
	return commands
}
