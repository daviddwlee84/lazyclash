package cli

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"github.com/spf13/cobra"
)

func (o *options) quickRuleTargets(cmd *cobra.Command, all bool) ([]config.Target, error) {
	if globalChanged(cmd, "controller") || globalChanged(cmd, "ssh") {
		return nil, usage("rules use saved targets; temporary controller/SSH overrides are not supported")
	}
	if !all {
		t, err := o.ruleTarget(cmd)
		return []config.Target{t}, err
	}
	for _, flag := range []string{"target", "secret-file", "secret-env", "ca-cert"} {
		if globalChanged(cmd, flag) {
			return nil, usage("--all cannot use --%s; each saved target uses its own credentials", flag)
		}
	}
	cfg, _, err := o.load(cmd)
	if err != nil {
		return nil, err
	}
	if len(cfg.Targets) == 0 {
		return nil, usage("no saved targets; register a target first")
	}
	return cfg.Targets, nil
}

func (o *options) quickRuleCommands() []*cobra.Command {
	var all, dryRun, yes bool
	var expected string
	apply := &cobra.Command{Use: "apply RULE", Short: "Apply a persistent common rule to one target or --all; relevant conflicts and invalid candidates block writes", Args: argsExact(1), Long: "Apply one DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR or IP-CIDR6 rule.\nConflicts involving the requested selector and invalid candidate configurations block all writes. Unrelated existing selector conflicts are health warnings; use rules healthcheck for details.\nInteractive terminals preview and ask [y/N]. --yes accepts warnings, never operation errors.\nWithout a terminal or with --json, omit --yes to preview. --all reports unavailable targets as skips.\nUse -- before a quoted YAML item beginning with '- '.", Example: "  lazyclash --target server rules apply -- '- DOMAIN-SUFFIX,example.com,DIRECT'\n  lazyclash rules apply --all --yes 'DOMAIN-SUFFIX,example.com,DIRECT'\n  lazyclash rules apply --all --dry-run --json 'DOMAIN-SUFFIX,example.com,DIRECT'", RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if _, err := rulecheck.Parse(args[0]); err != nil {
			return usage("%s", err)
		}
		if dryRun && yes {
			return usage("--dry-run and --yes are mutually exclusive")
		}
		if expected != "" {
			if !yes {
				return usage("--expect requires --yes")
			}
			if b, err := hex.DecodeString(expected); err != nil || len(b) != 32 {
				return usage("--expect requires a 64-character preview digest")
			}
		}
		if yes {
			if err := o.writable(); err != nil {
				return err
			}
		}
		targets, err := o.quickRuleTargets(cmd, all)
		if err != nil {
			return err
		}
		opts := o.ruleOptions(cmd)
		var p rulework.QuickPlan
		preview := func() error {
			var e error
			p, e = rulework.PreviewRules(cmd.Context(), targets, args[0], all, opts)
			return e
		}
		if all {
			err = preview()
		} else {
			err = o.authenticatedDiagnostic(cmd, targets[0], preview)
		}
		o.ruleGuidanceContext(cmd, &p)
		interactive := !o.json && o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout())
		if !yes || err != nil {
			if o.json {
				if e := o.output(cmd, p); e != nil {
					return e
				}
			} else {
				if _, e := fmt.Fprint(cmd.OutOrStdout(), core.Sanitize(rulework.FormatQuickPlan(p))); e != nil {
					return e
				}
			}
		}
		if err != nil {
			return err
		}
		if expected != "" && expected != p.Digest {
			return usage("rule preview changed; review a new preview before applying")
		}
		if dryRun || !yes && (!interactive || o.readOnly) {
			return nil
		}
		if !yes {
			if !p.HasChanges() {
				return nil
			}
			accepted, e := confirmQuickRule(cmd.Context(), cmd.InOrStdin(), cmd.ErrOrStderr())
			if e != nil {
				return e
			}
			if !accepted {
				return o.result(cmd, "Canceled; no targets changed.")
			}
		}
		result, err := rulework.ApplyRules(cmd.Context(), targets, args[0], all, p.Digest, opts)
		if o.json {
			if e := o.output(cmd, result); e != nil {
				return e
			}
		} else if _, e := fmt.Fprint(cmd.OutOrStdout(), core.Sanitize(rulework.FormatQuickResult(result))); e != nil {
			return e
		}
		return err
	}}
	apply.Flags().BoolVar(&all, "all", false, "apply to all saved targets, reporting unavailable targets as skips")
	apply.Flags().BoolVar(&dryRun, "dry-run", false, "validate and preview without writing or prompting")
	apply.Flags().BoolVar(&yes, "yes", false, "accept the current preview and warnings; errors still block all writes")
	apply.Flags().StringVar(&expected, "expect", "", "optionally require this reviewed digest with --yes")
	apply.ValidArgsFunction = func(_ *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
		var suggestions []string
		if len(args) == 0 {
			for _, kind := range []string{"DOMAIN,", "DOMAIN-SUFFIX,", "DOMAIN-KEYWORD,", "IP-CIDR,", "IP-CIDR6,"} {
				if strings.HasPrefix(kind, prefix) {
					suggestions = append(suggestions, kind)
				}
			}
		}
		return suggestions, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	}
	var healthAll bool
	health := &cobra.Command{Use: "healthcheck", Short: "Inspect rule conflicts, overlap and analysis coverage without changing a target", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		defer connection.CloseAuthentications()
		targets, err := o.quickRuleTargets(cmd, healthAll)
		if err != nil {
			return err
		}
		report, err := rulework.Healthcheck(cmd.Context(), targets, healthAll, o.ruleOptions(cmd))
		if e := o.output(cmd, report); e != nil {
			return e
		}
		return err
	}}
	health.Flags().BoolVar(&healthAll, "all", false, "inspect all saved targets and report unavailable sources")
	return []*cobra.Command{apply, health}
}

// Suggested binding commands must retain an explicitly selected settings file;
// otherwise the same target ID could refer to a different registered machine.
func (o *options) ruleGuidanceContext(cmd *cobra.Command, p *rulework.QuickPlan) {
	path, explicit, err := o.settingsPath(cmd)
	if err != nil || (!explicit && o.path == "") {
		return
	}
	quoted := "'" + strings.ReplaceAll(path, "'", "'\"'\"'") + "'"
	if runtime.GOOS == "windows" {
		quoted = "'" + strings.ReplaceAll(path, "'", "''") + "'"
	}
	for i := range p.Targets {
		for j, next := range p.Targets[i].NextCommands {
			p.Targets[i].NextCommands[j] = strings.Replace(next, "lazyclash ", "lazyclash --config "+quoted+" ", 1)
		}
	}
}

// Keep canonical terminal line editing and a negative default. Only the command
// owns stdin; JSON and redirected invocations never reach this prompt.
func confirmQuickRule(ctx context.Context, in io.Reader, out io.Writer) (bool, error) {
	if _, err := fmt.Fprint(out, "Apply these changes and accept the listed warnings? [y/N] "); err != nil {
		return false, err
	}
	type answer struct {
		value string
		err   error
	}
	ch := make(chan answer, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(in, 1024)).ReadString('\n')
		ch <- answer{line, err}
	}()
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case a := <-ch:
		if a.err != nil && a.err != io.EOF {
			return false, a.err
		}
		value := strings.ToLower(strings.TrimSpace(a.value))
		return value == "y" || value == "yes", nil
	}
}
