package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/discoveryguard"
	"github.com/daviddwlee84/lazyclash/internal/rulediscovery"
	"github.com/daviddwlee84/lazyclash/internal/ruleobserve"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"github.com/daviddwlee84/lazyclash/internal/tui"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/spf13/cobra"
)

func (o *options) rulesDiscoverCommand() *cobra.Command {
	group := &cobra.Command{Use: "discover", Short: "Observe connection logs, review candidates and recover temporary DIRECT sessions"}
	var duration time.Duration
	var direct, yes, dry bool
	start := &cobra.Command{Use: "start", Short: "Collect a timed foreground observation; --direct temporarily switches the fallback", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		defer connection.CloseAuthentications()
		if duration <= 0 || duration > 24*time.Hour {
			return usage("--duration must be positive and at most 24h")
		}
		if yes && dry {
			return usage("--yes and --dry-run are mutually exclusive")
		}
		if yes && !direct {
			return usage("--yes is only used with --direct")
		}
		t, err := o.ruleTarget(cmd)
		if err != nil {
			return err
		}
		_, path, err := o.load(cmd)
		if err != nil {
			return err
		}
		opts := rulediscovery.Options{SettingsPath: path, Duration: duration, Direct: direct}
		if direct {
			for _, flag := range []string{"secret-file", "secret-env", "ca-cert"} {
				if globalChanged(cmd, flag) {
					return usage("--direct uses saved credential references so its independent helper can restore the target; save --%s first", flag)
				}
			}
			plan, e := discoveryguard.Preview(cmd.Context(), t)
			if e != nil {
				return e
			}
			opts.Plan = plan
			if !yes || dry || o.readOnly {
				if e := o.output(cmd, map[string]any{"target_id": t.ID, "duration": duration.String(), "direct": true, "plan": plan}); e != nil {
					return e
				}
			}
			if dry || o.readOnly && !yes {
				return nil
			}
			if e := o.writable(); e != nil {
				return e
			}
			if !yes {
				if o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout()) {
					return nil
				}
				accepted, e := wizard.Confirm(cmd.Context(), "Start temporary DIRECT discovery", fmt.Sprintf("Target: %s\nFallback: %s\nSelection: %s → DIRECT\nDuration: %s\nThe independent helper will attempt restoration on stop, timeout or parent exit.", core.Sanitize(t.ID), core.Sanitize(plan.FallbackPolicy), core.Sanitize(plan.Previous), duration), cmd.InOrStdin(), cmd.ErrOrStderr())
				if e != nil {
					return e
				}
				if !accepted {
					return o.result(cmd, "Canceled; no routing settings changed.")
				}
			}
		} else if dry {
			return o.output(cmd, map[string]any{"target_id": t.ID, "duration": duration.String(), "direct": false})
		}
		return o.collectRuleDiscovery(cmd, t, opts)
	}}
	start.Flags().DurationVar(&duration, "duration", rulediscovery.DefaultDuration, "observation time, greater than zero and at most 24h")
	start.Flags().BoolVar(&direct, "direct", false, "temporarily select DIRECT in the actual MATCH fallback, with independent restoration")
	start.Flags().BoolVar(&yes, "yes", false, "accept the previewed temporary DIRECT change")
	start.Flags().BoolVar(&dry, "dry-run", false, "inspect the requested session without collecting or changing settings")
	var listInteractive bool
	list := &cobra.Command{Use: "list", Short: "List saved observations and pending restoration records", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		if listInteractive && (o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout())) {
			return usage("--interactive requires a terminal and cannot use --json")
		}
		snapshots, err := ruleobserve.List("")
		if err != nil {
			return err
		}
		path, _, err := o.settingsPath(cmd)
		if err != nil {
			return err
		}
		guards, err := discoveryguard.List(path)
		if err != nil {
			return err
		}
		if !listInteractive {
			return o.output(cmd, map[string]any{"observations": snapshots, "restorations": guards})
		}
		var choices []wizard.Choice
		for _, s := range snapshots {
			choices = append(choices, wizard.Choice{Value: "review:" + s.ID, Label: core.Sanitize(s.TargetID + " · " + s.StartedAt.Format(time.RFC3339) + " · " + s.Status)})
		}
		for _, g := range guards {
			if g.Pending() {
				choices = append(choices, wizard.Choice{Value: "recover:" + g.ID, Label: core.Sanitize("Restore " + g.TargetID + " · " + g.Phase + " · " + g.ID)})
			}
		}
		if len(choices) == 0 {
			return o.result(cmd, "No saved observations or pending restorations.")
		}
		choice, err := wizard.Choose(cmd.Context(), "Saved rule observations / restorations", choices, cmd.InOrStdin(), cmd.OutOrStdout())
		if err != nil {
			return err
		}
		if len(choice) > 7 && choice[:7] == "review:" {
			s, e := ruleobserve.Load("", choice[7:])
			if e != nil {
				return e
			}
			return o.reviewRuleSnapshot(cmd, s)
		}
		if len(choice) > 8 && choice[:8] == "recover:" {
			return o.recoverRuleDiscovery(cmd, choice[8:], false, false)
		}
		return nil
	}}
	list.Flags().BoolVar(&listInteractive, "interactive", false, "choose a saved observation or pending restoration")
	var interactive bool
	review := &cobra.Command{Use: "review ID", Short: "Read a saved observation or interactively review rules to apply", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		if interactive && (o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout())) {
			return usage("--interactive requires a terminal and cannot use --json")
		}
		s, err := ruleobserve.Load("", args[0])
		if err != nil {
			return err
		}
		if !interactive {
			return o.output(cmd, s)
		}
		return o.reviewRuleSnapshot(cmd, s)
	}}
	review.Flags().BoolVar(&interactive, "interactive", false, "search, select candidates, assign policies and preview one batch")
	var recoverYes, recoverDry bool
	recover := &cobra.Command{Use: "recover ID", Short: "Inspect and retry a pending guarded restoration", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		if recoverYes && recoverDry {
			return usage("--yes and --dry-run are mutually exclusive")
		}
		return o.recoverRuleDiscovery(cmd, args[0], recoverYes, recoverDry)
	}}
	recover.Flags().BoolVar(&recoverYes, "yes", false, "accept a guarded restoration attempt")
	recover.Flags().BoolVar(&recoverDry, "dry-run", false, "read the restoration record without changing the controller")
	group.AddCommand(start, list, review, recover)
	return group
}

func (o *options) collectRuleDiscovery(cmd *cobra.Command, t config.Target, opts rulediscovery.Options) error {
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	c, closer, err := o.deps.Open(ctx, t, true)
	if err != nil {
		return err
	}
	defer c.Close()
	if closer != nil {
		defer closer.Close()
	}
	// Authenticate without depending on a quiet log endpoint flushing headers.
	if _, err = c.Version(ctx); err != nil {
		return err
	}
	var mu sync.Mutex
	var session *rulediscovery.Session
	streamDone := make(chan error, 1)
	go func() {
		err := c.Stream(ctx, "logs", url.Values{"level": {"info"}}, func(record core.Object) {
			mu.Lock()
			s := session
			mu.Unlock()
			if s != nil {
				s.Observe(record, time.Now())
			}
		})
		streamDone <- err
		if err != nil {
			cancel()
		}
	}()
	select {
	case e := <-streamDone:
		return e
	default:
	}
	s, err := rulediscovery.Start(ctx, t, opts)
	if err != nil {
		if s != nil {
			cleanup, stop := context.WithTimeout(context.Background(), 135*time.Second)
			snapshot, recoveryErr := s.Stop(cleanup)
			stop()
			return errors.Join(err, recoveryErr, o.output(cmd, snapshot))
		}
		return err
	}
	mu.Lock()
	session = s
	mu.Unlock()
	if !o.json {
		if _, err = fmt.Fprintf(cmd.ErrOrStderr(), "Observing %s for %s. Session: %s\nCtrl-C stops collection and waits for restoration. No log events may arrive on a quiet core.\n", core.Sanitize(t.ID), opts.Duration, s.ID()); err != nil {
			s.RequestStop()
		}
	}
	var streamErr error
	select {
	case <-s.Done():
	case <-ctx.Done():
		s.RequestStop()
	case e := <-streamDone:
		streamErr = e
		s.Gap(time.Now(), "log stream disconnected")
		s.RequestStop()
	}
	if streamErr == nil && ctx.Err() != nil && cmd.Context().Err() == nil {
		select {
		case streamErr = <-streamDone:
			s.Gap(time.Now(), "log stream disconnected")
		default:
		}
	}
	cleanup, stopCleanup := context.WithTimeout(context.Background(), 135*time.Second)
	defer stopCleanup()
	snapshot, stopErr := s.Stop(cleanup)
	cancel()
	if e := o.output(cmd, snapshot); e != nil {
		return e
	}
	if !o.json {
		fmt.Fprintf(cmd.ErrOrStderr(), "Review: lazyclash rules discover review %s --interactive\n", snapshot.ID)
	}
	return errors.Join(err, streamErr, stopErr, cmd.Context().Err())
}

func (o *options) recoverRuleDiscovery(cmd *cobra.Command, id string, yes, dry bool) error {
	path, _, err := o.settingsPath(cmd)
	if err != nil {
		return err
	}
	statuses, err := discoveryguard.List(path)
	if err != nil {
		return err
	}
	var status discoveryguard.Status
	found := false
	for _, s := range statuses {
		if s.ID == id {
			status = s
			found = true
			break
		}
	}
	if !found {
		return usage("restoration record not found")
	}
	if dry || !yes && (o.readOnly || o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout())) {
		return o.output(cmd, status)
	}
	if err := o.writable(); err != nil {
		return err
	}
	if !yes {
		if err := o.output(cmd, status); err != nil {
			return err
		}
		accepted, e := wizard.Confirm(cmd.Context(), "Retry discovery restoration", fmt.Sprintf("Target: %s\nGroup: %s\nRestore selection: %s\nCurrent state will be checked before changing it.", core.Sanitize(status.TargetID), core.Sanitize(status.Group), core.Sanitize(status.Previous)), cmd.InOrStdin(), cmd.OutOrStdout())
		if e != nil {
			return e
		}
		if !accepted {
			return nil
		}
	}
	result, err := discoveryguard.Recover(cmd.Context(), path, id)
	if e := o.output(cmd, result); e != nil {
		return e
	}
	return err
}

func (o *options) reviewRuleSnapshot(cmd *cobra.Command, s ruleobserve.Snapshot) error {
	defer connection.CloseAuthentications()
	cfg, path, err := o.load(cmd)
	if err != nil {
		return err
	}
	var t config.Target
	for _, target := range cfg.Targets {
		if target.ID == s.TargetID {
			t = target
			break
		}
	}
	if globalChanged(cmd, "target") && o.target != s.TargetID {
		return usage("observation belongs to target %s", s.TargetID)
	}
	opts := o.ruleReviewOptions(cmd.Context(), t, s, path)
	result, err := tui.RunRuleReview(cmd.Context(), opts, cmd.InOrStdin(), cmd.OutOrStdout())
	if result.Status != "" {
		fmt.Fprintln(cmd.OutOrStdout(), rulework.FormatQuickResult(result))
	}
	return err
}

func (o *options) ruleReviewOptions(_ context.Context, t config.Target, s ruleobserve.Snapshot, path string) tui.RuleReviewOptions {
	opts := tui.RuleReviewOptions{Snapshot: s, ReadOnly: o.readOnly}
	if t.ID == "" || t.Transient || t.TransportOverride {
		opts.BlockedReason = "Save this target before applying observed rules."
	}
	if s.TargetIdentity != "" && s.TargetIdentity != rulediscovery.TargetIdentity(t) {
		opts.BlockedReason = "The saved target has changed; this observation is available for inspection only."
	}
	guardCheck := func() error {
		if opts.BlockedReason != "" {
			return errors.New(opts.BlockedReason)
		}
		fresh, err := config.Load(path, true)
		if err != nil {
			return err
		}
		found := false
		before, _ := json.Marshal(t)
		for _, candidate := range fresh.Targets {
			if candidate.ID == t.ID {
				after, _ := json.Marshal(candidate)
				found = string(before) == string(after)
				break
			}
		}
		if !found {
			return errors.New("target settings changed while reviewing; reopen the observation before applying")
		}
		statuses, err := discoveryguard.List(path)
		if err != nil {
			return err
		}
		for _, status := range statuses {
			if status.TargetID == t.ID && status.Pending() {
				return fmt.Errorf("restore discovery session %s before applying rules (%s)", status.ID, status.Phase)
			}
		}
		return nil
	}
	opts.Policies = func(ctx context.Context) ([]string, error) {
		if t.ID == "" {
			return nil, nil
		}
		c, closer, err := o.deps.Open(ctx, t, true)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		if closer != nil {
			defer closer.Close()
		}
		proxies, err := c.Proxies(ctx)
		if err != nil {
			return nil, err
		}
		var names []string
		for name := range proxies {
			names = append(names, name)
		}
		sort.Strings(names)
		return names, nil
	}
	optionsFor := func(ctx context.Context) rulework.Options {
		cmd := &cobra.Command{}
		cmd.SetContext(ctx)
		return o.ruleOptions(cmd)
	}
	opts.Preview = func(ctx context.Context, rules []string) (rulework.QuickPlan, error) {
		if err := guardCheck(); err != nil {
			return rulework.QuickPlan{}, err
		}
		return rulework.PreviewRuleBatch(ctx, []config.Target{t}, rules, false, optionsFor(ctx))
	}
	opts.Apply = func(ctx context.Context, rules []string, digest string) (rulework.QuickResult, error) {
		if err := guardCheck(); err != nil {
			return rulework.QuickResult{}, err
		}
		return rulework.ApplyRuleBatch(ctx, []config.Target{t}, rules, false, digest, optionsFor(ctx))
	}
	opts.Save = func(ctx context.Context, s ruleobserve.Snapshot) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return ruleobserve.Save("", s)
	}
	return opts
}
