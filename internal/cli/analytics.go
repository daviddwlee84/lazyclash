package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/analytics"
	"github.com/daviddwlee84/lazyclash/internal/analyticsservice"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/diagnostics"
	"github.com/daviddwlee84/lazyclash/internal/tui"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/spf13/cobra"
)

type analyticsCLI struct {
	o                                        *options
	configPath, stateDir, host, remoteBinary string
}

func (o *options) analyticsCommand() *cobra.Command {
	a := &analyticsCLI{o: o}
	c := &cobra.Command{Use: "analytics", Short: "Opt-in historical traffic collection, reports and user services", Long: "Keep client, proxy-server and host observations separately. Nothing is collected or installed until explicitly enabled. Collector paths and credentials belong to the collecting host."}
	c.PersistentFlags().StringVar(&a.configPath, "analytics-config", "", "analytics TOML on the collector host (default: XDG config/lazyclash/analytics.toml)")
	c.PersistentFlags().StringVar(&a.stateDir, "state-dir", "", "private state directory on the collector host")
	c.PersistentFlags().StringVar(&a.host, "collector-host", "", "query/configure an existing collector over SSH; no public listener")
	c.PersistentFlags().StringVar(&a.remoteBinary, "remote-binary", "", "existing lazyclash executable on collector host")
	c.AddCommand(a.setupCommand(), a.collectCommand(), a.reportCommand(), a.statusCommand(), a.doctorCommand(), a.serviceCommand(), a.importCommand(), a.alertsCommand())
	return c
}

func (a *analyticsCLI) paths() (analytics.Paths, error) {
	p, err := analytics.DefaultPaths()
	if err != nil {
		return p, err
	}
	if a.configPath != "" {
		original := p.Config
		p.Config, err = filepath.Abs(a.configPath)
		if err != nil {
			return p, err
		}
		if p.Config != original && a.stateDir == "" {
			hash := sha256.Sum256([]byte(p.Config))
			p.Database = filepath.Join(filepath.Dir(p.Database), fmt.Sprintf("%x", hash[:12]), "analytics.db")
		}
	}
	if a.stateDir != "" {
		dir, e := filepath.Abs(a.stateDir)
		if e != nil {
			return p, e
		}
		p.Database = filepath.Join(dir, "analytics.db")
	}
	return p, nil
}
func (a *analyticsCLI) load() (analytics.Config, analytics.Paths, error) {
	p, err := a.paths()
	if err != nil {
		return analytics.Config{}, p, err
	}
	cfg, err := analytics.LoadConfig(p.Config)
	if errors.Is(err, os.ErrNotExist) {
		return analytics.DefaultConfig(), p, nil
	}
	return cfg, p, err
}
func (a *analyticsCLI) targets(cmd *cobra.Command, cfg analytics.Config, includeDisabled ...bool) ([]config.Target, error) {
	needed := false
	for _, s := range cfg.Sources {
		needed = needed || s.Kind == "mihomo" && (s.Enabled || len(includeDisabled) > 0 && includeDisabled[0])
	}
	if !needed {
		return nil, nil
	}
	path := cfg.SettingsPath
	if path == "" {
		var err error
		path, _, err = a.o.settingsPath(cmd)
		if err != nil {
			return nil, err
		}
	}
	settings, err := config.Load(path, true)
	if err != nil {
		return nil, err
	}
	return settings.Targets, nil
}

func (a *analyticsCLI) setupCommand() *cobra.Command {
	var source analytics.SourceConfig
	var interactive, yes bool
	var detail, minute, months int
	var maxMiB int64
	var timezone, settingsPath, webhookFile, webhookEnv string
	var alerts bool
	var thresholds []int64
	c := &cobra.Command{Use: "setup", Short: "Register or update an opt-in source and configurable retention", Args: argsExact(0)}
	f := c.Flags()
	f.StringVar(&source.ID, "source", "", "stable source ID (unique per observation point)")
	f.StringVar(&source.Kind, "kind", "", "mihomo, interface, xray-access, xray-stats or vnstat")
	f.BoolVar(&source.Enabled, "enabled", false, "enable this source when the collector next starts")
	f.StringVar(&source.Interface, "interface", "", "explicit Linux/vnStat network interface")
	f.StringVar(&source.Path, "path", "", "absolute access-log path on the collecting host")
	f.StringVar(&source.Format, "format", "", "access/Stats format: xray or v2ray; v2ctl is supported for Stats only")
	f.StringVar(&source.Timezone, "source-timezone", "", "timezone of offset-less access logs or native vnStat days; access defaults to collector host local time")
	f.StringVar(&source.Binary, "binary", "", "installed xray/v2ray/vnstat executable on collecting host")
	f.StringVar(&source.Address, "address", "", "loopback Xray/V2Ray Stats API address")
	f.StringVar(&source.ServerID, "server-id", "", "server inventory ID for provenance (not an identity claim)")
	f.StringVar(&source.HostID, "host-id", "", "VPS inventory ID for provenance")
	f.IntVar(&source.PollSeconds, "poll-seconds", 0, "poll interval; 0 chooses the source default")
	f.StringVar(&settingsPath, "settings-path", "", "absolute collector-local lazyclash TOML for Mihomo target IDs")
	f.StringVar(&timezone, "timezone", "", "analysis day timezone; default Asia/Shanghai")
	f.IntVar(&detail, "detail-days", 30, "connection/event retention")
	f.IntVar(&minute, "minute-days", 90, "minute aggregate retention")
	f.IntVar(&months, "day-months", 13, "daily aggregate retention")
	f.Int64Var(&maxMiB, "max-mib", 1024, "collector storage budget in MiB (includes WAL)")
	f.BoolVar(&alerts, "alerts-enabled", false, "enable configured daily TX alerts")
	f.Int64SliceVar(&thresholds, "threshold-gib", []int64{20, 50, 100}, "daily TX thresholds in GiB")
	f.StringVar(&webhookFile, "webhook-file", "", "absolute private file containing Discord webhook URL")
	f.StringVar(&webhookEnv, "webhook-env", "", "collector-host environment variable containing Discord webhook URL")
	f.BoolVar(&interactive, "interactive", false, "open the source registration form")
	f.BoolVar(&yes, "yes", false, "save the displayed configuration; does not install/start services")
	c.RunE = func(cmd *cobra.Command, _ []string) error {
		if a.host != "" {
			return a.forward(cmd)
		}
		if a.o.readOnly {
			return usage("analytics setup is disabled in read-only mode")
		}
		cfg, p, err := a.load()
		if err != nil {
			return err
		}
		old, readErr := os.ReadFile(p.Config)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		useForm := interactive || (!serverBusinessFlags(cmd) && a.o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout()) && !a.o.json)
		if interactive && (a.o.json || !a.o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout())) {
			return usage("--interactive requires a terminal and cannot use --json")
		}
		prefilledID := ""
		for _, saved := range cfg.Sources {
			if saved.ID == source.ID {
				source = analyticsSourceDraft(saved, source, f.Changed)
				prefilledID = saved.ID
				break
			}
		}
		if globalChanged(cmd, "target") || useForm && prefilledID == "" && source.Target == "" {
			source.Target = a.o.target
		}
		if useForm {
			v, e := wizard.Edit(cmd.Context(), wizard.Spec{Title: "Analytics source", Description: "Sources are disabled by default. Paths and target IDs belong to this collector host. Saving does not install or start a service.", SubmitLabel: "Review", Fields: []wizard.Field{
				{Key: "id", Label: "Source ID", Value: source.ID, Required: true},
				{Key: "kind", Label: "Source type", Value: source.Kind, Kind: wizard.Select, Options: []wizard.Choice{{Value: "mihomo", Label: "Mihomo client"}, {Value: "interface", Label: "Linux host interface"}, {Value: "xray-access", Label: "Xray / V2Ray access log"}, {Value: "xray-stats", Label: "Xray / V2Ray Stats API"}, {Value: "vnstat", Label: "vnStat historical host usage"}}},
				{Key: "target", Label: "Mihomo target ID", Value: source.Target},
				{Key: "interface", Label: "Interface (host sources)", Value: source.Interface},
				{Key: "path", Label: "Access log absolute path", Value: source.Path},
				{Key: "format", Label: "Access / Stats format", Value: source.Format, Kind: wizard.Select, Options: analyticsSourceFormatChoices()},
				{Key: "source-timezone", Label: "Log timezone (blank=host local)", Value: source.Timezone},
				{Key: "binary", Label: "Stats / vnStat executable", Value: source.Binary},
				{Key: "address", Label: "Stats loopback address", Value: source.Address},
				{Key: "enabled", Label: "Enable collection", Kind: wizard.Toggle, Value: strconv.FormatBool(source.Enabled)},
			}}, cmd.InOrStdin(), cmd.OutOrStdout())
			if e != nil {
				return e
			}
			source, err = analyticsSourceFromForm(cfg.Sources, source, prefilledID, v)
			if err != nil {
				return usage("%s", err)
			}
		}
		if source.ID == "" {
			for _, name := range []string{"kind", "enabled", "interface", "path", "format", "source-timezone", "binary", "address", "server-id", "host-id", "poll-seconds"} {
				if f.Changed(name) {
					return usage("--source is required when changing source options")
				}
			}
		}
		index := -1
		for i, s := range cfg.Sources {
			if s.ID == source.ID {
				index = i
				break
			}
		}
		if source.ID != "" {
			switch source.Kind {
			case "mihomo":
				source.Scope = "client"
			case "interface", "vnstat":
				source.Scope = "host"
			case "xray-access", "xray-stats":
				source.Scope = "server"
			default:
				return usage("--kind must be mihomo, interface, xray-access, xray-stats or vnstat")
			}
			if err = analytics.ValidateSource(source); err != nil {
				return usage("%s", err)
			}
			if index < 0 {
				cfg.Sources = append(cfg.Sources, source)
			} else {
				cfg.Sources[index] = source
			}
		} else if source.Kind != "" || globalChanged(cmd, "target") {
			return usage("--source is required for source registration")
		}
		if settingsPath != "" {
			cfg.SettingsPath, err = filepath.Abs(settingsPath)
			if err != nil {
				return err
			}
		} else if source.Kind == "mihomo" && cfg.SettingsPath == "" {
			path, _, e := a.o.settingsPath(cmd)
			if e != nil {
				return e
			}
			cfg.SettingsPath, err = filepath.Abs(path)
			if err != nil {
				return err
			}
		}
		if f.Changed("timezone") {
			cfg.Timezone = timezone
			cfg.Alerts.Timezone = timezone
		}
		if f.Changed("detail-days") {
			cfg.Retention.DetailDays = detail
		}
		if f.Changed("minute-days") {
			cfg.Retention.MinuteDays = minute
		}
		if f.Changed("day-months") {
			cfg.Retention.DayMonths = months
		}
		if f.Changed("max-mib") {
			if maxMiB < 16 || maxMiB > 1<<20 {
				return usage("--max-mib must be 16–1048576")
			}
			cfg.MaxBytes = maxMiB << 20
		}
		if f.Changed("alerts-enabled") {
			cfg.Alerts.Enabled = alerts
		}
		if f.Changed("threshold-gib") {
			cfg.Alerts.ThresholdGiB = thresholds
		}
		if f.Changed("webhook-file") {
			cfg.Alerts.WebhookFile = webhookFile
			cfg.Alerts.WebhookEnv = ""
		}
		if f.Changed("webhook-env") {
			cfg.Alerts.WebhookEnv = webhookEnv
			cfg.Alerts.WebhookFile = ""
		}
		if f.Changed("webhook-file") && f.Changed("webhook-env") {
			return usage("choose --webhook-file or --webhook-env")
		}
		if err = analytics.ValidateConfig(cfg); err != nil {
			return usage("%s", err)
		}
		if stored, e := analytics.OpenStore(p.Database, true); e == nil {
			if source.ID != "" {
				err = stored.ValidateSourceConfig(cmd.Context(), source)
			}
			if err == nil && f.Changed("timezone") {
				var status analytics.Status
				status, err = stored.Status(cmd.Context())
				if err == nil && len(status.Sources) > 0 && status.Timezone != cfg.Timezone {
					err = errors.New("existing daily history uses a different timezone; use a separate analytics config/state directory")
				}
			}
			stored.Close()
			if err != nil {
				return usage("%s", err)
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if source.Kind == "mihomo" && (index < 0 || source.Enabled || globalChanged(cmd, "target") || f.Changed("kind")) {
			targets, e := a.targets(cmd, cfg, true)
			if e != nil {
				return e
			}
			found := false
			for _, t := range targets {
				if t.ID == source.Target {
					found = true
					if t.SSHHost != "" {
						return usage("target %s is SSH-based; run the collector on that host with a host-local target registration", t.ID)
					}
				}
			}
			if !found {
				return usage("target %q is not registered on this collector host", source.Target)
			}
		}
		if useForm {
			yes, err = wizard.Confirm(cmd.Context(), "Save analytics configuration", workJSON(cfg)+"\nRestart a running collector to apply changes. No service or proxy configuration is changed.", cmd.InOrStdin(), cmd.OutOrStdout())
			if err != nil {
				return err
			}
			if !yes {
				return wizard.ErrCanceled
			}
		}
		if yes {
			current, e := os.ReadFile(p.Config)
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				return e
			}
			if string(current) != string(old) {
				return errors.New("analytics configuration changed; reload before saving")
			}
			if err = analytics.SaveConfig(p.Config, cfg); err != nil {
				return err
			}
		}
		return a.o.output(cmd, map[string]any{"saved": yes, "path": p.Config, "config": cfg, "next": "Restart a running collector to apply settings. Use analytics collect or analytics service install/start to begin; source permissions are inspected by analytics doctor."})
	}
	return c
}

func (a *analyticsCLI) collectCommand() *cobra.Command {
	var duration time.Duration
	c := &cobra.Command{Use: "collect", Short: "Collect enabled local sources until canceled or the duration expires", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		if a.o.readOnly {
			return usage("collection writes analytics state and is disabled in read-only mode")
		}
		if a.host != "" {
			return usage("run collect on the collector host; use analytics service for an SSH-managed background collector")
		}
		if duration < 0 {
			return usage("--duration must not be negative")
		}
		cfg, p, err := a.load()
		if err != nil {
			return err
		}
		targets, err := a.targets(cmd, cfg)
		if err != nil {
			return err
		}
		anyEnabled := false
		for _, s := range cfg.Sources {
			anyEnabled = anyEnabled || s.Enabled
		}
		if !anyEnabled {
			return usage("no sources are enabled; use analytics setup --source ID --enabled --yes")
		}
		store, err := analytics.OpenStore(p.Database, false)
		if err != nil {
			return err
		}
		defer store.Close()
		err = analytics.RunCollector(cmd.Context(), cfg, store, targets, analytics.CollectorOptions{Duration: duration, Open: a.o.deps.Open})
		if err != nil {
			return err
		}
		status, err := store.Status(cmd.Context())
		if err != nil {
			return err
		}
		return a.o.output(cmd, status)
	}}
	c.Flags().DurationVar(&duration, "duration", 0, "stop after this duration, e.g. 10m; 0 runs until canceled")
	return c
}

func (a *analyticsCLI) statusCommand() *cobra.Command {
	return &cobra.Command{Use: "status", Short: "Read collector configuration, retained coverage and storage usage", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		if a.host != "" {
			return a.forward(cmd)
		}
		cfg, p, err := a.load()
		if err != nil {
			return err
		}
		result := map[string]any{"config": cfg, "paths": p, "state": "not-collected"}
		s, err := analytics.OpenStore(p.Database, true)
		if errors.Is(err, os.ErrNotExist) {
			return a.o.output(cmd, result)
		}
		if err != nil {
			return err
		}
		defer s.Close()
		status, err := s.Status(cmd.Context())
		if err != nil {
			return err
		}
		result["state"] = "available"
		result["storage"] = status
		if health, e := analytics.CollectorHealth(p.Database); e == nil {
			result["collector"] = health
		} else if !errors.Is(e, os.ErrNotExist) {
			result["collector_error"] = e.Error()
		}
		return a.o.output(cmd, result)
	}}
}

func (a *analyticsCLI) doctorCommand() *cobra.Command {
	return &cobra.Command{Use: "doctor", Short: "Inspect source permissions and capabilities without changing them", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		if a.host != "" {
			return a.forward(cmd)
		}
		cfg, p, err := a.load()
		if err != nil {
			return err
		}
		targets, err := a.targets(cmd, cfg)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		capabilities := analytics.DoctorWithOptions(ctx, cfg, targets, analytics.CollectorOptions{Open: a.o.deps.Open})
		service, e := analyticsservice.Run(ctx, analyticsservice.Request{Action: "status", ConfigPath: p.Config, StateDir: filepath.Dir(p.Database)}, analyticsservice.Options{})
		result := map[string]any{"sources": capabilities, "paths": p, "service": service}
		if e != nil {
			result["service_error"] = e.Error()
		}
		return a.o.output(cmd, result)
	}}
}

func (a *analyticsCLI) serviceCommand() *cobra.Command {
	c := &cobra.Command{Use: "service", Short: "Preview and operate an owned user service; never uses sudo"}
	for _, action := range []string{"install", "start", "stop", "status", "remove"} {
		action := action
		var yes bool
		var expect, binary string
		sub := &cobra.Command{Use: action, Short: action + " the user collector service", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
			if a.host != "" {
				return a.forward(cmd)
			}
			if a.o.readOnly && yes {
				return usage("service mutations are disabled in read-only mode")
			}
			p, err := a.paths()
			if err != nil {
				return err
			}
			if binary == "" && action == "install" {
				binary, err = os.Executable()
				if err != nil {
					return err
				}
				if err := serverReviewFlags(yes, expect); err != nil {
					return err
				}
			}
			r, err := analyticsservice.Run(cmd.Context(), analyticsservice.Request{Action: action, Executable: binary, ConfigPath: p.Config, StateDir: filepath.Dir(p.Database), Apply: yes, Expect: expect}, analyticsservice.Options{ReadOnly: a.o.readOnly})
			if err != nil {
				return err
			}
			return a.o.output(cmd, r)
		}}
		if action != "status" {
			sub.Flags().BoolVar(&yes, "yes", false, "apply the reviewed action")
			sub.Flags().StringVar(&expect, "expect", "", "digest from the action preview")
		}
		if action == "install" {
			sub.Flags().StringVar(&binary, "executable", "", "existing native lazyclash executable to copy into owned service storage")
		}
		c.AddCommand(sub)
	}
	return c
}

func (a *analyticsCLI) importCommand() *cobra.Command {
	var source, file string
	c := &cobra.Command{Use: "import-vnstat", Short: "Import available completed vnStat JSON intervals without inventing history", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		if a.host != "" {
			return usage("import-vnstat reads a host-local file; run it on the collecting host")
		}
		if a.o.readOnly {
			return usage("import writes analytics state and is disabled in read-only mode")
		}
		if source == "" || file == "" {
			return usage("--source and --file (or '-') are required")
		}
		cfg, p, err := a.load()
		if err != nil {
			return err
		}
		var in io.Reader = cmd.InOrStdin()
		if file != "-" {
			f, e := os.Open(file)
			if e != nil {
				return e
			}
			defer f.Close()
			in = f
		}
		s, err := analytics.OpenStore(p.Database, false)
		if err != nil {
			return err
		}
		defer s.Close()
		r, err := analytics.ImportVNStat(cmd.Context(), s, cfg, source, in)
		if err != nil {
			return err
		}
		return a.o.output(cmd, r)
	}}
	c.Flags().StringVar(&source, "source", "", "configured vnstat source ID")
	c.Flags().StringVar(&file, "file", "", "vnstat --json file or '-' for stdin")
	return c
}

func (a *analyticsCLI) alertsCommand() *cobra.Command {
	c := &cobra.Command{Use: "alerts", Short: "Inspect or evaluate daily host TX threshold alerts"}
	c.AddCommand(&cobra.Command{Use: "list", Short: "Read saved alert delivery state", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		if a.host != "" {
			return a.forward(cmd)
		}
		p, err := a.paths()
		if err != nil {
			return err
		}
		s, err := analytics.OpenStore(p.Database, true)
		if err != nil {
			return err
		}
		defer s.Close()
		rows, err := s.Alerts(cmd.Context(), 100)
		if err != nil {
			return err
		}
		return a.o.output(cmd, rows)
	}})
	var send bool
	eval := &cobra.Command{Use: "evaluate", Short: "Record crossed thresholds; optionally deliver configured pending alerts", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		if a.host != "" {
			return a.forward(cmd)
		}
		if a.o.readOnly {
			return usage("alert evaluation writes state and is disabled in read-only mode")
		}
		cfg, p, err := a.load()
		if err != nil {
			return err
		}
		s, err := analytics.OpenStore(p.Database, false)
		if err != nil {
			return err
		}
		defer s.Close()
		rows, err := s.EvaluateAlerts(cmd.Context(), cfg.Alerts, time.Now())
		if err != nil {
			return err
		}
		if send {
			if err = s.DeliverAlerts(cmd.Context(), cfg.Alerts); err != nil {
				return err
			}
		}
		return a.o.output(cmd, rows)
	}}
	eval.Flags().BoolVar(&send, "send", false, "send pending alerts through the configured webhook reference")
	c.AddCommand(eval)
	return c
}

// Calendar windows use the selected civil timezone; explicit RFC3339 bounds
// retain their offsets. End is exclusive, including at month boundaries.
func analyticsWindow(now time.Time, period, from, to, zone string) (time.Time, time.Time, error) {
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return time.Time{}, time.Time{}, usage("invalid timezone")
	}
	n := now.In(loc)
	start := time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, loc)
	switch period {
	case "day":
	case "week":
		start = start.AddDate(0, 0, -(int(n.Weekday())+6)%7)
	case "month":
		start = time.Date(n.Year(), n.Month(), 1, 0, 0, 0, 0, loc)
	default:
		return start, now, usage("--period must be day, week or month")
	}
	end := now
	parse := func(v string) (time.Time, error) {
		if t, e := time.Parse(time.RFC3339, v); e == nil {
			return t, nil
		}
		return time.ParseInLocation("2006-01-02", v, loc)
	}
	if (from == "") != (to == "") {
		return start, end, usage("use --from and --to together (end exclusive)")
	}
	if from != "" {
		start, err = parse(from)
		if err != nil {
			return start, end, usage("invalid --from; use YYYY-MM-DD or RFC3339")
		}
		end, err = parse(to)
		if err != nil {
			return start, end, usage("invalid --to; use YYYY-MM-DD or RFC3339")
		}
	}
	if !end.After(start) {
		return start, end, usage("report end must be after start")
	}
	return start, end, nil
}

func (a *analyticsCLI) reportCommand() *cobra.Command {
	var q analytics.Query
	var period, from, to, zone string
	var alsoHosts []string
	var interactive bool
	c := &cobra.Command{Use: "report", Short: "Read day/week/month history without starting collection", Args: argsExact(0)}
	f := c.Flags()
	f.StringVar(&period, "period", "day", "calendar day, week (Monday) or month")
	f.StringVar(&from, "from", "", "inclusive YYYY-MM-DD or RFC3339 boundary")
	f.StringVar(&to, "to", "", "exclusive YYYY-MM-DD or RFC3339 boundary")
	f.StringVar(&zone, "timezone", "", "display/calendar timezone; defaults to saved analytics timezone")
	f.StringVar(&q.SourceID, "source", "", "one observation source; scopes are never summed")
	f.StringVar(&q.GroupBy, "group-by", "source", "source, domain, process, route, ip or principal")
	f.StringVar(&q.Domain, "domain", "", "exact observed domain filter")
	f.StringVar(&q.Process, "process", "", "exact observed process filter")
	f.StringVar(&q.Route, "route", "", "exact observed routing chain filter")
	f.StringVar(&q.IP, "ip", "", "exact observed source IP filter")
	f.StringVar(&q.Principal, "principal", "", "exact observed authentication label filter")
	f.IntVar(&q.Limit, "limit", 100, "maximum report rows (1–1000)")
	f.BoolVar(&interactive, "interactive", false, "open the historical analytics browser")
	f.StringSliceVar(&alsoHosts, "also-host", nil, "also query these SSH collector aliases; 'local' adds this machine (extra collectors use their default config/state)")
	c.RunE = func(cmd *cobra.Command, _ []string) error {
		if interactive && (a.o.json || !a.o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout())) {
			return usage("--interactive requires a terminal and cannot use --json")
		}
		if q.Limit < 1 || q.Limit > 1000 {
			return usage("--limit must be 1–1000")
		}
		if len(alsoHosts) > 7 {
			return usage("at most eight collectors can be queried together")
		}
		federated := len(alsoHosts) > 0 || strings.Contains(q.SourceID, "::")
		if a.host != "" && !interactive && !federated {
			return a.forward(cmd)
		}
		if !strings.Contains("|source|domain|process|route|ip|principal|", "|"+q.GroupBy+"|") {
			return usage("invalid --group-by")
		}
		cfg, p, err := a.load()
		var initialWarning string
		if a.host != "" {
			args := []string{"status", "--json"}
			for _, pair := range [][2]string{{"--analytics-config", a.configPath}, {"--state-dir", a.stateDir}} {
				if pair[1] != "" {
					args = append(args, pair[0], pair[1])
				}
			}
			var raw []byte
			raw, err = remoteAnalytics(cmd.Context(), a.host, a.remoteBinary, args)
			if err == nil {
				var remote struct {
					Config analytics.Config `json:"config"`
				}
				err = json.Unmarshal(raw, &remote)
				cfg = remote.Config
			}
			if err != nil && len(alsoHosts) > 0 {
				cfg = analytics.DefaultConfig()
				err = nil
				if zone == "" {
					initialWarning = "Primary collector settings unavailable; calendar window uses default Asia/Shanghai. Individual collector failures are shown separately."
				}
			}
		}
		if err != nil {
			return err
		}
		if zone == "" {
			zone = cfg.Timezone
		}
		q.Timezone = zone
		q.From, q.To, err = analyticsWindow(time.Now(), period, from, to, zone)
		if err != nil {
			return err
		}
		localPaths := p
		if a.host != "" {
			localPaths, err = analytics.DefaultPaths()
			if err != nil {
				return err
			}
		}
		loadOne := func(ctx context.Context, host string, primary bool, query analytics.Query) (analytics.Report, error) {
			if host != "" {
				args := []string{"report", "--from", query.From.Format(time.RFC3339), "--to", query.To.Format(time.RFC3339), "--timezone", query.Timezone, "--group-by", query.GroupBy, "--limit", strconv.Itoa(query.Limit), "--json"}
				for _, pair := range [][2]string{{"--source", query.SourceID}, {"--domain", query.Domain}, {"--process", query.Process}, {"--route", query.Route}, {"--ip", query.IP}, {"--principal", query.Principal}} {
					if pair[1] != "" {
						args = append(args, pair[0], pair[1])
					}
				}
				if primary {
					for _, pair := range [][2]string{{"--analytics-config", a.configPath}, {"--state-dir", a.stateDir}} {
						if pair[1] != "" {
							args = append(args, pair[0], pair[1])
						}
					}
				}
				out, e := remoteAnalytics(ctx, host, a.remoteBinary, args)
				if e != nil {
					return analytics.Report{}, e
				}
				var r analytics.Report
				if e = json.Unmarshal(out, &r); e != nil {
					return r, errors.New("invalid remote report")
				}
				return r, nil
			}
			s, e := analytics.OpenStore(localPaths.Database, true)
			if errors.Is(e, os.ErrNotExist) {
				return analytics.Report{From: query.From, To: query.To, Timezone: query.Timezone, GroupBy: query.GroupBy, Rows: []analytics.ReportRow{}, Coverage: []analytics.Coverage{}, Warnings: []string{"No history has been collected. Configure and enable a source, then run analytics collect."}}, nil
			}
			if e != nil {
				return analytics.Report{}, e
			}
			defer s.Close()
			return s.Report(ctx, query)
		}
		load := func(ctx context.Context, query analytics.Query) (analytics.Report, error) {
			return loadOne(ctx, a.host, true, query)
		}
		if federated {
			primaryID := "local"
			if a.host != "" {
				primaryID = "ssh/" + a.host
			}
			collectors := []analyticsCollector{{ID: primaryID, Load: load}}
			for _, host := range alsoHosts {
				if strings.TrimSpace(host) == "" {
					return usage("collector alias cannot be empty")
				}
				host := host
				id := "ssh/" + host
				if host == "local" {
					host = ""
					id = "local"
				}
				collectors = append(collectors, analyticsCollector{ID: id, Load: func(ctx context.Context, query analytics.Query) (analytics.Report, error) {
					return loadOne(ctx, host, false, query)
				}})
			}
			load = func(ctx context.Context, query analytics.Query) (analytics.Report, error) {
				r, err := federatedAnalytics(ctx, query, collectors)
				if initialWarning != "" {
					r.Warnings = append(r.Warnings, initialWarning)
				}
				return r, err
			}
		}
		if interactive {
			return tui.RunAnalytics(cmd.Context(), tui.AnalyticsOptions{Query: q, Load: load, TargetID: a.o.target, ReadOnly: a.o.readOnly, Diagnose: func(ctx context.Context, targetID, domain, via string) (string, error) {
				settings, _, e := a.o.load(cmd)
				if e != nil {
					return "", e
				}
				var target config.Target
				for _, t := range settings.Targets {
					if t.ID == targetID {
						target = t
						break
					}
				}
				if target.ID == "" {
					return "", fmt.Errorf("select a registered client target ID")
				}
				r, e := diagnostics.RunURL(ctx, target, "https://"+domain, diagnostics.URLOptions{Options: a.o.diagnosticOptions(), Via: via})
				if e != nil {
					return "", e
				}
				return diagnostics.FormatURL(r), nil
			}}, cmd.InOrStdin(), cmd.OutOrStdout())
		}
		r, err := load(cmd.Context(), q)
		if err != nil {
			return err
		}
		if a.o.json {
			return a.o.output(cmd, r)
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), tui.FormatAnalyticsReport(r))
		return err
	}
	return c
}
