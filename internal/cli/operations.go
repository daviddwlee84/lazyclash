package cli

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/spf13/cobra"
)

func (o *options) statusCommand() *cobra.Command {
	return &cobra.Command{Use: "status", Short: "Read core version and runtime settings", Args: argsExact(0), RunE: func(cmd *cobra.Command, args []string) error {
		return o.withClient(cmd, func(c *core.Client, t config.Target) error {
			version, err := c.Version(cmd.Context())
			if err != nil {
				return err
			}
			settings, err := c.Config(cmd.Context())
			if err != nil {
				return err
			}
			return o.output(cmd, core.Object{"target": t.ID, "controller": t.Controller, "version": version, "config": settings})
		})
	}}
}

func (o *options) proxyCommands() *cobra.Command {
	group := &cobra.Command{Use: "proxies", Short: "Inspect groups, select a member and test latency"}
	var filter string
	list := &cobra.Command{Use: "list", Short: "List proxies and groups", Args: argsExact(0), RunE: func(cmd *cobra.Command, args []string) error {
		return o.withClient(cmd, func(c *core.Client, t config.Target) error {
			proxies, err := c.Proxies(cmd.Context())
			if err != nil {
				return err
			}
			for name, p := range proxies {
				if !strings.Contains(strings.ToLower(name+" "+p.Type), strings.ToLower(filter)) {
					delete(proxies, name)
				}
			}
			if o.json {
				return o.output(cmd, proxies)
			}
			keys := make([]string, 0, len(proxies))
			for key := range proxies {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tTYPE\tCURRENT\tDELAY")
			for _, name := range keys {
				p := proxies[name]
				delay := "unknown"
				if len(p.History) > 0 {
					delay = fmt.Sprintf("%d ms", p.History[len(p.History)-1].Delay)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", core.Sanitize(name), core.Sanitize(p.Type), core.Sanitize(p.Now), delay)
			}
			return w.Flush()
		})
	}}
	list.Flags().StringVar(&filter, "filter", "", "case-insensitive name/type filter")
	group.AddCommand(list, &cobra.Command{Use: "select GROUP MEMBER", Short: "Select a group member and verify the result", Args: argsExact(2), RunE: func(cmd *cobra.Command, args []string) error {
		if e := o.writable(); e != nil {
			return e
		}
		return o.withClient(cmd, func(c *core.Client, t config.Target) error {
			if e := c.Select(cmd.Context(), args[0], args[1]); e != nil {
				return e
			}
			return o.result(cmd, "Selected "+args[0]+" → "+args[1]+" on "+t.ID)
		})
	}}, &cobra.Command{Use: "delay NAME", Short: "Test one proxy without resetting group selections", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		if e := o.writable(); e != nil {
			return e
		}
		return o.withClient(cmd, func(c *core.Client, t config.Target) error {
			data, e := c.Delay(cmd.Context(), args[0])
			if e != nil {
				return e
			}
			return o.output(cmd, data)
		})
	}})
	return group
}

func (o *options) connectionCommands() *cobra.Command {
	group := &cobra.Command{Use: "connections", Short: "Inspect or close active connections"}
	group.AddCommand(&cobra.Command{Use: "list", Short: "Read active connections and matched rules", Args: argsExact(0), RunE: func(cmd *cobra.Command, args []string) error {
		return o.withClient(cmd, func(c *core.Client, t config.Target) error {
			v, e := c.Connections(cmd.Context())
			if e != nil {
				return e
			}
			return o.output(cmd, v)
		})
	}})
	var all, yes bool
	closeCmd := &cobra.Command{Use: "close [ID]", Short: "Close a connection, or all with --all --yes", Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 1 {
			return usage("connections close accepts one ID or --all --yes")
		}
		return nil
	}, RunE: func(cmd *cobra.Command, args []string) error {
		if e := o.writable(); e != nil {
			return e
		}
		if all && len(args) != 0 {
			return usage("choose an ID or --all, not both")
		}
		if !all && len(args) != 1 {
			return usage("supply a connection ID or --all --yes")
		}
		if all && !yes {
			return usage("closing all connections requires --all --yes")
		}
		id := ""
		if len(args) > 0 {
			id = args[0]
			if strings.TrimSpace(id) == "" {
				return usage("connection ID cannot be empty; closing all connections requires --all --yes")
			}
		}
		return o.withClient(cmd, func(c *core.Client, t config.Target) error {
			if e := c.CloseConnections(cmd.Context(), id); e != nil {
				return e
			}
			return o.result(cmd, "Connections closed on "+t.ID)
		})
	}}
	closeCmd.Flags().BoolVar(&all, "all", false, "close all active connections")
	closeCmd.Flags().BoolVar(&yes, "yes", false, "confirm closing every connection")
	group.AddCommand(closeCmd)
	return group
}

func (o *options) logsCommand() *cobra.Command {
	var level, filter string
	var duration time.Duration
	var limit int
	cmd := &cobra.Command{Use: "logs", Short: "Follow core logs (NDJSON with --json)", Args: argsExact(0), RunE: func(cmd *cobra.Command, args []string) error {
		switch level {
		case "debug", "info", "warning", "error":
		default:
			return usage("--level must be debug, info, warning or error")
		}
		if duration < 0 || limit < 0 {
			return usage("--duration and --limit must be zero or positive")
		}
		return o.withClient(cmd, func(c *core.Client, t config.Target) error {
			filter := strings.ToLower(filter)
			return c.StreamWithOptions(cmd.Context(), "logs", url.Values{"level": {level}}, core.StreamOptions{Duration: duration, Limit: limit}, func(entry core.Object) (bool, error) {
				payload := fmt.Sprint(entry["payload"])
				if !strings.Contains(strings.ToLower(payload), filter) {
					return false, nil
				}
				var writeErr error
				if o.json {
					writeErr = o.output(cmd, entry)
				} else {
					_, writeErr = fmt.Fprintf(cmd.OutOrStdout(), "[%s] %s\n", core.Sanitize(fmt.Sprint(entry["type"])), core.Sanitize(payload))
				}
				return writeErr == nil, writeErr
			})
		})
	}}
	cmd.Flags().StringVar(&level, "level", "info", "minimum severity: debug, info, warning, error")
	cmd.Flags().StringVar(&filter, "filter", "", "case-insensitive payload filter")
	cmd.Flags().DurationVar(&duration, "duration", 0, "stop after collecting for this duration (e.g. 30s; 0 is unlimited)")
	cmd.Flags().IntVar(&limit, "limit", 0, "stop after this many matching records (0 is unlimited)")
	return cmd
}

func (o *options) rulesCommand() *cobra.Command {
	var filter string
	group := &cobra.Command{Use: "rules", Short: "Inspect runtime rules in matching order"}
	list := &cobra.Command{Use: "list", Short: "List ordered rules", Args: argsExact(0), RunE: func(cmd *cobra.Command, args []string) error {
		return o.withClient(cmd, func(c *core.Client, t config.Target) error {
			v, e := c.Rules(cmd.Context())
			if e != nil {
				return e
			}
			if filter != "" {
				if rows, ok := v["rules"].([]any); ok {
					filtered := make([]any, 0)
					for _, row := range rows {
						if strings.Contains(strings.ToLower(fmt.Sprint(row)), strings.ToLower(filter)) {
							filtered = append(filtered, row)
						}
					}
					v["rules"] = filtered
				}
			}
			return o.output(cmd, v)
		})
	}}
	list.Flags().StringVar(&filter, "filter", "", "case-insensitive rule filter")
	group.AddCommand(list)
	return group
}

func providerKind(kind string) error {
	if kind != "proxies" && kind != "rules" {
		return usage("provider kind must be proxies or rules")
	}
	return nil
}
func (o *options) providerCommands() *cobra.Command {
	group := &cobra.Command{Use: "providers", Short: "Inspect and update proxy/rule providers"}
	group.AddCommand(&cobra.Command{Use: "list [proxies|rules]", Short: "List providers", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		if e := providerKind(args[0]); e != nil {
			return e
		}
		return o.withClient(cmd, func(c *core.Client, t config.Target) error {
			v, e := c.Providers(cmd.Context(), args[0])
			if e != nil {
				return e
			}
			return o.output(cmd, v)
		})
	}}, &cobra.Command{Use: "update [proxies|rules] NAME", Short: "Refresh a provider from its configured source", Args: argsExact(2), RunE: func(cmd *cobra.Command, args []string) error {
		if e := providerKind(args[0]); e != nil {
			return e
		}
		if e := o.writable(); e != nil {
			return e
		}
		return o.withClient(cmd, func(c *core.Client, t config.Target) error {
			if e := c.UpdateProvider(cmd.Context(), args[0], args[1]); e != nil {
				return e
			}
			v, e := c.Providers(cmd.Context(), args[0])
			if e != nil {
				return fmt.Errorf("provider update accepted; refresh failed: %w", e)
			}
			return o.output(cmd, v)
		})
	}}, &cobra.Command{Use: "healthcheck NAME", Short: "Run a proxy-provider healthcheck", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		if e := o.writable(); e != nil {
			return e
		}
		return o.withClient(cmd, func(c *core.Client, t config.Target) error {
			if e := c.HealthcheckProvider(cmd.Context(), args[0]); e != nil {
				return e
			}
			return o.result(cmd, "Healthcheck requested for "+args[0]+" on "+t.ID)
		})
	}})
	return group
}

func (o *options) patch(cmd *cobra.Command, patch core.Object) error {
	if e := o.writable(); e != nil {
		return e
	}
	return o.withClient(cmd, func(c *core.Client, t config.Target) error {
		v, e := c.SetConfig(cmd.Context(), patch)
		if e != nil {
			return e
		}
		return o.output(cmd, v)
	})
}

func (o *options) modeCommand() *cobra.Command {
	return &cobra.Command{Use: "mode [rule|global|direct]", Short: "Change routing mode and verify", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "rule", "global", "direct":
		default:
			return usage("mode must be rule, global or direct")
		}
		return o.patch(cmd, core.Object{"mode": args[0]})
	}}
}
func onOff(value string) (bool, error) {
	switch value {
	case "on":
		return true, nil
	case "off":
		return false, nil
	default:
		return false, usage("expected on or off")
	}
}
func (o *options) tunCommand() *cobra.Command {
	return &cobra.Command{Use: "tun [on|off]", Short: "Toggle core TUN (requires a privileged core)", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		enabled, e := onOff(args[0])
		if e != nil {
			return e
		}
		return o.patch(cmd, core.Object{"tun": core.Object{"enable": enabled}})
	}}
}
func (o *options) allowLANCommand() *cobra.Command {
	return &cobra.Command{Use: "allow-lan [on|off]", Short: "Change whether proxy listeners accept LAN connections", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		enabled, e := onOff(args[0])
		if e != nil {
			return e
		}
		return o.patch(cmd, core.Object{"allow-lan": enabled})
	}}
}
