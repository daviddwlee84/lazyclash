package cli

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/topology"
	"github.com/daviddwlee84/lazyclash/internal/tui"
	"github.com/spf13/cobra"
)

func (o *options) topologyCommand() *cobra.Command {
	var file, sourcePath, format, view, focus string
	var live, interactive bool
	c := &cobra.Command{Use: "topology", Short: "Inspect YAML routing relationships, optionally overlay current selections", Args: argsExact(0)}
	c.RunE = func(cmd *cobra.Command, _ []string) error {
		defer connection.CloseAuthentications()
		if format != "ascii" && format != "mermaid" {
			return usage("--format must be ascii or mermaid")
		}
		if view != "graph" && view != "relations" {
			return usage("--view must be graph or relations")
		}
		if o.json && cmd.Flags().Changed("format") {
			return usage("--json and --format are mutually exclusive")
		}
		if format == "mermaid" && view == "relations" {
			return usage("Mermaid output requires --view graph")
		}
		if _, e := o.sourceInteractive(cmd, interactive, false); e != nil {
			return e
		}
		if file != "" && (sourcePath != "" || live || globalChanged(cmd, "target") || globalChanged(cmd, "controller") || globalChanged(cmd, "ssh")) {
			return usage("--file is an offline local input; use --source-path for a target-host file")
		}
		var target config.Target
		var stdin []byte
		var err error
		if file == "-" {
			stdin, err = boundedInput(cmd, file, "")
			if err != nil {
				return err
			}
		}
		if file == "" {
			target, err = o.configWorkTarget(cmd)
			if err != nil {
				return err
			}
		}
		load := func(ctx context.Context, withLive bool) (topology.Graph, error) {
			if file != "" {
				raw := stdin
				if file != "-" {
					var e error
					raw, e = boundedInput(cmd, file, "")
					if e != nil {
						return topology.Graph{}, e
					}
				}
				return topology.Parse(raw, topology.Source{Kind: "yaml", Path: file})
			}
			return topology.Read(ctx, target, sourcePath, withLive, o.configWorkOptions(cmd))
		}
		if interactive {
			return tui.RunTopology(cmd.Context(), tui.TopologyOptions{
				Load: load, Live: live, CanLive: file == "", Focus: focus, View: view, Format: format,
				Authenticate: func(ctx context.Context, cause error) (*exec.Cmd, error) {
					host := target.SSHHost
					var auth *connection.AuthRequiredError
					if errors.As(cause, &auth) {
						host = auth.Host
					}
					return o.deps.Authenticate(ctx, host)
				},
			}, cmd.InOrStdin(), cmd.OutOrStdout())
		}
		var g topology.Graph
		err = o.authenticatedDiagnostic(cmd, target, func() error {
			var e error
			g, e = load(cmd.Context(), live)
			return e
		})
		if err != nil {
			return err
		}
		g, err = g.Focus(focus)
		if err != nil {
			return usage("%s", err)
		}
		if o.json {
			return o.output(cmd, g)
		}
		if format == "mermaid" {
			fmt.Fprintln(cmd.ErrOrStderr(), g.Summary())
			_, err = fmt.Fprint(cmd.OutOrStdout(), topology.Mermaid(g))
			return err
		}
		body := g.Relations()
		if view == "graph" {
			if drawn, e := topology.ASCII(g, 100); e == nil {
				body = drawn
			} else {
				fmt.Fprintln(cmd.ErrOrStderr(), e)
			}
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), g.Summary()+"\n\n"+body)
		return err
	}
	c.Flags().StringVar(&file, "file", "", "local YAML file or '-' for stdin (offline)")
	c.Flags().StringVar(&sourcePath, "source-path", "", "explicit YAML path on the selected target's host")
	c.Flags().BoolVar(&live, "live", false, "read current selections and provider members; no active probes")
	c.Flags().StringVar(&format, "format", "ascii", "ascii or mermaid")
	c.Flags().StringVar(&view, "view", "graph", "graph or relations")
	c.Flags().StringVar(&focus, "focus", "", "node name or ID: include its ancestors and descendants")
	c.Flags().BoolVar(&interactive, "interactive", false, "open the searchable topology browser")
	return c
}
