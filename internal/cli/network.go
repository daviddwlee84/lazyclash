package cli

import (
	"fmt"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/networkcheck"
	"github.com/spf13/cobra"
)

func (o *options) diagnosticNetworkCommand() *cobra.Command {
	return &cobra.Command{Use: "network", Short: "Inspect passive host VPN, TUN, routing and scoped DNS evidence", Long: "Inspect the local host by default, an explicit --ssh host, or an explicitly selected target's host. No traffic tests, routes, DNS, VPN services or system proxy settings are changed. A running VPN process is evidence, not proof of traffic interception.", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		defer connection.CloseAuthentications()
		target := config.Target{SSHHost: o.ssh}
		inspectCore := o.target != "" || o.controller != ""
		if inspectCore {
			cfg, _, err := o.load(cmd)
			if err != nil {
				return err
			}
			var e error
			target, _, e = o.choose(cmd, cfg)
			if e != nil {
				return e
			}
		}
		var report networkcheck.Report
		err := o.authenticatedDiagnostic(cmd, target, func() error {
			var e error
			report, e = networkcheck.Inspect(cmd.Context(), target.SSHHost)
			return e
		})
		if err != nil {
			return err
		}
		if inspectCore && target.Controller != "" {
			client, closer, e := o.deps.Open(cmd.Context(), target, true)
			if closer != nil {
				defer closer.Close()
			}
			if e == nil && client != nil {
				defer client.Close()
				settings, e := client.Config(cmd.Context())
				if e == nil {
					if tun, ok := settings["tun"].(map[string]any); ok {
						if enabled, known := tun["enable"].(bool); known {
							device, _ := tun["device"].(string)
							report = networkcheck.WithCoreTUNDevice(report, enabled, device)
						}
					}
				}
				if e != nil {
					report.Conflicts = append(report.Conflicts, networkcheck.Finding{Code: "core-tun-unavailable", Level: "warning", Confidence: "unknown", Message: "Controller TUN state is unavailable; host evidence remains available."})
				}
			} else {
				report.Conflicts = append(report.Conflicts, networkcheck.Finding{Code: "core-tun-unavailable", Level: "warning", Confidence: "unknown", Message: "Controller TUN state is unavailable; host evidence remains available."})
			}
		}
		if o.json {
			return o.output(cmd, report)
		}
		_, err = fmt.Fprint(cmd.OutOrStdout(), networkcheck.Format(report))
		return err
	}}
}
