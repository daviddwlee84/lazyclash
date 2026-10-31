package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/doctor"
	"github.com/spf13/cobra"
)

func (o *options) doctorCommand() *cobra.Command {
	timeout := doctor.DefaultTimeout
	cmd := &cobra.Command{
		Use:     "doctor",
		Short:   "Report local proxy health using passive, read-only evidence",
		Long:    "Collect local controller identity/runtime, process proxy variables, system proxy settings and host network metadata. Never opens SSH, tests egress, saves discovery or changes proxy state. Remote targets are unsupported, not replaced with a local target. Optional host tools may be unavailable.",
		Example: "  lazyclash doctor\n  lazyclash doctor --json\n  lazyclash --target LOCAL doctor\n  lazyclash --controller http://127.0.0.1:9090 doctor --timeout 5s",
		Args:    argsExact(0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if timeout <= 0 {
				return usage("--timeout must be greater than zero")
			}
			id, controller := o.target, o.controller
			if !globalChanged(cmd, "target") && !globalChanged(cmd, "controller") {
				id, controller = os.Getenv("LAZYCLASH_TARGET"), os.Getenv("LAZYCLASH_CONTROLLER")
				if id == "" && controller == "" {
					controller = os.Getenv("CLASH_CONTROLLER")
				}
				if id != "" && controller != "" {
					return usage("set only one of LAZYCLASH_TARGET or LAZYCLASH_CONTROLLER")
				}
			}
			if controller != "" {
				if !strings.Contains(controller, "://") {
					controller = "http://" + controller
				}
				if config.ValidateController(controller) != nil {
					return usage("invalid --controller; use an HTTP(S) URL without credentials/query/fragment, or unix:///absolute/socket")
				}
			}
			path, explicit, pathErr := o.settingsPath(cmd)
			opts := o.deps.Doctor
			if opts.Open == nil {
				opts.Open = o.deps.Open
			}
			if pathErr != nil {
				// Settings failures belong in the report; host collectors still run.
				opts.Load = func(string, bool) (config.Config, error) { return config.Config{}, pathErr }
			}
			report := doctor.Run(cmd.Context(), doctor.Request{SettingsPath: path, ExplicitSettings: explicit, TargetID: id, Controller: controller, SSHHost: o.ssh, SecretEnv: o.secretEnv, SecretFile: o.secretFile, CAFile: o.caFile, Timeout: timeout}, opts)
			var err error
			if o.json {
				err = o.output(cmd, report)
			} else {
				_, err = fmt.Fprint(cmd.OutOrStdout(), doctor.Format(report))
			}
			if err != nil {
				return err
			}
			if report.Summary.ExitCode != 0 {
				return &reportedOutcome{code: report.Summary.ExitCode}
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", doctor.DefaultTimeout, "overall diagnostic deadline (includes all collectors)")
	return cmd
}
