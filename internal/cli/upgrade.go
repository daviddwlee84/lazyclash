package cli

import (
	"fmt"
	"io"

	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/selfupdate"
	"github.com/spf13/cobra"
)

func (o *options) upgradeCommand() *cobra.Command {
	var request selfupdate.Request
	cmd := &cobra.Command{
		Use: "upgrade", Short: "Check or upgrade this local lazyclash executable",
		Long: `Upgrade the running executable to the latest stable lazyclash release.
The resolved executable path is retained, including for moved Go release binaries.
Use --check to inspect the version, build source, destination and update method.
Development builds require --force; package-managed or unknown binaries are never
overwritten. Archive installations use checksummed platform assets; Go source installations
require Go. Neither method installs a missing toolchain.

This command runs without prompting, including in pipelines. It does not load
lazyclash settings, contact a controller, upgrade Mihomo or modify a Git checkout.
--read-only governs core operations; use upgrade --check to prevent a local update.
With --json, stdout is one result object and failures use the usual stderr error
envelope. Build progress is suppressed in JSON mode.`,
		Example: "  lazyclash upgrade --check\n  lazyclash upgrade --check --json\n  lazyclash upgrade\n  lazyclash upgrade --force",
		Args:    argsExact(0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			var progress io.Writer = cmd.ErrOrStderr()
			if o.json {
				progress = io.Discard
			}
			result, err := o.deps.Upgrade(cmd.Context(), request, progress)
			if err != nil {
				return err
			}
			if o.json {
				return o.output(cmd, result)
			}
			return printUpgrade(cmd.OutOrStdout(), result)
		},
	}
	cmd.Flags().BoolVar(&request.Check, "check", false, "inspect versions and update method without writing files")
	cmd.Flags().BoolVar(&request.Force, "force", false, "reinstall the latest stable release, including replacing a development build")
	return cmd
}

func printUpgrade(out io.Writer, r selfupdate.Result) error {
	clean := func(s string) string { return core.Sanitize(s) }
	_, err := fmt.Fprintf(out, "Current: %s\nLatest stable: %s\nBuild: %s\nMethod: %s\nExecutable: %s\nDestination: %s\n",
		clean(r.CurrentVersion), clean(r.LatestVersion), clean(r.Installation.BuildKind), clean(r.Installation.Method),
		clean(r.Installation.Executable), clean(r.Installation.ResolvedPath))
	if err != nil {
		return err
	}
	if _, err = fmt.Fprintf(out, "Update available: %t\nCan upgrade here: %t\n", r.UpdateAvailable, r.CanUpgrade); err != nil {
		return err
	}
	if r.Installation.Manager != "" {
		if _, err = fmt.Fprintln(out, "Managed by:", clean(r.Installation.Manager)); err != nil {
			return err
		}
	}
	for _, evidence := range r.Installation.Evidence {
		if _, err = fmt.Fprintln(out, "Detected:", clean(evidence)); err != nil {
			return err
		}
	}
	label := r.Status
	if r.Status == "updated" {
		label = "Updated to " + r.LatestVersion + "; start a new invocation to use it."
	}
	if _, err = fmt.Fprintln(out, clean(label)); err != nil {
		return err
	}
	if r.Reason != "" {
		if _, err = fmt.Fprintln(out, clean(r.Reason)); err != nil {
			return err
		}
	}
	if r.ReleaseURL != "" {
		_, err = fmt.Fprintln(out, "Release notes:", clean(r.ReleaseURL))
	}
	return err
}
