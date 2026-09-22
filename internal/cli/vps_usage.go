package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
	"github.com/daviddwlee84/lazyclash/internal/tui"
	"github.com/daviddwlee84/lazyclash/internal/vps"
	"github.com/spf13/cobra"
)

func (o *options) vpsBindCloudCommand() *cobra.Command {
	var binding serverstate.CloudObservationBinding
	var yes bool
	var expect string
	cmd := &cobra.Command{Use: "bind-cloud ID", Short: "Review a read-only cloud resource binding for usage monitoring", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		if err := serverReviewFlags(yes, expect); err != nil {
			return err
		}
		service, err := o.vpsService(cmd)
		if err != nil {
			return err
		}
		if yes {
			host, e := service.BindCloud(cmd.Context(), args[0], binding, expect)
			if e != nil {
				return e
			}
			return o.output(cmd, host)
		}
		preview, err := service.PlanBindCloud(cmd.Context(), args[0], binding)
		if err != nil {
			return err
		}
		return o.output(cmd, preview)
	}}
	cmd.Flags().StringVar(&binding.Provider, "provider", "", "oracle or azure")
	cmd.Flags().StringVar(&binding.Profile, "profile", "", "Oracle CLI profile (default: CLI default)")
	cmd.Flags().StringVar(&binding.Region, "region", "", "cloud region containing the VM")
	cmd.Flags().StringVar(&binding.ResourceID, "resource-id", "", "Oracle instance OCID or Azure VM resource ID")
	cmd.Flags().StringVar(&binding.TenancyID, "tenancy", "", "Oracle tenancy OCID")
	cmd.Flags().StringVar(&binding.CompartmentID, "compartment", "", "optional Oracle compartment OCID; otherwise read from the instance")
	cmd.Flags().StringVar(&binding.SubscriptionID, "subscription", "", "explicit Azure subscription UUID")
	cmd.Flags().BoolVar(&yes, "yes", false, "save the reviewed observation binding; cloud ownership remains unchanged")
	cmd.Flags().StringVar(&expect, "expect", "", "reviewed preview digest")
	return cmd
}

func (o *options) vpsUsageCommand() *cobra.Command    { return o.cloudUsageCommand(false) }
func (o *options) serverUsageCommand() *cobra.Command { return o.cloudUsageCommand(true) }
func (o *options) cloudUsageCommand(server bool) *cobra.Command {
	var month string
	cmd := &cobra.Command{Use: "usage ID", Short: "Read UTC-month VM traffic and separate provider billing meters", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		service, err := o.vpsService(cmd)
		if err != nil {
			return err
		}
		var report vps.UsageReport
		if server {
			report, err = service.UsageForServerMonth(cmd.Context(), args[0], month)
		} else {
			report, err = service.UsageMonth(cmd.Context(), args[0], month)
		}
		if err != nil {
			return err
		}
		if o.json {
			return o.output(cmd, report)
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), usageReportText(report))
		return err
	}}
	cmd.Flags().StringVar(&month, "month", "", "UTC calendar month YYYY-MM (default: current month; full window must fit provider retention)")
	return cmd
}

func usageReportText(r vps.UsageReport) string {
	var out strings.Builder
	fmt.Fprintf(&out, "%s · %s · %s UTC\n", core.Sanitize(r.HostID), core.Sanitize(r.Provider), r.PeriodStart.Format("2006-01"))
	bytes := func(value *float64) string {
		if value == nil {
			return "unknown"
		}
		n := *value
		unit := "B"
		for _, next := range []string{"KB", "MB", "GB", "TB"} {
			if n < 1000 {
				break
			}
			n /= 1000
			unit = next
		}
		return fmt.Sprintf("%.2f %s", n, unit)
	}
	fmt.Fprintf(&out, "VM observed: inbound %s · outbound %s\n", bytes(r.Observed.InboundBytes), bytes(r.Observed.OutboundBytes))
	fmt.Fprintf(&out, "Hourly coverage: in %d/%d · out %d/%d · latest %s", r.Observed.InboundPoints, r.Observed.ExpectedPoints, r.Observed.OutboundPoints, r.Observed.ExpectedPoints, usageTime(r.Observed.LatestAt))
	if r.Observed.Partial {
		out.WriteString(" · PARTIAL")
	}
	out.WriteByte('\n')
	fmt.Fprintf(&out, "Source: %s\n\nProvider billing: %s · latest day %s\nScope: %s\n", core.Sanitize(r.Observed.Source), core.Sanitize(r.Billing.Status), usageTime(r.Billing.LatestAt), core.Sanitize(r.Billing.Scope))
	for _, m := range r.Billing.Meters {
		fmt.Fprintf(&out, "  %s [%s]: quantity %.8g; provider unit %q", core.Sanitize(m.Name), core.Sanitize(m.ID), m.Quantity, core.Sanitize(m.Unit))
		if m.Cost != nil {
			fmt.Fprintf(&out, "; reported cost %.4f %s", *m.Cost, core.Sanitize(m.Currency))
		}
		out.WriteByte('\n')
	}
	if r.Billing.PublishedAllowance != "" {
		fmt.Fprintf(&out, "\n%s\n", core.Sanitize(r.Billing.PublishedAllowance))
	}
	for _, warning := range append(append([]string{}, r.Warnings...), r.Billing.Warnings...) {
		fmt.Fprintf(&out, "- %s\n", core.Sanitize(warning))
	}
	return strings.TrimSpace(out.String())
}
func usageTime(at time.Time) string {
	if at.IsZero() {
		return "unknown"
	}
	return at.UTC().Format("2006-01-02 15:04 UTC")
}

// The dashboard calls this only from an explicit usage action. It retains the
// local inventory rows and does not poll cloud APIs on normal Overview refresh.
func (o *options) serverUsageWorkbench(ctx context.Context, r tui.WorkRequest, result tui.WorkResult) (tui.WorkResult, error) {
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	service, err := o.vpsService(cmd)
	if err != nil {
		return result, err
	}
	kind, id, _ := strings.Cut(r.Receipt, ":")
	var report vps.UsageReport
	switch kind {
	case "host":
		report, err = service.Usage(ctx, id)
	case "server":
		report, err = service.UsageForServer(ctx, id)
	default:
		return result, fmt.Errorf("select a proxy server or VPS to inspect cloud usage")
	}
	for i := range result.Rows {
		if result.Rows[i].ID == r.Receipt {
			if err != nil {
				result.Rows[i].Detail += "\n\nUsage unavailable: " + core.Sanitize(err.Error())
			} else {
				result.Rows[i].Detail += "\n\n" + usageReportText(report)
			}
		}
	}
	result.Summary = "Current UTC-month cloud usage. Observed VM bytes and delayed shared billing meters are separate; no remaining quota is inferred. Press u to refresh usage."
	return result, err
}
