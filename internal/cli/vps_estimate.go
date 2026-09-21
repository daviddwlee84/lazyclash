package cli

import (
	"math"

	"github.com/daviddwlee84/lazyclash/internal/vps"
	"github.com/spf13/cobra"
)

func (o *options) vpsEstimateCommand() *cobra.Command {
	var req vps.CreateRequest
	var outbound, inbound float64
	cmd := &cobra.Command{Use: "estimate", Short: "Estimate compute, disk, IPv4 and traffic costs with explicit uncertainty", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validateManagedOverrides(cmd, false, false); err != nil {
			return err
		}
		if err := vps.ValidateDraft(req); err != nil {
			return usage("%s", err)
		}
		if req.Provider == "" || req.Plan == "" || !cmd.Flags().Changed("egress") {
			return usage("estimate requires --provider, --plan and --egress (monthly outbound in the provider's displayed GB/GiB unit)")
		}
		if outbound < 0 || math.IsNaN(outbound) || math.IsInf(outbound, 0) {
			return usage("--egress must be a finite nonnegative amount")
		}
		var ingress *float64
		if cmd.Flags().Changed("ingress") {
			if inbound < 0 || math.IsNaN(inbound) || math.IsInf(inbound, 0) {
				return usage("--ingress must be a finite nonnegative amount")
			}
			ingress = &inbound
		}
		s, err := o.vpsService(cmd)
		if err != nil {
			return err
		}
		q, err := s.Quote(cmd.Context(), req)
		if err != nil {
			return err
		}
		cost, err := vps.EstimateCostWithUsage(q, outbound, ingress)
		if err != nil {
			return usage("%s", err)
		}
		return o.output(cmd, cost)
	}}
	f := cmd.Flags()
	f.StringVar(&req.Provider, "provider", "", vpsProviderHelp)
	f.StringVar(&req.Plan, "plan", "", "provider plan ID")
	f.StringVar(&req.Region, "region", "", "provider region (recommended for regional price checks)")
	f.StringVar(&req.Profile, "profile", "", "official CLI profile (Vultr: config file path)")
	vpsCloudFlags(f, &req)
	f.Float64Var(&outbound, "egress", 0, "expected monthly outbound in the quoted provider GB/GiB unit")
	f.Float64Var(&inbound, "ingress", 0, "expected monthly inbound in the quoted unit; Lightsail's allowance counts both directions")
	return cmd
}
