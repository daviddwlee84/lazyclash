package cli

import (
	"github.com/daviddwlee84/lazyclash/internal/vps"
	"github.com/spf13/cobra"
	"math"
)

func (o *options) vpsEstimateCommand() *cobra.Command {
	var req vps.CreateRequest
	var outbound float64
	cmd := &cobra.Command{Use: "estimate", Short: "Estimate machine plus monthly outbound cost with provider units and explicit uncertainty", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validateManagedOverrides(cmd, false, false); err != nil {
			return err
		}
		if req.Provider == "" || req.Plan == "" || !cmd.Flags().Changed("egress") {
			return usage("estimate requires --provider, --plan and --egress (monthly outbound in the provider's displayed GB/GiB unit)")
		}
		if outbound < 0 || math.IsNaN(outbound) || math.IsInf(outbound, 0) {
			return usage("--egress must be a finite nonnegative amount")
		}
		s, err := o.vpsService(cmd)
		if err != nil {
			return err
		}
		q, err := s.Quote(cmd.Context(), req)
		if err != nil {
			return err
		}
		cost, err := vps.EstimateCost(q, outbound)
		if err != nil {
			return usage("%s", err)
		}
		return o.output(cmd, cost)
	}}
	f := cmd.Flags()
	f.StringVar(&req.Provider, "provider", "", "oracle, vultr, linode or digitalocean")
	f.StringVar(&req.Plan, "plan", "", "provider plan ID")
	f.StringVar(&req.Region, "region", "", "provider region (recommended for regional price checks)")
	f.StringVar(&req.Profile, "profile", "", "official CLI profile (Vultr: config file path)")
	f.Float64Var(&outbound, "egress", 0, "expected monthly outbound; GB for Vultr/Linode/Oracle, GiB for DigitalOcean")
	return cmd
}
