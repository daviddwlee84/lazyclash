package cli

import (
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/managedcore"
	"github.com/spf13/cobra"
)

func (o *options) rulePresetCommand() *cobra.Command {
	group := &cobra.Command{Use: "preset", Short: "Inspect or apply verified offline routing presets to an owned core"}
	group.AddCommand(&cobra.Command{Use: "list", Short: "Show bundled presets, immutable rules revision and licenses", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		presets, err := managedcore.Presets()
		if err != nil {
			return err
		}
		return o.output(cmd, presets)
	}})
	for _, operation := range []string{"apply", "update"} {
		var id, expect string
		var yes bool
		var categories []string
		var roles map[string]string
		use := operation
		if operation == "apply" {
			use += " NAME"
		}
		cmd := &cobra.Command{Use: use, Short: "Preview preset " + operation + "; update uses this binary's bundled immutable snapshot", Args: func(_ *cobra.Command, args []string) error {
			wanted := 0
			if operation == "apply" {
				wanted = 1
			}
			if len(args) != wanted {
				return usage("rules preset %s requires %d arguments", operation, wanted)
			}
			return nil
		}, RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateManagedOverrides(cmd, false, true); err != nil {
				return err
			}
			defer connection.CloseAuthentications()
			coreID, err := o.managedPresetTarget(cmd, id)
			if err != nil {
				return err
			}
			request, err := managedcore.LoadRequest(coreID, o.managedOptions(cmd))
			if err != nil {
				return err
			}
			if operation == "apply" {
				request.Preset = args[0]
			}
			if operation == "update" && request.Preset == "preserve" {
				instance, e := managedcore.GetInstance(coreID, o.managedOptions(cmd))
				if e != nil {
					return e
				}
				request.Preset = instance.ActivePreset
			}
			if request.Preset != "cn-split" && request.Preset != "simple" {
				return usage("select cn-split or simple before updating a routing preset")
			}
			if cmd.Flags().Changed("category") {
				request.Categories = categories
			}
			if cmd.Flags().Changed("policy") {
				request.PolicyRoles = roles
			}
			if yes && expect == "" {
				return usage("--yes requires --expect DIGEST")
			}
			return o.runManagedPreviewApply(cmd, request, coreID, yes, expect)
		}}
		cmd.Flags().StringVar(&id, "core", "", "managed core ID (or select a managed --target)")
		cmd.Flags().StringSliceVar(&categories, "category", nil, "optional rule categories")
		cmd.Flags().StringToStringVar(&roles, "policy", nil, "category=existing-policy mappings")
		cmd.Flags().BoolVar(&yes, "yes", false, "apply exactly the reviewed preset change")
		cmd.Flags().StringVar(&expect, "expect", "", "reviewed preset digest")
		group.AddCommand(cmd)
	}
	return group
}
