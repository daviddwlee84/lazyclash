package cli

import (
	"fmt"
	"text/tabwriter"

	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/managedrpi"
	"github.com/spf13/cobra"
)

func (o *options) inventoryCommand() *cobra.Command {
	return &cobra.Command{Use: "inventory", Short: "讀取受管 RPi 的 DHCP、鄰居與 Wi-Fi 裝置觀測", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		t, err := o.ruleTarget(cmd)
		if err != nil {
			return err
		}
		observed, err := managedrpi.Call(cmd.Context(), t, managedrpi.Request{Operation: "inventory"}, nil)
		if err != nil {
			return err
		}
		if o.json {
			return o.output(cmd, map[string]any{"schema": observed.Schema, "complete": observed.Complete, "lan": observed.LAN, "devices": observed.Devices})
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		completion := "完整"
		if !observed.Complete {
			completion = "未完成"
		}
		fmt.Fprintf(w, "LAN：%s；觀測：%s\n", inventoryValue(observed.LAN, "address"), completion)
		fmt.Fprintln(w, "IP\tMAC\t名稱\t狀態\t來源")
		for _, device := range observed.Devices {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", inventoryValue(device, "ipv4"), inventoryValue(device, "mac"), inventoryValue(device, "hostname"), inventoryValue(device, "presence"), inventoryValue(device, "sources"))
		}
		fmt.Fprintln(w, "DHCP 租約與鄰居快取是觀測資料，不等同裝置目前在線；Wi-Fi associated、REACHABLE、FAILED 分別列示。")
		return w.Flush()
	}}
}
func inventoryValue(device map[string]any, key string) string {
	value, ok := device[key]
	if !ok || value == nil {
		return "—"
	}
	return core.Sanitize(fmt.Sprint(value))
}
