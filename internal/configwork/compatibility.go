package configwork

import (
	"fmt"
	"strings"
)

// Runtime metadata is only an early capability gate. The bound binary still
// validates the complete candidate before a preview can be applied.
func checkCompatibility(version map[string]any, defs []Definition) error {
	meta, _ := version["meta"].(bool)
	if meta {
		return nil
	}
	for _, d := range defs {
		if d.Kind != "proxy" {
			continue
		}
		switch strings.ToLower(d.Type) {
		case "vless", "hysteria", "hysteria2", "tuic", "anytls":
			return fmt.Errorf("node %q uses %s, but this core does not advertise Mihomo support (version %v); classic Clash cannot import this protocol", d.Name, d.Type, version["version"])
		}
		if get(d.Node, "reality-opts") != nil {
			return fmt.Errorf("node %q requires a REALITY-capable Mihomo core", d.Name)
		}
	}
	return nil
}

func checkRequestCompatibility(version map[string]any, req Request) error {
	if req.Kind != "proxy" || (req.Action != "add" && req.Action != "import") {
		return nil
	}
	defs, diagnostics, err := ParseImport(req.Input)
	if err != nil || len(diagnostics) > 0 {
		return nil
	} // The parser reports its bounded diagnostics during preview.
	return checkCompatibility(version, defs)
}
