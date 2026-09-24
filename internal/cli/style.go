package cli

import (
	"io"
	"os"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// cliStyle belongs to human command output. Domain reports and JSON never
// contain styling, and every value is sanitized before trusted SGR is added.
type cliStyle struct{ enabled bool }
type cliTone uint8

const (
	tonePlain cliTone = iota
	toneAccent
	toneSuccess
	toneWarning
	toneError
	toneMuted
	toneStrong
)

func validateColorMode(mode string) error {
	switch mode {
	case "auto", "always", "never":
		return nil
	default:
		return usage("--color must be auto, always or never")
	}
}

func (o *options) registerColorFlag(root *cobra.Command) {
	root.PersistentFlags().StringVar(&o.color, "color", "auto", "human command colors: auto, always or never (auto honors NO_COLOR and TERM=dumb; JSON stays plain)")
	_ = root.RegisterFlagCompletionFunc("color", func(_ *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		var values []string
		for _, value := range []string{"auto", "always", "never"} {
			if strings.HasPrefix(value, prefix) {
				values = append(values, value)
			}
		}
		return values, cobra.ShellCompDirectiveNoFileComp
	})
}

func (o *options) commandStyle(out io.Writer) cliStyle {
	terminal := false
	if f, ok := out.(*os.File); ok {
		terminal = term.IsTerminal(int(f.Fd()))
	}
	return cliStyle{enabled: colorEnabled(o.color, o.json, terminal, os.Getenv("NO_COLOR") != "", os.Getenv("TERM"))}
}

func colorEnabled(mode string, json, terminal, noColor bool, terminalType string) bool {
	if json || mode == "never" {
		return false
	}
	if mode == "always" {
		return true
	}
	return (mode == "auto" || mode == "") && terminal && !noColor && !strings.EqualFold(terminalType, "dumb")
}

func (s cliStyle) paint(tone cliTone, value string) string {
	value = core.Sanitize(value)
	if !s.enabled || value == "" {
		return value
	}
	style := lipgloss.NewStyle().TabWidth(lipgloss.NoTabConversion)
	switch tone {
	case toneAccent:
		style = style.Bold(true).Foreground(lipgloss.Color("6"))
	case toneSuccess:
		style = style.Foreground(lipgloss.Color("2"))
	case toneWarning:
		style = style.Foreground(lipgloss.Color("3"))
	case toneError:
		style = style.Bold(true).Foreground(lipgloss.Color("1"))
	case toneMuted:
		style = style.Faint(true)
	case toneStrong:
		style = style.Bold(true)
	default:
		return value
	}
	return style.Render(value)
}

func statusTone(status string) cliTone {
	switch status {
	case "ready", "completed", "applied_verified", "restored_verified":
		return toneSuccess
	case "blocked", "error", "errors", "failed", "stopped", "source_changed", "invalid":
		return toneError
	case "skipped_existing", "no_changes", "unattempted":
		return toneMuted
	case "completed_with_skips", "skipped_unavailable", "unavailable", "partial":
		return toneWarning
	default:
		if strings.Contains(status, "unknown") || strings.Contains(status, "pending") || strings.Contains(status, "not_verified") {
			return toneWarning
		}
		return tonePlain
	}
}
