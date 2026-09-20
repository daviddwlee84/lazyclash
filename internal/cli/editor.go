package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/spf13/cobra"
)

func (o *options) settingsEditCommand() *cobra.Command {
	return &cobra.Command{Use: "edit", Short: "Edit settings with $VISUAL, $EDITOR, or vi", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		if o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout()) {
			return usage("settings edit requires an interactive terminal and cannot use --json; use settings path to locate the file")
		}
		value := os.Getenv("VISUAL")
		if strings.TrimSpace(value) == "" {
			value = os.Getenv("EDITOR")
		}
		if strings.TrimSpace(value) == "" {
			value = "vi"
		}
		argv, err := editorArguments(value)
		if err != nil {
			return usage("editor: %s", err)
		}
		// Check the executable before creating any settings file.
		executable, err := exec.LookPath(argv[0])
		if err != nil {
			return fmt.Errorf("find editor: %w", err)
		}
		path, _, err := o.settingsPath(cmd)
		if err != nil {
			return err
		}
		path, err = filepath.Abs(path)
		if err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return fmt.Errorf("create settings directory: %w", err)
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			_, writeErr := file.WriteString("# lazyclash preferences; see lazyclash targets add --help\n")
			closeErr := file.Close()
			if writeErr != nil {
				return writeErr
			}
			if closeErr != nil {
				return closeErr
			}
		} else if !os.IsExist(err) {
			return fmt.Errorf("create settings: %w", err)
		}
		child := exec.CommandContext(cmd.Context(), executable, append(argv[1:], path)...)
		child.Stdin, child.Stdout, child.Stderr = cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()
		if err = o.deps.RunEditor(child); err != nil {
			if cmd.Context().Err() != nil {
				return cmd.Context().Err()
			}
			return fmt.Errorf("editor failed (your edits were retained): %w", err)
		}
		if _, err = config.Load(path, true); err != nil {
			return usage("settings are invalid (your edits were retained): %s", err)
		}
		return o.result(cmd, "Settings validated: "+path)
	}}
}

// Parse executable arguments with quote/backslash support only. No shell,
// variable expansion, command substitution, pipelines, or redirection runs.
func editorArguments(value string) ([]string, error) {
	var words []string
	var word strings.Builder
	var quote rune
	started, escaped := false, false
	for _, r := range value {
		if escaped {
			word.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' && quote != '\'' {
			escaped, started = true, true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				word.WriteRune(r)
			}
			continue
		}
		switch {
		case r == '\'' || r == '"':
			quote, started = r, true
		case unicode.IsSpace(r):
			if started {
				words = append(words, word.String())
				word.Reset()
				started = false
			}
		default:
			started = true
			word.WriteRune(r)
		}
	}
	if quote != 0 || escaped {
		return nil, fmt.Errorf("unclosed quote or trailing backslash")
	}
	if started {
		words = append(words, word.String())
	}
	if len(words) == 0 || words[0] == "" {
		return nil, fmt.Errorf("empty executable")
	}
	return words, nil
}
