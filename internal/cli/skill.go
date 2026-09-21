package cli

import (
	"errors"
	"io"

	"github.com/daviddwlee84/lazyclash/internal/skill"
	"github.com/spf13/cobra"
)

const skillAnnotation = "lazyclash.static-skill"

// skillInvocation identifies documentation paths before settings or discovery.
// The root flag is local: it cannot silently replace an operational subcommand.
func skillInvocation(cmd *cobra.Command) bool {
	if cmd == cmd.Root() {
		enabled, _ := cmd.Flags().GetBool("skill")
		return enabled
	}
	for current := cmd; current != nil; current = current.Parent() {
		if current.Annotations[skillAnnotation] == "true" {
			return true
		}
	}
	return false
}

func printSkill(cmd *cobra.Command, topic string) error {
	jsonOutput, _ := cmd.Root().PersistentFlags().GetBool("json")
	if jsonOutput {
		return usage("skill documents are Markdown; omit --json")
	}
	document, err := skill.Read(topic)
	if errors.Is(err, skill.ErrUnknownTopic) {
		return usage("unknown skill topic %q; choose controllers, runtime, automation, diagnosis, workflows, sources, environment, setup, servers or tailnet", topic)
	}
	if err != nil {
		return err
	}
	_, err = io.WriteString(cmd.OutOrStdout(), document)
	return err
}

func (o *options) skillCommand() *cobra.Command {
	group := &cobra.Command{
		Use:         "skill",
		Short:       "Read the agent guide embedded in this binary",
		Annotations: map[string]string{skillAnnotation: "true"},
		Args:        argsExact(0),
		RunE:        func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	group.AddCommand(&cobra.Command{
		Use:       "print [topic]",
		Short:     "Print an embedded operating topic, including sources, environment and setup",
		Long:      "Print embedded operational knowledge without loading settings or contacting a core. Omit topic for SKILL.md. Use each command's --help as the authority for CLI syntax. --json is not supported for Markdown documents.",
		ValidArgs: []string{"controllers", "runtime", "automation", "diagnosis", "workflows", "sources", "environment", "setup", "servers", "tailnet"},
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				return usage("%s accepts at most one topic; see --help", cmd.CommandPath())
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			topic := ""
			if len(args) == 1 {
				topic = args[0]
			}
			return printSkill(cmd, topic)
		},
	})
	return group
}
