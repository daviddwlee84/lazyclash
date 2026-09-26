package cli

import (
	"strings"
	"testing"
)

func TestUnknownSubcommandsAreUsageErrors(t *testing.T) {
	isolated(t)
	for _, args := range [][]string{{"targets", "show", "x"}, {"skill", "list"}, {"frobnicate"}} {
		_, _, err := run(t, Dependencies{}, args...)
		if ExitCode(err) != 2 || !strings.Contains(err.Error(), "unknown") || !strings.Contains(err.Error(), "choose one of") {
			t.Fatalf("%v: expected a usage error naming valid subcommands, got %v", args, err)
		}
	}
	if _, _, err := run(t, Dependencies{}, "connections", "--json"); ExitCode(err) != 2 {
		t.Fatalf("bare group with --json must not print help as data: %v", err)
	}
	if out, _, err := run(t, Dependencies{}, "targets"); err != nil || !strings.Contains(out, "Available Commands") {
		t.Fatalf("bare group should still print help: %v", err)
	}
}
