package connection

import (
	"context"
	"strings"
	"testing"
)

func TestFreshManagementSSHNeverUsesConfiguredMasterOrForwards(t *testing.T) {
	for _, interactive := range []bool{false, true} {
		cmd, err := freshSSHCommand(context.Background(), "fixture", interactive)
		if err != nil {
			t.Fatal(err)
		}
		args := strings.Join(cmd.Args, " ")
		for _, want := range []string{"ControlMaster=no", "ControlPath=none", "ControlPersist=no", "ClearAllForwardings=yes", "ConnectTimeout=5", "-- fixture true"} {
			if !strings.Contains(args, want) {
				t.Fatalf("missing %s: %s", want, args)
			}
		}
		if interactive != strings.Contains(args, "BatchMode=no") {
			t.Fatal(args)
		}
	}
	if _, err := FreshSSHAuthenticationCommand(context.Background(), "bad;host"); err == nil {
		t.Fatal("invalid alias accepted")
	}
	if err := VerifyFreshSSH(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
}
