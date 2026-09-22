package managedcore

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWindowsPrivateTransferGuards(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell unavailable for private transfer guard fixtures")
	}
	helper, err := filepath.Abs("windows_host.ps1")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File", "testdata/windows_transfer_safety.ps1", "-Helper", helper)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("private transfer guard fixture: %v\n%s", err, out)
	}
}
