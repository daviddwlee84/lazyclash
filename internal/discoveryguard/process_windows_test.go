//go:build windows

package discoveryguard

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsHelperRequiresJobBreakaway(t *testing.T) {
	cmd := exec.Command("fixture.exe")
	detach(cmd)
	want := uint32(windows.CREATE_BREAKAWAY_FROM_JOB | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW)
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.CreationFlags&want != want {
		t.Fatal("helper can inherit foreground job lifetime")
	}
}

func TestWindowsPrivateRecoveryDirectoryAndExclusiveLock(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	root, err := stateRoot(true)
	if err != nil {
		t.Fatal(err)
	}
	key := digest("controller-fixture")
	first, err := takeLock(root, key)
	if err != nil {
		t.Fatal(err)
	}
	if next, err := takeLock(root, key); err == nil {
		next.Close()
		first.Close()
		t.Fatal("another process can own the controller lock")
	}
	first.Close()
	next, err := takeLock(root, key)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}
