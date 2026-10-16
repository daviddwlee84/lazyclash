//go:build windows

package discoveryguard

import (
	"errors"
	"io"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/daviddwlee84/lazyclash/internal/windowslock"
	"golang.org/x/sys/windows"
)

func supported() error { return nil }

func detach(cmd *exec.Cmd) {
	// No fallback without BREAKAWAY: sharing a kill-on-close host job would
	// silently remove the independent recovery guarantee.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_BREAKAWAY_FROM_JOB | windows.CREATE_NO_WINDOW, HideWindow: true}
}

func protectHelper() {}

func helperIndependent() error {
	var inJob int32
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")
	result, _, _ := proc.Call(uintptr(windows.CurrentProcess()), 0, uintptr(unsafe.Pointer(&inJob)))
	if result == 0 || inJob != 0 {
		return errors.New("host job policy prevents an independent recovery helper; no fallback change was made")
	}
	return nil
}

type releaseLock func()

func (release releaseLock) Close() error { release(); return nil }

func platformLock(path string) (io.Closer, error) {
	release, err := windowslock.Acquire(path, false)
	if err != nil {
		return nil, err
	}
	return releaseLock(release), nil
}

func secureDirectory(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// The replacement file is flushed before rename. Windows does not provide
// Unix directory fsync through an ordinary Go directory handle.
func syncDirectory(string) error { return nil }
