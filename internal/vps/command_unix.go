//go:build unix

package vps

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Cloud CLIs may be shell wrappers (Homebrew az starts a Python child).
// Cancel the invocation's own process group, not just the wrapper: descendants
// otherwise retain stdout and make exec.Wait outlive the operation deadline.
// This follows the process-group pattern used by brewupgrade/selfupdate.
func configureCLICommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 2 * time.Second
}
