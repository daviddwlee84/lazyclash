//go:build linux || darwin

package discoveryguard

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

func supported() error { return nil }

func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func protectHelper() {
	// A dead parent closes the status pipe. Reporting must never kill rollback.
	signal.Ignore(syscall.SIGPIPE, syscall.SIGHUP)
}

func platformLock(path string) (io.Closer, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errors.New("cannot open private discovery controller lock")
	}
	f := os.NewFile(uintptr(fd), path)
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("a discovery helper or recovery already owns this controller")
	}
	return f, nil
}
func helperIndependent() error          { return nil }
func secureDirectory(path string) error { return os.Chmod(path, 0700) }
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
