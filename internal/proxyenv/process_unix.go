//go:build !windows

package proxyenv

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func configureChild(cmd *exec.Cmd) {
	// Children retain the terminal's foreground group. CommandContext still
	// cancels the direct process; do not move interactive children off their TTY.
	cmd.WaitDelay = 2 * time.Second
}
func signalExitCode(e *exec.ExitError) int {
	if status, ok := e.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return 1
}
func processIdentity(pid int) (string, error) {
	if pid < 1 {
		return "", errors.New("invalid shell process ID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ps", "-o", "uid=,lstart=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			return "", nil
		}
		return "", errors.New("cannot verify shell process identity; no session was reaped")
	}
	parts := strings.Fields(string(out))
	if len(parts) < 6 {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			return "", nil
		}
		return "", errors.New("process identity is incomplete; no session was reaped")
	}
	uid, err := strconv.Atoi(parts[0])
	if err != nil || uid != os.Getuid() {
		return "", errors.New("shell process is not owned by this user")
	}
	return strings.Join(parts[1:], " "), nil
}
func privateInfo(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid() && info.Mode().Perm()&0077 == 0
}
func socketIdentity(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSocket == 0 || !privateInfo(info) {
		return "", errors.New("session control socket is not private")
	}
	stat := info.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino), nil
}
func lockFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !privateInfo(info) {
		f.Close()
		return nil, errors.New("session lock is not a private regular file")
	}
	if err = unix.Flock(fd, unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
func unlockFile(f *os.File) {
	if f != nil {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}
}
