//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package analytics

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lockCollector(dbPath string) (func(), error) {
	path := dbPath + ".collector.lock"
	// O_NOFOLLOW prevents a replaced lock path from redirecting our writes.
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errors.New("cannot open analytics collector lock")
	}
	f := os.NewFile(uintptr(fd), path)
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("another analytics collector or import is already running")
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = f.Close() }, nil
}
