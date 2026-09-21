//go:build darwin || linux

package serverstate

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

// Lock holds a nonblocking interprocess lock until the returned function runs.
func Lock(path string) (func(), error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("lock path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errors.New("server operation lock is unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("server operation lock must be a regular file")
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another server operation is in progress; inspect its result before retrying")
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = f.Close() }, nil
}
