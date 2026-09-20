//go:build darwin || linux

package managedcore

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

// One lock spans the host mutation and the local source/receipt commit. Leaving
// the lock inode in place is intentional; kernel ownership ends on process exit.
func mutationLock(id string, opts Options) (func(), error) {
	dir, err := instanceDir(id, opts)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return nil, err
	}
	fd, err := unix.Open(dir+".lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errors.New("managed mutation lock is unavailable")
	}
	file := os.NewFile(uintptr(fd), dir+".lock")
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("managed mutation lock is not a regular file")
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("another managed operation owns this instance; wait for its receipt before retrying")
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = file.Close() }, nil
}
