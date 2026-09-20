//go:build darwin || linux

package selfupdate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func acquireLock(destination string) (func(), error) {
	path := filepath.Join(filepath.Dir(destination), "."+filepath.Base(destination)+".upgrade.lock")
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open update lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("update lock must be a regular file")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("another lazyclash upgrade is already updating this executable")
		}
		return nil, fmt.Errorf("acquire update lock: %w", err)
	}
	return func() {
		unix.Flock(fd, unix.LOCK_UN)
		file.Close()
		// Leave the inode in place: unlinking a flock file lets another process
		// lock a different inode under the same name during handoff.
	}, nil
}

func writableDirectory(path string) error { return unix.Access(path, unix.W_OK|unix.X_OK) }
