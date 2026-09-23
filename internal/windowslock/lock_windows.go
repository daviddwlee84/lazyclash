//go:build windows

// Package windowslock provides a nonblocking lock on one verified native file.
package windowslock

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
)

func Acquire(path string, createParents bool) (func(), error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("lock path must be absolute")
	}
	if createParents {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, errors.New("operation lock is unavailable")
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		windows.CloseHandle(h)
		return nil, errors.New("operation lock must be one regular file, not a reparse point or hard link")
	}
	overlap := &windows.Overlapped{}
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlap); err != nil {
		windows.CloseHandle(h)
		return nil, errors.New("another operation holds this lock; inspect its result before retrying")
	}
	return func() { _ = windows.UnlockFileEx(h, 0, 1, 0, overlap); _ = windows.CloseHandle(h) }, nil
}
