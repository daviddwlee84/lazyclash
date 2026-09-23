//go:build !windows

// Package privatefs checks private local state using the host's access model.
package privatefs

import "os"

func Private(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && (info.Mode().IsRegular() || info.IsDir()) && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0077 == 0
}
