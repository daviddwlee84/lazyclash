//go:build !darwin && !linux

package selfupdate

import "errors"

func acquireLock(string) (func(), error) {
	return nil, errors.New("self-upgrade is supported on macOS and Linux")
}

func writableDirectory(string) error { return nil }
