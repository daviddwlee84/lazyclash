//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

package analytics

import "errors"

func lockCollector(string) (func(), error) {
	return nil, errors.New("analytics collection is supported on Linux and macOS")
}
