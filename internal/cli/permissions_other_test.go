//go:build !windows

package cli

import "os"

func makePublicFixture(path string) error { return os.Chmod(path, 0644) }
