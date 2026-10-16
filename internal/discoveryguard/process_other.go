//go:build !linux && !darwin && !windows

package discoveryguard

import (
	"errors"
	"io"
	"os/exec"
)

func supported() error {
	return errors.New("independent DIRECT recovery helpers are unavailable on this platform; use passive discovery")
}
func detach(*exec.Cmd)                       {}
func protectHelper()                         {}
func platformLock(string) (io.Closer, error) { return nil, supported() }
func helperIndependent() error               { return supported() }
func secureDirectory(string) error           { return supported() }
func syncDirectory(string) error             { return supported() }
