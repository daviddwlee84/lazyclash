//go:build !darwin && !linux

package selfupdate

import "os/exec"

func configureCommand(*exec.Cmd) {}
