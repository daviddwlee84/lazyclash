//go:build !linux && !darwin

package connection

import "os/exec"

func configureHelperProcess(*exec.Cmd) {}
