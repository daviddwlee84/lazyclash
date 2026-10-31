//go:build !unix

package vps

import (
	"os/exec"
	"time"
)

// Bound waiting for inherited pipes on platforms without Unix process groups.
func configureCLICommand(cmd *exec.Cmd) { cmd.WaitDelay = 2 * time.Second }
