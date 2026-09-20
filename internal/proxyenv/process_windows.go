//go:build windows

package proxyenv

import (
	"errors"
	"os"
	"os/exec"
)

func configureChild(cmd *exec.Cmd)         {}
func signalExitCode(e *exec.ExitError) int { return 1 }
func processIdentity(int) (string, error) {
	return "", errors.New("persistent shell proxy sessions require macOS or Linux")
}
func privateInfo(os.FileInfo) bool          { return false }
func socketIdentity(string) (string, error) { return "", errors.New("SSH session sockets unavailable") }
func lockFile(string) (*os.File, error) {
	return nil, errors.New("shell sessions require macOS or Linux")
}
func unlockFile(*os.File) {}
