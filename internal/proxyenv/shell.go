package proxyenv

import (
	_ "embed"
	"errors"
	"strings"
)

//go:embed shell.sh
var shellScript string

// ShellInit is pure text generation: no config reads, network or session writes.
func ShellInit(shell, binary string, replace bool) (string, error) {
	if shell != "bash" && shell != "zsh" {
		return "", errors.New("shell-init supports bash and zsh")
	}
	if binary == "" || strings.ContainsAny(binary, "\r\n\x00") {
		return "", errors.New("invalid executable path")
	}
	text := strings.ReplaceAll(shellScript, "@BINARY@", Quote(binary))
	text = strings.ReplaceAll(text, "@SHELL@", Quote(shell))
	flag := "0"
	if replace {
		flag = "1"
	}
	text = strings.ReplaceAll(text, "@REPLACE@", flag)
	return text, nil
}
