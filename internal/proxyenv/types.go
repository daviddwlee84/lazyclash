// Package proxyenv resolves data-plane proxies independently of controller
// selection and owns only the shell sessions and artifacts it creates.
package proxyenv

import (
	"context"
	"errors"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"io"
	"os/exec"
)

type Request struct {
	TargetID      string
	Endpoint      string
	SocksEndpoint string
}

type Options struct {
	Open     func(context.Context, config.Target, bool) (*core.Client, io.Closer, error)
	Discover func(context.Context, string) ([]config.Target, error)
	Getenv   func(string) string
}

// Plan contains endpoints and credential references, never resolved passwords.
type Plan struct {
	TargetID     string `json:"target_id,omitempty"`
	Source       string `json:"source"`
	HTTP         string `json:"http_proxy"`
	All          string `json:"all_proxy"`
	SSHHost      string `json:"ssh_host,omitempty"`
	Username     string `json:"-"`
	PasswordEnv  string `json:"-"`
	PasswordFile string `json:"-"`
	CAFile       string `json:"-"`
}

type AmbiguousError struct{ Targets []config.Target }

func (*AmbiguousError) Error() string {
	return "multiple local proxies are available; select --target ID"
}

var ErrRemoteEnv = errors.New("SSH proxy needs an owned session; use proxy-on or proxy exec")

type ExitError struct{ Code int }

func (e *ExitError) Error() string { return "child command exited unsuccessfully" }

type Runner func(*exec.Cmd) error

type TestResult struct {
	Endpoint     string `json:"endpoint"`
	URL          string `json:"url"`
	HTTPStatus   int    `json:"http_status"`
	Milliseconds int64  `json:"milliseconds"`
	Scope        string `json:"scope"`
}
