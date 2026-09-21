// Package tailnet manages existing, joined Tailscale peers. It never logs in,
// installs Tailscale, changes tailnet policy, or silently falls back to direct.
package tailnet

import (
	"context"
	"os/exec"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

type Peer struct {
	ID            string   `json:"id"`
	Hostname      string   `json:"hostname"`
	DNSName       string   `json:"dns_name,omitempty"`
	OS            string   `json:"os"`
	IPs           []string `json:"ips"`
	Online        bool     `json:"online"`
	ExitAvailable bool     `json:"exit_available"`
	Selected      bool     `json:"selected"`
	Connection    string   `json:"connection,omitempty"`
}

type Request struct {
	LocalTarget      *config.Target `json:"-"`
	Action           string         `json:"action"`
	ID               string         `json:"id,omitempty"`
	SSHHost          string         `json:"ssh_host,omitempty"`
	AllowLAN         bool           `json:"allow_lan"`
	Controller       string         `json:"controller,omitempty"`
	ControllerSecret string         `json:"-"`
	ProbeProxy       string         `json:"probe_proxy,omitempty"`
}

type Plan struct {
	Request        Request  `json:"request"`
	Digest         string   `json:"digest"`
	Peer           Peer     `json:"peer"`
	Changes        []string `json:"changes"`
	Warnings       []string `json:"warnings"`
	Blockers       []string `json:"blockers"`
	NeedsPrivilege bool     `json:"needs_privilege"`
	snapshot       snapshot
}

type Result struct {
	ID             string    `json:"id,omitempty"`
	Status         string    `json:"status"`
	Peer           Peer      `json:"peer"`
	Message        string    `json:"message,omitempty"`
	VerifiedAt     time.Time `json:"verified_at,omitempty"`
	DirectIP       string    `json:"direct_ip,omitempty"`
	ProxyIP        string    `json:"proxy_ip,omitempty"`
	Warnings       []string  `json:"warnings,omitempty"`
	Selected       bool      `json:"selected"`
	TUNPaused      bool      `json:"tun_paused"`
	NeedsPrivilege bool      `json:"needs_privilege,omitempty"`
}

type Options struct {
	ReadOnly        bool
	Execute         func(context.Context, string, bool, []byte) ([]byte, error)
	Foreground      func(*exec.Cmd) error
	FreshManagement func(context.Context, string) error
	Now             func() time.Time
	// NetworkCheck overrides passive reverse-TUN conflict checking in tests.
	NetworkCheck func(context.Context, string, bool, string) ([]string, error)
}

type Service struct {
	Store   serverstate.Store
	Options Options
}

type AuthorizationRequiredError struct{ Host string }

func (e *AuthorizationRequiredError) Error() string {
	return "administrator authorization requires a native terminal or an existing noninteractive sudo policy"
}

// ProbeFailure identifies a failed verification phase without including remote
// response text, command arguments, or credentials.
type ProbeFailure struct {
	Phase    string `json:"phase"`
	ExitCode int    `json:"exit_code"`
	Message  string `json:"message"`
}

func (e *ProbeFailure) Error() string { return e.Message }
