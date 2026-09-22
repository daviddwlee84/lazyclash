// Package serverdeploy manages owned proxy services independently of Mihomo clients.
package serverdeploy

import (
	"context"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

type Recipe struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	RequiresDomain bool   `json:"requires_domain"`
	UDP            bool   `json:"udp"`
	Source         string `json:"source"`
	Evidence       string `json:"evidence"`
}

func Recipes() []Recipe {
	return []Recipe{
		{"vless-reality", "VLESS + REALITY + Vision", "Direct TCP with Xray; no certificate or owned domain required", false, false, "https://xtls.github.io/en/config/transport.html", "Upstream-supported recommendation; each deployment requires authenticated network verification"},
		{"hysteria2", "Hysteria 2", "QUIC over UDP with trusted TLS; UDP reachability required", true, true, "https://v2.hysteria.network/docs/advanced/Full-Server-Config/", "Upstream-supported alternative; each deployment requires authenticated UDP network verification"},
		{"legacy-vmess-ws-tls", "VMess AEAD + WebSocket + TLS", "Historical Azure recipe with nginx TLS termination", true, false, "https://github.com/daviddwlee84/DockerCompose-V2Ray/tree/9e6f3b957edbbaf2bbcfd9deea8d871873069e56", "User-reported historical Azure combination; lazyclash verification is recorded separately per deployment"},
	}
}

type Request struct {
	ID            string `json:"id"`
	HostID        string `json:"host_id"`
	Recipe        string `json:"recipe"`
	Backend       string `json:"backend"`
	PublicHost    string `json:"public_host"`
	PublicPort    int    `json:"public_port"`
	ListenPort    int    `json:"listen_port"`
	Domain        string `json:"domain,omitempty"`
	RealityTarget string `json:"reality_target,omitempty"`
	ServerName    string `json:"server_name,omitempty"`
	Version       string `json:"version,omitempty"`
	Email         string `json:"email,omitempty"`
}

type Options struct {
	Store           serverstate.Store
	ReadOnly        bool
	VerifyInterface string
	Execute         func(context.Context, string, RemoteRequest) (RemoteResponse, error)
	Resolve         func(context.Context, Request, string) (Artifact, error)
	Probe           func(context.Context, []byte) (string, error)
}

type Plan struct {
	ID         string   `json:"id"`
	HostID     string   `json:"host_id"`
	Action     string   `json:"action"`
	Recipe     string   `json:"recipe"`
	Backend    string   `json:"backend"`
	PublicHost string   `json:"public_host"`
	Domain     string   `json:"domain,omitempty"`
	PublicPort int      `json:"public_port"`
	ListenPort int      `json:"listen_port"`
	Digest     string   `json:"digest"`
	Summary    string   `json:"summary"`
	Steps      []string `json:"steps"`
	Warnings   []string `json:"warnings,omitempty"`
	Request    Request  `json:"request"`
	Artifact   Artifact `json:"artifact"`
}

type Result struct {
	ID       string   `json:"id"`
	HostID   string   `json:"host_id"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Warnings []string `json:"warnings,omitempty"`
}

type Status struct {
	// Service is a live observation only. Journal phase/verification remain dated
	// historical evidence when SSH or the remote helper cannot be inspected.
	ServiceObserved       bool      `json:"service_observed"`
	CheckedAt             time.Time `json:"checked_at"`
	LastKnownStatus       string    `json:"last_known_status,omitempty"`
	LastKnownAt           time.Time `json:"last_known_at,omitempty"`
	FailureKind           string    `json:"failure_kind,omitempty"`
	ID                    string    `json:"id"`
	HostID                string    `json:"host_id"`
	Service               string    `json:"service"`
	SSH                   string    `json:"ssh"`
	PublicHost            string    `json:"public_host"`
	PublicPort            int       `json:"public_port"`
	Message               string    `json:"message,omitempty"`
	ObservedExitIP        string    `json:"observed_exit_ip,omitempty"`
	ClientUpdateRequired  bool      `json:"client_update_required"`
	VerifiedAt            time.Time `json:"verified_at,omitempty"`
	VerificationInterface string    `json:"verification_interface,omitempty"`
}

type Artifact struct {
	Version    string `json:"version"`
	Arch       string `json:"arch"`
	URL        string `json:"url,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Image      string `json:"image,omitempty"`
	NginxImage string `json:"nginx_image,omitempty"`
	Source     string `json:"source"`
}

// RemoteRequest is the closed protocol of the embedded helper. Files are only
// relative paths below the deployment's owned root; no command comes from users.
type RemoteRequest struct {
	Op           string            `json:"op"`
	ID           string            `json:"id"`
	Token        string            `json:"token,omitempty"`
	Request      Request           `json:"request"`
	Artifact     Artifact          `json:"artifact"`
	Files        map[string]string `json:"files,omitempty"`
	AllowInstall bool              `json:"allow_install,omitempty"`
}
type RemoteResponse struct {
	OK               bool              `json:"ok"`
	Error            string            `json:"error,omitempty"`
	Arch             string            `json:"arch,omitempty"`
	OS               string            `json:"os,omitempty"`
	Service          string            `json:"service,omitempty"`
	Owned            bool              `json:"owned,omitempty"`
	Warnings         []string          `json:"warnings,omitempty"`
	CertificateFiles map[string]string `json:"certificate_files,omitempty"`
}

type credentials struct {
	UUID       string `json:"uuid"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ShortID    string `json:"short_id"`
	WSPath     string `json:"ws_path"`
}
type journal struct {
	Plan                  Plan              `json:"plan"`
	Host                  serverstate.Host  `json:"host"`
	Token                 string            `json:"token"`
	Credentials           credentials       `json:"credentials"`
	Files                 map[string]string `json:"files"`
	Integrity             string            `json:"integrity"`
	Approved              bool              `json:"approved"`
	Phase                 string            `json:"phase"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
	ObservedExitIP        string            `json:"observed_exit_ip,omitempty"`
	VerifiedAt            time.Time         `json:"verified_at,omitempty"`
	VerificationInterface string            `json:"verification_interface,omitempty"`
}
