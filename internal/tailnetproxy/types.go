// Package tailnetproxy owns private HTTP/SOCKS gateways and per-port Tailscale
// Serve mappings. It never owns tailscaled or the tailnet access policy.
package tailnetproxy

import (
	"context"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/managedcore"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

type Request struct {
	ID      string `json:"id"`
	NodeID  string `json:"node_id"`
	Name    string `json:"name,omitempty"`
	Mode    string `json:"mode"`
	Backend string `json:"backend"`
	Egress  string `json:"egress"`
	// Upstream may contain credentials, so public plans never serialize it.
	Upstream       string `json:"-"`
	Port           int    `json:"port"`
	LocalPort      int    `json:"local_port"`
	ControllerPort int    `json:"controller_port"`
	UDP            bool   `json:"udp"`
	UDPSet         bool   `json:"-"`
}

const (
	DefaultPort           = 7898
	DefaultLocalPort      = 17898
	DefaultControllerPort = 19098
)

type Options struct {
	Store    serverstate.Store
	ReadOnly bool
	Core     managedcore.Options
	Execute  func(context.Context, string, RemoteRequest) (RemoteResponse, error)
	Probe    func(context.Context, []byte) (string, error)
	Now      func() time.Time
}

type Service struct{ Options Options }

type Plan struct {
	ID          string            `json:"id"`
	Action      string            `json:"action"`
	Digest      string            `json:"digest"`
	Request     Request           `json:"request"`
	PeerID      string            `json:"peer_id"`
	SSHHost     string            `json:"ssh_host"`
	ListenIP    string            `json:"listen_ip"`
	Upstream    string            `json:"upstream,omitempty"`
	Summary     string            `json:"summary"`
	Steps       []string          `json:"steps"`
	Warnings    []string          `json:"warnings,omitempty"`
	Blockers    []string          `json:"blockers,omitempty"`
	Core        *managedcore.Plan `json:"core,omitempty"`
	Mapping     string            `json:"mapping,omitempty"`
	StateDigest string            `json:"state_digest,omitempty"`
}

type Result struct {
	ID             string    `json:"id"`
	Status         string    `json:"status"`
	Message        string    `json:"message"`
	ObservedExitIP string    `json:"observed_exit_ip,omitempty"`
	VerifiedAt     time.Time `json:"verified_at,omitempty"`
}

type Status struct {
	ID             string    `json:"id"`
	NodeID         string    `json:"node_id"`
	Mode           string    `json:"mode"`
	Status         string    `json:"status"`
	Message        string    `json:"message,omitempty"`
	Endpoint       string    `json:"endpoint"`
	Running        bool      `json:"running"`
	MappingOwned   bool      `json:"mapping_owned"`
	AddressPresent bool      `json:"address_present"`
	ObservedExitIP string    `json:"observed_exit_ip,omitempty"`
	VerifiedAt     time.Time `json:"verified_at,omitempty"`
}

// RemoteRequest is a closed protocol to the fixed helper. Token is persisted
// privately and never included in a Plan, Result or client bundle.
type RemoteRequest struct {
	Op             string `json:"op"`
	ID             string `json:"id"`
	PeerID         string `json:"peer_id"`
	Token          string `json:"token,omitempty"`
	Port           int    `json:"port"`
	TargetPort     int    `json:"target_port"`
	ListenIP       string `json:"listen_ip,omitempty"`
	ControllerPort int    `json:"controller_port,omitempty"`
	Expected       string `json:"expected,omitempty"`
	Mode           string `json:"mode"`
	Backend        string `json:"backend,omitempty"`
	CoreID         string `json:"core_id,omitempty"`
	UDP            bool   `json:"udp"`
	Protocol       string `json:"protocol,omitempty"`
	UpstreamHost   string `json:"upstream_host,omitempty"`
	UpstreamPort   int    `json:"upstream_port,omitempty"`
	HostOS         string `json:"host_os,omitempty"`
	DockerEndpoint string `json:"docker_endpoint,omitempty"`
}

type RemoteResponse struct {
	OK             bool     `json:"ok"`
	Error          string   `json:"error,omitempty"`
	PeerID         string   `json:"peer_id"`
	OS             string   `json:"os"`
	IPs            []string `json:"ips"`
	Running        bool     `json:"running"`
	Mapping        string   `json:"mapping,omitempty"`
	Owned          bool     `json:"owned"`
	ListenerSafe   bool     `json:"listener_safe"`
	ListenerActive bool     `json:"listener_active"`
	Warnings       []string `json:"warnings,omitempty"`
}

type journal struct {
	Request        Request   `json:"request"`
	Upstream       string    `json:"upstream,omitempty"`
	PeerID         string    `json:"peer_id"`
	SSHHost        string    `json:"ssh_host"`
	ListenIP       string    `json:"listen_ip"`
	HostOS         string    `json:"host_os,omitempty"`
	DockerEndpoint string    `json:"docker_endpoint,omitempty"`
	CoreID         string    `json:"core_id,omitempty"`
	Token          string    `json:"token"`
	Username       string    `json:"username"`
	Password       string    `json:"password"`
	Phase          string    `json:"phase"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	ObservedExitIP string    `json:"observed_exit_ip,omitempty"`
	VerifiedAt     time.Time `json:"verified_at,omitempty"`
}
