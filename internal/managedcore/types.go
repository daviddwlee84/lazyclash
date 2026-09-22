// Package managedcore owns explicitly installed Mihomo clients. An ordinary
// registered endpoint never grants installation or service ownership.
package managedcore

import (
	"context"
	"io"
	"net/http"
	"os/exec"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/networkcheck"
)

const ProtocolVersion = 1
const DefaultVersion = "v1.19.31"

type NetworkOptions struct {
	TUN             bool                `json:"tun"`
	SystemProxy     bool                `json:"system_proxy"`
	Services        []string            `json:"services,omitempty"`
	ExcludedRoutes  []string            `json:"excluded_routes,omitempty"`
	DNSPolicies     map[string][]string `json:"dns_policies,omitempty"`
	FakeIPFilter    []string            `json:"fake_ip_filter,omitempty"`
	ProxyExceptions []string            `json:"proxy_exceptions,omitempty"`
	RoutingOwner    string              `json:"routing_owner,omitempty"`
}

type Request struct {
	HostOS            string                   `json:"host_os,omitempty"`
	Client            string                   `json:"client,omitempty"`
	ClientVersion     string                   `json:"client_version,omitempty"`
	CloneSourceID     string                   `json:"clone_source_id,omitempty"`
	CloneSourceSHA256 string                   `json:"clone_source_sha256,omitempty"`
	CloneSelections   map[string]string        `json:"clone_selections,omitempty"`
	CloneChecks       []config.DiagnosticCheck `json:"clone_checks,omitempty"`

	ID             string            `json:"id"`
	Name           string            `json:"name,omitempty"`
	SSHHost        string            `json:"ssh_host,omitempty"`
	Backend        string            `json:"backend"`
	Version        string            `json:"version"`
	InputKind      string            `json:"input_kind"`
	Input          []byte            `json:"-"`
	InputBaseDir   string            `json:"-"`
	Preset         string            `json:"preset"`
	Categories     []string          `json:"categories,omitempty"`
	PolicyRoles    map[string]string `json:"policy_roles,omitempty"`
	ControllerPort int               `json:"controller_port"`
	MixedPort      int               `json:"mixed_port"`
	// ProxyListen is an explicit Tailnet address for a private gateway. Empty
	// retains the ordinary loopback-only managed client behavior.
	ProxyListen         string         `json:"proxy_listen,omitempty"`
	ProxyUDP            bool           `json:"proxy_udp,omitempty"`
	ProxyGateway        bool           `json:"proxy_gateway,omitempty"`
	ServiceScope        string         `json:"service_scope"`
	Boot                bool           `json:"boot"`
	DockerContext       string         `json:"docker_context,omitempty"`
	Network             NetworkOptions `json:"network"`
	DockerArchive       string         `json:"docker_archive,omitempty"`
	DockerArchiveSHA256 string         `json:"docker_archive_sha256,omitempty"`
	BootstrapTarget     string         `json:"bootstrap_target,omitempty"`
	ArtifactFile        string         `json:"-"`
	ArtifactSHA256      string         `json:"artifact_sha256,omitempty"`
}

type HostFacts struct {
	WindowsRASEntries  int                `json:"windows_ras_entries,omitempty"`
	UserSID            string             `json:"user_sid,omitempty"`
	InteractiveSession int                `json:"interactive_session,omitempty"`
	TaskScheduler      bool               `json:"task_scheduler,omitempty"`
	VergeExisting      bool               `json:"verge_existing,omitempty"`
	VergeDataDir       string             `json:"verge_data_dir,omitempty"`
	LocalAppData       string             `json:"local_app_data,omitempty"`
	ProgramFiles       string             `json:"program_files,omitempty"`
	WindowsStateDigest string             `json:"windows_state_digest,omitempty"`
	WindowsProxy       *WindowsProxyState `json:"windows_proxy,omitempty"`
	WindowsCFW         []WindowsProcess   `json:"windows_cfw,omitempty"`

	OS             string `json:"os"`
	Arch           string `json:"arch"`
	Home           string `json:"home"`
	UID            int    `json:"uid"`
	Systemd        bool   `json:"systemd"`
	Launchd        bool   `json:"launchd"`
	Docker         bool   `json:"docker"`
	DockerRootless bool   `json:"docker_rootless"`
	DockerOS       string `json:"docker_os,omitempty"`
	DockerArch     string `json:"docker_arch,omitempty"`
	DockerEndpoint string `json:"docker_endpoint,omitempty"`
	BusyPorts      []int  `json:"busy_ports"`
	Existing       bool   `json:"existing"`
	ExistingDigest string `json:"existing_digest,omitempty"`
	ArchiveSHA256  string `json:"archive_sha256,omitempty"`
	ArchiveSize    int64  `json:"archive_size,omitempty"`
	IsRoot         bool   `json:"is_root"`
	Sandbox        bool   `json:"sandbox"`
}

type Artifact struct {
	ConfigSHA256 string `json:"config_sha256,omitempty"`
	Kind         string `json:"kind"`
	Version      string `json:"version"`
	Name         string `json:"name"`
	URL          string `json:"url,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	Size         int64  `json:"size,omitempty"`
	Image        string `json:"image,omitempty"`
	Platform     string `json:"platform"`
}

type Plan struct {
	ID                string            `json:"id"`
	Digest            string            `json:"digest"`
	Request           Request           `json:"request"`
	Host              HostFacts         `json:"host"`
	Artifact          Artifact          `json:"artifact"`
	Root              string            `json:"root"`
	Service           string            `json:"service"`
	Controller        string            `json:"controller"`
	ProbeProxy        string            `json:"probe_proxy"`
	InputSHA256       string            `json:"input_sha256"`
	ProfileSHA256     string            `json:"profile_sha256"`
	RulesVersion      string            `json:"rules_version,omitempty"`
	ResourceInventory []string          `json:"resource_inventory"`
	ResourceOrigins   map[string]string `json:"resource_origins,omitempty"`
	ResourceSHA256    map[string]string `json:"resource_sha256"`
	NeedsPrivilege    bool              `json:"needs_privilege"`
	Changes           []string          `json:"changes"`
	Warnings          []string          `json:"warnings"`
	Blockers          []string          `json:"blockers"`
	windowsProxy      *WindowsProxyState
	current           *Instance
	profile           []byte
	resources         map[string][]byte
	systemProxy       *networkcheck.SystemProxyPlan
	SystemProxy       *networkcheck.SystemProxyPlan `json:"system_proxy,omitempty"`
}

type Instance struct {
	WindowsGUIActivated bool   `json:"windows_gui_activated,omitempty"`
	WindowsRegistered   bool   `json:"windows_registered,omitempty"`
	WindowsInitialized  bool   `json:"windows_initialized,omitempty"`
	Client              string `json:"client,omitempty"`
	ClientVersion       string `json:"client_version,omitempty"`
	UserSID             string `json:"user_sid,omitempty"`
	AppRoot             string `json:"app_root,omitempty"`
	ProfileUID          string `json:"profile_uid,omitempty"`

	ID                string         `json:"id"`
	Name              string         `json:"name"`
	SSHHost           string         `json:"ssh_host,omitempty"`
	Backend           string         `json:"backend"`
	Version           string         `json:"version"`
	Artifact          Artifact       `json:"artifact"`
	Root              string         `json:"root"`
	Service           string         `json:"service"`
	ServiceScope      string         `json:"service_scope"`
	DockerContext     string         `json:"docker_context,omitempty"`
	DockerEndpoint    string         `json:"docker_endpoint,omitempty"`
	OS                string         `json:"os"`
	ResourceInventory []string       `json:"resource_inventory,omitempty"`
	OwnerToken        string         `json:"-"`
	CoreGuardRef      string         `json:"-"`
	ProxyGuardRef     string         `json:"-"`
	Digest            string         `json:"digest"`
	ProfileSHA256     string         `json:"profile_sha256"`
	RulesVersion      string         `json:"rules_version,omitempty"`
	ActivePreset      string         `json:"active_preset,omitempty"`
	Network           NetworkOptions `json:"network"`
	Boot              bool           `json:"boot"`
	Removed           bool           `json:"removed"`
	Target            config.Target  `json:"target"`
	CreatedAt         time.Time      `json:"created_at"`
}

type Receipt struct {
	ID               string        `json:"id"`
	InstanceID       string        `json:"instance_id"`
	Operation        string        `json:"operation"`
	Status           string        `json:"status"`
	Digest           string        `json:"digest"`
	CreatedAt        time.Time     `json:"created_at"`
	Message          string        `json:"message,omitempty"`
	Warnings         []string      `json:"warnings,omitempty"`
	Target           config.Target `json:"target"`
	NeedsACK         bool          `json:"needs_ack"`
	RollbackDeadline time.Time     `json:"rollback_deadline,omitempty"`
	DataPreserved    bool          `json:"data_preserved"`
	ProxyHealthy     bool          `json:"proxy_healthy"`
}

type Status struct {
	Instance          Instance `json:"instance"`
	Running           bool     `json:"running"`
	State             string   `json:"state"`
	ControllerHealthy bool     `json:"controller_healthy"`
	Message           string   `json:"message,omitempty"`
}

type HostExecutor func(context.Context, string, bool, []byte) ([]byte, error)
type Options struct {
	Upload          func(context.Context, string, string, string) error
	DownloadClient  func(context.Context, string) (*http.Client, io.Closer, error)
	ReadOnly        bool
	StateDir        string
	Execute         HostExecutor
	ResolveArtifact func(context.Context, Request, HostFacts) (Artifact, error)
	FetchArtifact   func(context.Context, Artifact) ([]byte, error)
	Open            func(context.Context, config.Target, bool) (*core.Client, io.Closer, error)
	Register        func(config.Target) error
	Unregister      func(string) error
	NetworkPlan     func(context.Context, string, NetworkOptions) (NetworkOptions, []string, []string, error)
	ReadSystemProxy func(context.Context, string, []string) (networkcheck.SystemProxySnapshot, error)
	FreshManagement func(context.Context, string) error
	Probe           func(context.Context, config.Target) error
	Foreground      func(*exec.Cmd) error
	Now             func() time.Time
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}
