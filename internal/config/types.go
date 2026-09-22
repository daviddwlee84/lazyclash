package config

type Config struct {
	loaded        bool
	loadedPath    string
	original      []byte
	existed       bool
	DefaultTarget string         `toml:"default_target,omitempty" json:"default_target,omitempty"`
	Targets       []Target       `toml:"targets" json:"targets"`
	TUI           TUIPreferences `toml:"tui,omitempty" json:"tui,omitempty"`
}

type Target struct {
	TransportOverride bool           `toml:"-" json:"-"` // temporary endpoint/SSH rebinding; never a persistent rule owner
	ID                string         `toml:"id" json:"id"`
	Name              string         `toml:"name,omitempty" json:"name,omitempty"`
	Controller        string         `toml:"controller" json:"controller"`
	SecretFile        string         `toml:"secret_file,omitempty" json:"secret_file,omitempty"`
	SecretEnv         string         `toml:"secret_env,omitempty" json:"secret_env,omitempty"`
	CAFile            string         `toml:"ca_file,omitempty" json:"ca_file,omitempty"`
	SSHHost           string         `toml:"ssh_host,omitempty" json:"ssh_host,omitempty"`
	SourceConfig      string         `toml:"source_config,omitempty" json:"source_config,omitempty"`
	ProbeProxy        string         `toml:"probe_proxy,omitempty" json:"probe_proxy,omitempty"`
	ProbeUsername     string         `toml:"probe_username,omitempty" json:"probe_username,omitempty"`
	ProbePasswordEnv  string         `toml:"probe_password_env,omitempty" json:"probe_password_env,omitempty"`
	ProbePasswordFile string         `toml:"probe_password_file,omitempty" json:"probe_password_file,omitempty"`
	ProbeCAFile       string         `toml:"probe_ca_file,omitempty" json:"probe_ca_file,omitempty"`
	Configs           []CoreConfig   `toml:"configs,omitempty" json:"configs,omitempty"`
	RuleSource        *RuleSource    `toml:"rule_source,omitempty" json:"rule_source,omitempty"`
	ConfigSource      *ConfigSource  `toml:"config_source,omitempty" json:"config_source,omitempty"`
	Service           *ClientService `toml:"service,omitempty" json:"service,omitempty"`
	ManagedCoreID     string         `toml:"managed_core_id,omitempty" json:"managed_core_id,omitempty"`
	Secret            string         `toml:"-" json:"-"`
	Transient         bool           `toml:"-" json:"-"`
	AuthRequired      bool           `toml:"-" json:"auth_required,omitempty"`
}

// ConfigSource explicitly grants node/group writes. It is independent of the
// credential-discovery SourceConfig and the narrower existing RuleSource.
type ConfigSource struct {
	Kind                 string `toml:"kind" json:"kind"`
	ConfigID             string `toml:"config_id,omitempty" json:"config_id,omitempty"`
	HostPath             string `toml:"host_path,omitempty" json:"host_path,omitempty"`
	CorePath             string `toml:"core_path,omitempty" json:"core_path,omitempty"`
	Binary               string `toml:"binary,omitempty" json:"binary,omitempty"`
	Home                 string `toml:"home,omitempty" json:"home,omitempty"`
	Container            string `toml:"container,omitempty" json:"container,omitempty"`
	DockerHost           string `toml:"docker_host,omitempty" json:"docker_host,omitempty"`
	ValidationDockerHost string `toml:"validation_docker_host,omitempty" json:"validation_docker_host,omitempty"`
	ValidationImage      string `toml:"validation_image,omitempty" json:"validation_image,omitempty"`
	Version              string `toml:"version,omitempty" json:"version,omitempty"`
	DataDir              string `toml:"data_dir,omitempty" json:"data_dir,omitempty"`
	ProfileUID           string `toml:"profile_uid,omitempty" json:"profile_uid,omitempty"`
}

// RuleSource explicitly identifies the persistent owner. SourceConfig remains
// a credential reference and never implicitly grants permission to edit YAML.
type RuleSource struct {
	Kind       string `toml:"kind" json:"kind"`
	Version    string `toml:"version,omitempty" json:"version,omitempty"`
	ConfigID   string `toml:"config_id,omitempty" json:"config_id,omitempty"`
	Binary     string `toml:"binary,omitempty" json:"binary,omitempty"`
	Home       string `toml:"home,omitempty" json:"home,omitempty"`
	DataDir    string `toml:"data_dir,omitempty" json:"data_dir,omitempty"`
	ProfileUID string `toml:"profile_uid,omitempty" json:"profile_uid,omitempty"`
}

// TUIPreferences keeps absent values distinct from explicit choices. Reading
// defaults never changes the saved configuration.
type TUIPreferences struct {
	StartPage     string `toml:"start_page,omitempty" json:"start_page,omitempty"`
	Mouse         *bool  `toml:"mouse,omitempty" json:"mouse,omitempty"`
	GraphStyle    string `toml:"graph_style,omitempty" json:"graph_style,omitempty"`
	HistoryWindow string `toml:"history_window,omitempty" json:"history_window,omitempty"`
}

func (p TUIPreferences) WithDefaults() TUIPreferences {
	if p.StartPage == "" {
		p.StartPage = "overview"
	}
	if p.Mouse == nil {
		enabled := true
		p.Mouse = &enabled
	} else {
		enabled := *p.Mouse
		p.Mouse = &enabled
	}
	if p.GraphStyle == "" {
		p.GraphStyle = "braille"
	}
	if p.HistoryWindow == "" {
		p.HistoryWindow = "5m"
	}
	return p
}

type CoreConfig struct {
	ID   string `toml:"id" json:"id"`
	Name string `toml:"name,omitempty" json:"name,omitempty"`
	Path string `toml:"path" json:"path"`
}

func (t Target) Label() string {
	if t.Name != "" {
		return t.Name
	}
	return t.ID
}

// ClientService binds an existing service without adopting its files or installation.
// Observed identities prevent a reused name from authorizing a different service.
type ClientService struct {
	Kind           string `toml:"kind" json:"kind"`
	DockerHost     string `toml:"docker_host,omitempty" json:"docker_host,omitempty"`
	Container      string `toml:"container,omitempty" json:"container,omitempty"`
	Image          string `toml:"image,omitempty" json:"image,omitempty"`
	MountsSHA256   string `toml:"mounts_sha256,omitempty" json:"mounts_sha256,omitempty"`
	ComposeFile    string `toml:"compose_file,omitempty" json:"compose_file,omitempty"`
	ComposeProject string `toml:"compose_project,omitempty" json:"compose_project,omitempty"`
	ComposeService string `toml:"compose_service,omitempty" json:"compose_service,omitempty"`
	Unit           string `toml:"unit,omitempty" json:"unit,omitempty"`
	Scope          string `toml:"scope,omitempty" json:"scope,omitempty"`
	FragmentPath   string `toml:"fragment_path,omitempty" json:"fragment_path,omitempty"`
	UnitSHA256     string `toml:"unit_sha256,omitempty" json:"unit_sha256,omitempty"`
}
