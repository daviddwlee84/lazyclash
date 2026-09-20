package config

type Config struct {
	loaded        bool
	loadedPath    string
	original      []byte
	existed       bool
	DefaultTarget string   `toml:"default_target,omitempty" json:"default_target,omitempty"`
	Targets       []Target `toml:"targets" json:"targets"`
}

type Target struct {
	ID           string       `toml:"id" json:"id"`
	Name         string       `toml:"name,omitempty" json:"name,omitempty"`
	Controller   string       `toml:"controller" json:"controller"`
	SecretFile   string       `toml:"secret_file,omitempty" json:"secret_file,omitempty"`
	SecretEnv    string       `toml:"secret_env,omitempty" json:"secret_env,omitempty"`
	CAFile       string       `toml:"ca_file,omitempty" json:"ca_file,omitempty"`
	SSHHost      string       `toml:"ssh_host,omitempty" json:"ssh_host,omitempty"`
	SourceConfig string       `toml:"source_config,omitempty" json:"source_config,omitempty"`
	Configs      []CoreConfig `toml:"configs,omitempty" json:"configs,omitempty"`
	Secret       string       `toml:"-" json:"-"`
	Transient    bool         `toml:"-" json:"-"`
	AuthRequired bool         `toml:"-" json:"auth_required,omitempty"`
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
