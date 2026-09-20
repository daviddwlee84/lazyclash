package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/pelletier/go-toml/v2"
)

var ErrConflict = errors.New("configuration changed since it was loaded; reload before saving")
var saveMu sync.Mutex
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var envPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// DefaultPath follows XDG on macOS and Linux, ignoring relative XDG paths.
func DefaultPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil || !filepath.IsAbs(home) {
			return "", errors.New("cannot determine home directory for lazyclash configuration")
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "lazyclash", "config.toml"), nil
}

// Load never creates directories. Explicitly selected missing files are errors.
func Load(path string, explicit bool) (Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Config{}, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !explicit {
			return Config{loaded: true, loadedPath: abs}, nil
		}
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}
	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return Config{}, errors.New("invalid TOML configuration; check syntax and field types")
	}
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	cfg.loaded, cfg.loadedPath, cfg.original, cfg.existed = true, abs, data, true
	return cfg, nil
}

func Validate(cfg Config) error {
	if err := ValidateTUI(cfg.TUI); err != nil {
		return err
	}
	ids := map[string]bool{}
	for _, t := range cfg.Targets {
		if !idPattern.MatchString(t.ID) {
			return errors.New("target ID must begin with a letter or number and contain only letters, numbers, '.', '_' or '-'")
		}
		if ids[t.ID] {
			return fmt.Errorf("duplicate target ID %q", t.ID)
		}
		ids[t.ID] = true
		if err := ValidateTarget(t); err != nil {
			return fmt.Errorf("target %q: %w", t.ID, err)
		}
	}
	if cfg.DefaultTarget != "" && !ids[cfg.DefaultTarget] {
		return errors.New("default_target does not refer to a registered target")
	}
	return nil
}

// ValidateTarget also validates temporary targets, which need not have an ID.
func ValidateTarget(t Target) error {
	for _, value := range []string{t.SourceConfig, t.SecretFile, t.CAFile, t.SSHHost, t.ProbePasswordFile, t.ProbeCAFile, t.ProbeUsername} {
		if strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return errors.New("target paths and SSH host must not contain control characters")
		}
	}
	if err := ValidateController(t.Controller); err != nil {
		return err
	}
	if err := ValidateProbe(t); err != nil {
		return err
	}
	if t.SecretFile != "" && t.SecretEnv != "" {
		return errors.New("secret_file and secret_env are mutually exclusive")
	}
	if t.SecretEnv != "" && !envPattern.MatchString(t.SecretEnv) {
		return errors.New("invalid secret environment variable name")
	}
	if t.SourceConfig != "" && !filepath.IsAbs(t.SourceConfig) {
		return errors.New("source_config must be an absolute path on the core host")
	}
	if t.SecretFile != "" && !filepath.IsAbs(t.SecretFile) {
		return errors.New("secret_file must be an absolute local path")
	}
	if t.CAFile != "" && !filepath.IsAbs(t.CAFile) {
		return errors.New("ca_file must be an absolute local path")
	}
	if t.SSHHost != "" && (strings.HasPrefix(t.SSHHost, "-") || strings.ContainsAny(t.SSHHost, " \t\r\n\x00") || strings.ContainsAny(t.SSHHost, "'\"`$;|&<>\\")) {
		return errors.New("invalid SSH host alias")
	}
	ids := map[string]bool{}
	for _, c := range t.Configs {
		if !idPattern.MatchString(c.ID) {
			return errors.New("config ID must begin with a letter or number and contain only letters, numbers, '.', '_' or '-'")
		}
		if ids[c.ID] {
			return fmt.Errorf("duplicate config ID %q", c.ID)
		}
		ids[c.ID] = true
		if !filepath.IsAbs(c.Path) || strings.ContainsAny(c.Path, "\r\n\x00") {
			return errors.New("registered YAML paths must be absolute paths on the core host")
		}
	}
	if err := ValidateRuleSource(t); err != nil {
		return err
	}
	if err := ValidateConfigSource(t); err != nil {
		return err
	}
	if t.ManagedCoreID != "" && !idPattern.MatchString(t.ManagedCoreID) {
		return errors.New("invalid managed core ID")
	}
	return nil
}

func ValidateConfigSource(t Target) error {
	s := t.ConfigSource
	if s == nil {
		return nil
	}
	for _, v := range []string{s.Kind, s.ConfigID, s.HostPath, s.CorePath, s.Binary, s.Home, s.Container, s.Version, s.DataDir, s.ProfileUID} {
		if len(v) > 4096 || strings.IndexFunc(v, unicode.IsControl) >= 0 {
			return errors.New("config source fields contain invalid characters")
		}
	}
	switch s.Kind {
	case "native", "mihomo":
		if s.ConfigID == "" || !filepath.IsAbs(s.Binary) || !filepath.IsAbs(s.Home) || s.Home == "/" || s.Container != "" || s.DataDir != "" || s.ProfileUID != "" || s.Version != "" || s.HostPath != "" || s.CorePath != "" {
			return errors.New("native config source requires config_id, absolute binary/home, and no Docker/Verge fields")
		}
		for _, c := range t.Configs {
			if c.ID == s.ConfigID {
				return nil
			}
		}
		return errors.New("config source config_id is not registered")
	case "docker":
		if !idPattern.MatchString(s.Container) || !filepath.IsAbs(s.HostPath) || s.HostPath == "/" || !filepath.IsAbs(s.CorePath) || s.CorePath == "/" || !filepath.IsAbs(s.Binary) || !filepath.IsAbs(s.Home) || s.Home == "/" || s.DataDir != "" || s.ProfileUID != "" || s.Version != "" {
			return errors.New("Docker source requires container, host_path, core_path, binary and home; host/container paths are distinct")
		}
		if s.ConfigID != "" {
			for _, c := range t.Configs {
				if c.ID == s.ConfigID && c.Path == s.CorePath {
					return nil
				}
			}
			return errors.New("Docker config_id must refer to core_path")
		}
		return nil
	case "verge":
		if s.Version != "2.5.2" || !filepath.IsAbs(s.DataDir) || s.DataDir == "/" || s.ProfileUID == "" || s.ConfigID != "" || s.HostPath != "" || s.CorePath != "" || s.Container != "" || s.Binary != "" || s.Home != "" {
			return errors.New("Verge config source requires declared version 2.5.2, data_dir and profile_uid only")
		}
		return nil
	default:
		return errors.New("config source kind must be native, docker or verge")
	}
}

func ValidateRuleSource(t Target) error {
	s := t.RuleSource
	if s == nil {
		return nil
	}
	for _, value := range []string{s.Kind, s.Version, s.ConfigID, s.Binary, s.Home, s.DataDir, s.ProfileUID} {
		if len(value) > 4096 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return errors.New("rule source fields must not contain control characters")
		}
	}
	switch s.Kind {
	case "mihomo":
		if s.ConfigID == "" || !filepath.IsAbs(s.Binary) || !filepath.IsAbs(s.Home) || s.Home == "/" || s.DataDir != "" || s.ProfileUID != "" || s.Version != "" {
			return errors.New("mihomo rule source requires a registered config_id, absolute binary and home, and no Verge fields")
		}
		for _, c := range t.Configs {
			if c.ID == s.ConfigID {
				return nil
			}
		}
		return errors.New("rule source config_id is not registered for this target")
	case "verge":
		if s.Version != "2.5.2" {
			return errors.New("Verge rule repair supports declared owner version 2.5.2; set --owner-version 2.5.2 only for that compatible owner")
		}
		if !filepath.IsAbs(s.DataDir) || s.DataDir == "/" || s.ProfileUID == "" || s.ConfigID != "" || s.Binary != "" || s.Home != "" {
			return errors.New("Verge rule source requires an absolute data_dir and profile_uid, and no standalone fields")
		}
		return nil
	default:
		return errors.New("rule source kind must be mihomo or verge")
	}
}

func ValidateTUI(p TUIPreferences) error {
	switch p.StartPage {
	case "", "overview", "proxies", "connections", "logs", "rules", "providers", "configs":
	default:
		return errors.New("tui.start_page must be overview, proxies, connections, logs, rules, providers or configs")
	}
	switch p.GraphStyle {
	case "", "braille", "block", "ascii":
	default:
		return errors.New("tui.graph_style must be braille, block or ascii")
	}
	switch p.HistoryWindow {
	case "", "1m", "5m", "15m":
	default:
		return errors.New("tui.history_window must be 1m, 5m or 15m")
	}
	return nil
}

// ValidateProbe deliberately never echoes a proxy URL: rejected URLs may carry
// credentials. A data-plane route is independent of the controller endpoint.
func ValidateProbe(t Target) error {
	if t.ProbeProxy != "" {
		u, err := url.Parse(t.ProbeProxy)
		if err != nil || u.User != nil || u.Hostname() == "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.IndexFunc(t.ProbeProxy, unicode.IsControl) >= 0 {
			return errors.New("probe_proxy must be an HTTP(S) or SOCKS5(H) URL with an explicit port and no credentials, path, query or fragment")
		}
		switch u.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return errors.New("probe_proxy scheme must be http, https, socks5 or socks5h")
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return errors.New("probe_proxy requires an explicit port between 1 and 65535")
		}
	}
	if t.ProbePasswordEnv != "" && t.ProbePasswordFile != "" {
		return errors.New("probe_password_env and probe_password_file are mutually exclusive")
	}
	if t.ProbePasswordEnv != "" && !envPattern.MatchString(t.ProbePasswordEnv) {
		return errors.New("invalid proxy password environment variable name")
	}
	if t.ProbePasswordFile != "" && !filepath.IsAbs(t.ProbePasswordFile) {
		return errors.New("probe_password_file must be an absolute local path")
	}
	if t.ProbeCAFile != "" && !filepath.IsAbs(t.ProbeCAFile) {
		return errors.New("probe_ca_file must be an absolute local path")
	}
	for _, value := range []string{t.ProbeUsername, t.ProbePasswordFile, t.ProbeCAFile} {
		if strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return errors.New("probe credentials and paths must not contain control characters")
		}
	}
	return nil
}

func ValidateController(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.IndexFunc(endpoint, unicode.IsControl) >= 0 {
		return errors.New("controller must be an HTTP(S) URL without credentials, query or fragment, or unix:///absolute/socket")
	}
	if strings.IndexFunc(u.Path, unicode.IsControl) >= 0 {
		return errors.New("controller path must not contain control characters")
	}
	switch u.Scheme {
	case "http", "https":
		if u.Hostname() == "" {
			return errors.New("controller URL is missing a hostname")
		}
		if p := u.Port(); p != "" {
			var n int
			if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n < 1 || n > 65535 {
				return errors.New("controller URL has an invalid port")
			}
		}
	case "unix":
		if u.Host != "" || !filepath.IsAbs(u.Path) || u.Path == "/" {
			return errors.New("Unix controller must use unix:///absolute/socket")
		}
	default:
		return errors.New("controller scheme must be http, https or unix")
	}
	return nil
}

// Save uses a compare-before-replace check and a same-directory atomic rename.
// It preserves comments and unknown TOML fields in supported array-table files.
// Callers should reload after saving before performing another edit.
func Save(path string, cfg Config) error {
	if err := Validate(cfg); err != nil {
		return err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	saveMu.Lock()
	defer saveMu.Unlock()
	current, err := os.ReadFile(abs)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read configuration before save: %w", err)
	}
	if cfg.loaded {
		if cfg.loadedPath != abs || cfg.existed != exists || !bytes.Equal(cfg.original, current) {
			return ErrConflict
		}
	} else if exists {
		return errors.New("load the existing configuration before editing it")
	}
	data, err := preserve(current, cfg)
	if err != nil {
		return err
	}
	var check Config
	if err := toml.Unmarshal(data, &check); err != nil {
		return errors.New("cannot preserve this TOML layout safely; edit the configuration manually")
	}
	if err := Validate(check); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(abs+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("configuration is being edited (lock %s); retry after the writer exits: %w", abs+".lock", err)
	}
	lock.Close()
	defer os.Remove(abs + ".lock")
	// Re-check after acquiring our interprocess lock.
	latest, readErr := os.ReadFile(abs)
	if (readErr == nil) != exists || (readErr != nil && !errors.Is(readErr, os.ErrNotExist)) || !bytes.Equal(current, latest) {
		return ErrConflict
	}
	tmp, err := os.CreateTemp(filepath.Dir(abs), ".lazyclash-*.toml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	// An editor not observing our lock may have written while we prepared bytes.
	latest, readErr = os.ReadFile(abs)
	if (readErr == nil) != exists || (readErr != nil && !errors.Is(readErr, os.ErrNotExist)) || !bytes.Equal(current, latest) {
		return ErrConflict
	}
	if err := os.Rename(tmp.Name(), abs); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(abs)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
