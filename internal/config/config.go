package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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
	for _, value := range []string{t.SourceConfig, t.SecretFile, t.CAFile, t.SSHHost} {
		if strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return errors.New("target paths and SSH host must not contain control characters")
		}
	}
	if err := ValidateController(t.Controller); err != nil {
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
