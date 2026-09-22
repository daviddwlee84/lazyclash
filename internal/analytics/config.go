package analytics

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

var sourceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func DefaultConfig() Config {
	return Config{Version: 1, Timezone: DefaultTimezone, Sources: []SourceConfig{}, Retention: RetentionConfig{30, 90, 13}, MaxBytes: 1 << 30, Alerts: AlertConfig{ThresholdGiB: []int64{20, 50, 100}, Timezone: DefaultTimezone}}
}
func DefaultPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, err
	}
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if !filepath.IsAbs(configHome) {
		configHome = filepath.Join(home, ".config")
	}
	stateHome := os.Getenv("XDG_STATE_HOME")
	if !filepath.IsAbs(stateHome) {
		stateHome = filepath.Join(home, ".local", "state")
	}
	return Paths{Config: filepath.Join(configHome, "lazyclash", "analytics.toml"), Database: filepath.Join(stateHome, "lazyclash", "analytics", "analytics.db")}, nil
}
func ValidateConfig(c Config) error {
	if c.Version != 1 {
		return errors.New("unsupported analytics config version")
	}
	if _, err := time.LoadLocation(c.Timezone); err != nil {
		return errors.New("analytics timezone is invalid")
	}
	if c.Retention.DetailDays < 1 || c.Retention.MinuteDays < c.Retention.DetailDays || c.Retention.DayMonths < 1 || c.Retention.MinuteDays > 3660 || c.Retention.DayMonths > 120 {
		return errors.New("analytics retention requires positive detail days, minute days >= detail days (max 3660), and 1–120 day months")
	}
	if c.MaxBytes < 16<<20 || c.MaxBytes > 1<<40 {
		return errors.New("analytics max_bytes must be between 16 MiB and 1 TiB")
	}
	if len(c.Sources) > 128 {
		return errors.New("analytics supports at most 128 configured sources")
	}
	seen := map[string]bool{}
	bindings := map[string]bool{}
	for _, s := range c.Sources {
		if !sourceIDPattern.MatchString(s.ID) || seen[s.ID] {
			return errors.New("analytics source IDs must be unique safe names (1–64 characters)")
		}
		seen[s.ID] = true
		if s.Kind == "" || len(s.Kind) > 64 {
			return errors.New("analytics source kind is required")
		}
		if s.Scope != "" && s.Scope != "client" && s.Scope != "server" && s.Scope != "host" {
			return errors.New("analytics source scope must be client, server or host")
		}
		if s.Timezone != "" {
			if _, err := time.LoadLocation(s.Timezone); err != nil {
				return errors.New("invalid analytics source timezone")
			}
		}
		if s.PollSeconds < 0 || s.PollSeconds > 3600 {
			return errors.New("analytics poll_seconds must be 0–3600")
		}
		for _, v := range []string{s.Kind, s.Target, s.Interface, s.Path, s.Format, s.Binary, s.Address, s.ServerID, s.HostID} {
			if len(v) > 4096 || strings.ContainsAny(v, "\x00\r\n") {
				return errors.New("analytics source contains an invalid field")
			}
		}
		if s.Enabled {
			var key string
			switch s.Kind {
			case "interface", "host-interface":
				key = "interface:" + s.Interface
			case "access", "xray-access", "v2ray-access":
				key = "access:" + filepath.Clean(s.Path)
			case "mihomo":
				key = "mihomo:" + s.Target
			case "stats", "xray-stats", "v2ray-stats":
				address := s.Address
				if address == "" {
					address = "127.0.0.1:10085"
				}
				key = "stats:" + address
			case "vnstat":
				key = "vnstat:" + s.Interface
			}
			if key != "" {
				if bindings[key] {
					return errors.New("enabled analytics sources contain duplicate source bindings (including kind aliases)")
				}
				bindings[key] = true
			}
		}
	}
	if c.SettingsPath != "" && !filepath.IsAbs(c.SettingsPath) {
		return errors.New("analytics settings_path must be absolute on the collector host")
	}
	return validateAlerts(c.Alerts)
}
func validateAlerts(c AlertConfig) error {
	if c.WebhookEnv != "" && c.WebhookFile != "" {
		return errors.New("choose webhook_file or webhook_env")
	}
	if c.WebhookFile != "" && !filepath.IsAbs(c.WebhookFile) {
		return errors.New("webhook_file must be an absolute secret-file reference")
	}
	if strings.ContainsAny(c.WebhookEnv, "\x00\r\n=") {
		return errors.New("invalid webhook_env")
	}
	if c.Timezone != "" {
		if _, err := time.LoadLocation(c.Timezone); err != nil {
			return errors.New("invalid alert timezone")
		}
	}
	if len(c.ThresholdGiB) > 32 {
		return errors.New("too many alert thresholds")
	}
	for _, n := range c.ThresholdGiB {
		if n <= 0 || n > 1<<30 {
			return errors.New("alert thresholds must be positive GiB values")
		}
	}
	return nil
}
func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	info, err := os.Lstat(path)
	if err != nil {
		return c, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return c, errors.New("analytics config must be a regular file no larger than 1 MiB")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err = toml.Unmarshal(b, &c); err != nil {
		return c, errors.New("invalid analytics TOML")
	}
	return c, ValidateConfig(c)
}
func SaveConfig(path string, c Config) error {
	if err := ValidateConfig(c); err != nil {
		return err
	}
	b, err := toml.Marshal(c)
	if err != nil {
		return err
	}
	return writePrivateFile(path, b)
}
func writePrivateFile(path string, b []byte) error {
	if !filepath.IsAbs(path) {
		return errors.New("analytics path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if st, err := os.Lstat(path); err == nil && !st.Mode().IsRegular() {
		return errors.New("analytics destination is not a regular file")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".analytics-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	if err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("save analytics: %w", err)
	}
	return nil
}
