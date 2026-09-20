package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreferencesDefaultsDoNotRewriteAndPreserveTypedFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	original := "# mine\n[[targets]]\nid='local'\ncontroller='http://localhost:9090'\n\n[tui] # preferences\nmouse = false # hands off\nfuture_option = 8\n\n[extra]\nkeep = true\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.TUI.WithDefaults()
	if p.StartPage != "overview" || *p.Mouse || p.GraphStyle != "braille" || p.HistoryWindow != "5m" {
		t.Fatalf("defaults: %+v", p)
	}
	*p.Mouse = true
	if *cfg.TUI.Mouse {
		t.Fatal("effective defaults share mutable preference pointer")
	}
	data, _ := os.ReadFile(path)
	if string(data) != original {
		t.Fatal("read rewrote preferences")
	}
	cfg.TUI.GraphStyle = "ascii"
	cfg.TUI.HistoryWindow = "15m"
	cfg.Targets[0].ProbeProxy = "socks5h://127.0.0.1:7890"
	cfg.Targets[0].ProbeUsername = "probe-user"
	cfg.Targets[0].ProbePasswordEnv = "PROXY_PASSWORD"
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	for _, want := range []string{"mouse = false # hands off", "future_option = 8", "keep = true", "# preferences", "probe_password_env = 'PROXY_PASSWORD'"} {
		// TOML quote style is an encoder choice for newly inserted values.
		if !strings.Contains(string(data), want) && !strings.Contains(string(data), strings.ReplaceAll(want, "'", "\"")) {
			t.Errorf("lost %q:\n%s", want, data)
		}
	}
	loaded, err := Load(path, true)
	if err != nil || loaded.TUI.GraphStyle != "ascii" || *loaded.TUI.Mouse || loaded.Targets[0].ProbeProxy != cfg.Targets[0].ProbeProxy {
		t.Fatalf("roundtrip: %+v %v", loaded, err)
	}
}

func TestPreferencesCanBeAddedWithExistingTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[[targets]]\nid='x'\ncontroller='http://localhost'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg.TUI = cfg.TUI.WithDefaults()
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path, true)
	if err != nil || !*loaded.TUI.Mouse || loaded.TUI.StartPage != "overview" || len(loaded.Targets) != 1 {
		t.Fatalf("saved preferences: %+v %v", loaded, err)
	}
}

func TestProbeURLValidationDoesNotExposeCredentials(t *testing.T) {
	for _, endpoint := range []string{"http://user:VERY_SECRET@host:7890", "http://host", "http://host:0", "http://host:65536", "http://host:7890/", "http://host:7890?", "http://host:7890?token=VERY_SECRET", "http://host:7890#VERY_SECRET", "ftp://host:7890", "socks5://host:xyz"} {
		err := ValidateProbe(Target{ProbeProxy: endpoint})
		if err == nil {
			t.Errorf("accepted %s", endpoint)
		} else if strings.Contains(err.Error(), "VERY_SECRET") {
			t.Fatal("secret exposed")
		}
	}
	for _, endpoint := range []string{"http://127.0.0.1:7890", "https://proxy.example:8443", "socks5://[::1]:1080", "socks5h://proxy.example:1080"} {
		if err := ValidateProbe(Target{ProbeProxy: endpoint}); err != nil {
			t.Errorf("valid route %s: %v", endpoint, err)
		}
	}
	for _, target := range []Target{{ProbePasswordEnv: "PW", ProbePasswordFile: "/tmp/pw"}, {ProbePasswordFile: "relative"}, {ProbeCAFile: "relative"}, {ProbePasswordEnv: "bad-name"}, {ProbeUsername: "bad\nname"}} {
		if ValidateProbe(target) == nil {
			t.Errorf("invalid probe config accepted: %+v", target)
		}
	}
	for _, p := range []TUIPreferences{{StartPage: "missing"}, {GraphStyle: "dots"}, {HistoryWindow: "3h"}} {
		if Validate(Config{TUI: p}) == nil {
			t.Errorf("invalid preferences accepted: %+v", p)
		}
	}
}
