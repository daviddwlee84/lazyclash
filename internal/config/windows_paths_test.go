package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsSourcePathsKeepControllerCredentialsLocal(t *testing.T) {
	target := Target{ID: "windows", HostOS: "windows", SSHHost: "windows-host", Controller: "http://127.0.0.1:9097", SecretFile: filepath.Join(t.TempDir(), "controller.secret"), SourceConfig: `C:\Users\David\配置\clash-verge.yaml`, Configs: []CoreConfig{{ID: "source", Path: `C:\Users\David\配置\profiles\profile.yaml`}}, ConfigSource: &ConfigSource{Kind: "verge", Version: "2.5.2", DataDir: `C:\Users\David\配置`, ProfileUID: "owned", Binary: `C:\Program Files\Verge\verge-mihomo.exe`, Home: `C:\Users\David\配置`}, RuleSource: &RuleSource{Kind: "verge", Version: "2.5.2", DataDir: `C:\Users\David\配置`, ProfileUID: "owned"}}
	if err := ValidateTarget(target); err != nil {
		t.Fatal(err)
	}
	bad := target
	bad.SourceConfig = `C:relative.yaml`
	if ValidateTarget(bad) == nil {
		t.Fatal("accepted drive-relative remote source")
	}
	bad = target
	bad.HostOS = "linux"
	if ValidateTarget(bad) == nil {
		t.Fatal("Windows paths accepted for a POSIX host")
	}
	if filepath.Separator != '\\' {
		bad = target
		bad.SecretFile = `C:\Users\David\controller.secret`
		if ValidateTarget(bad) == nil {
			t.Fatal("remote secret path accepted as local credential reference")
		}
	}
	path := filepath.Join(t.TempDir(), "settings.toml")
	raw := "# preserve this comment\n[[targets]]\nid='windows'\ncontroller='http://127.0.0.1:9097'\nfuture_setting='keep'\n"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets[0] = target
	if err = Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(path, true)
	if err != nil || reloaded.Targets[0].HostOS != "windows" {
		t.Fatalf("platform not preserved: %+v %v", reloaded, err)
	}
	after, _ := os.ReadFile(path)
	if !strings.Contains(string(after), "# preserve this comment") || !strings.Contains(string(after), "future_setting='keep'") {
		t.Fatal("foreign settings lost")
	}
}
