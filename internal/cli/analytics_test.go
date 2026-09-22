package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/analytics"
)

func analyticsIsolation(t *testing.T) (string, string) {
	t.Helper()
	settings := isolated(t)
	root := t.TempDir()
	t.Setenv("XDG_STATE_HOME", root)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	return settings, root
}

func TestAnalyticsCalendarWindows(t *testing.T) {
	now := time.Date(2026, 9, 22, 4, 0, 0, 0, time.UTC)
	for _, tt := range []struct{ period, want string }{{"day", "2026-09-22T00:00:00+08:00"}, {"week", "2026-09-21T00:00:00+08:00"}, {"month", "2026-09-01T00:00:00+08:00"}} {
		from, to, err := analyticsWindow(now, tt.period, "", "", "Asia/Shanghai")
		if err != nil || from.Format(time.RFC3339) != tt.want || !to.Equal(now) {
			t.Fatalf("%s: %v %v %v", tt.period, from, to, err)
		}
	}
	from, to, err := analyticsWindow(now, "day", "2026-03-08", "2026-03-09", "America/New_York")
	if err != nil || to.Sub(from) != 23*time.Hour {
		t.Fatalf("DST civil day: %v %v %v", from, to, err)
	}
	for _, args := range [][4]string{{"year", "", "", "UTC"}, {"day", "2026-01-01", "", "UTC"}, {"day", "2026-01-02", "2026-01-01", "UTC"}, {"day", "bad", "also bad", "UTC"}, {"day", "", "", "nowhere"}} {
		if _, _, e := analyticsWindow(now, args[0], args[1], args[2], args[3]); e == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestAnalyticsReadsAndPreviewCreateNoState(t *testing.T) {
	_, state := analyticsIsolation(t)
	for _, args := range [][]string{{"analytics", "--help"}, {"analytics", "status", "--json"}, {"analytics", "report", "--json"}, {"analytics", "setup", "--source", "vps", "--kind", "interface", "--interface", "eth0", "--json"}} {
		out, _, err := run(t, Dependencies{}, args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if args[len(args)-1] == "--json" && !json.Valid([]byte(out)) {
			t.Fatalf("invalid JSON: %s", out)
		}
	}
	paths, _ := analytics.DefaultPaths()
	if _, err := os.Stat(paths.Config); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preview created config: %v", err)
	}
	entries, _ := os.ReadDir(state)
	if len(entries) > 0 {
		t.Fatalf("read created analytics state: %v", entries)
	}
}

func TestAnalyticsSourceOptInAndConfigUpdates(t *testing.T) {
	analyticsIsolation(t)
	args := []string{"analytics", "setup", "--source", "vps", "--kind", "interface", "--interface", "eth0", "--yes", "--json"}
	if _, _, err := run(t, Dependencies{}, args...); err != nil {
		t.Fatal(err)
	}
	p, _ := analytics.DefaultPaths()
	cfg, err := analytics.LoadConfig(p.Config)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Sources) != 1 || cfg.Sources[0].Enabled {
		t.Fatalf("source enabled without opt in: %+v", cfg)
	}
	if st, _ := os.Stat(p.Config); st.Mode().Perm() != 0600 {
		t.Fatal("configuration is not private")
	}
	if _, _, err = run(t, Dependencies{}, "analytics", "setup", "--source", "vps", "--enabled", "--yes", "--json"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = run(t, Dependencies{}, "analytics", "setup", "--detail-days", "7", "--minute-days", "30", "--day-months", "3", "--max-mib", "64", "--yes"); err != nil {
		t.Fatal(err)
	}
	cfg, err = analytics.LoadConfig(p.Config)
	if err != nil || !cfg.Sources[0].Enabled || cfg.Sources[0].Interface != "eth0" || cfg.Retention.DetailDays != 7 || cfg.MaxBytes != 64<<20 {
		t.Fatalf("updated config: %+v %v", cfg, err)
	}
	before, _ := os.ReadFile(p.Config)
	for _, args := range [][]string{{"analytics", "setup", "--enabled", "--yes"}, {"analytics", "setup", "--source", "bad", "--kind", "bogus", "--yes"}, {"analytics", "setup", "--max-mib", "2", "--yes"}, {"--read-only", "analytics", "setup", "--source", "vps", "--enabled=false", "--yes"}, {"analytics", "report", "--limit", "0"}, {"analytics", "report", "--from", "2026-09-01"}, {"analytics", "report", "--interactive", "--json"}} {
		if _, _, e := run(t, Dependencies{}, args...); e == nil || ExitCode(e) != 2 {
			t.Fatalf("invalid intent %v: %v", args, e)
		}
	}
	after, _ := os.ReadFile(p.Config)
	if string(before) != string(after) {
		t.Fatal("invalid/read-only command changed config")
	}
}

func TestAnalyticsCustomConfigsHaveIsolatedDefaultState(t *testing.T) {
	analyticsIsolation(t)
	a := analyticsCLI{configPath: filepath.Join(t.TempDir(), "a.toml")}
	b := analyticsCLI{configPath: filepath.Join(t.TempDir(), "b.toml")}
	pa, err := a.paths()
	if err != nil {
		t.Fatal(err)
	}
	pb, err := b.paths()
	if err != nil || pa.Database == pb.Database {
		t.Fatal("configurations share unrequested state")
	}
}

func TestAnalyticsCollectAndReportAgainstDisposableCore(t *testing.T) {
	settings, _ := analyticsIsolation(t)
	var reads atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/version" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"version":"test","meta":true}`)
			return
		}
		if r.Method != "GET" || r.URL.Path != "/connections" {
			t.Errorf("unexpected controller operation: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
			return
		}
		n := reads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"uploadTotal":%d,"downloadTotal":%d,"connections":[{"id":"a","start":"2026-01-01T00:00:00Z","upload":%d,"download":%d,"metadata":{"host":"download.example","sourceIP":"192.0.2.10","process":"fetcher"},"rule":"Domain","chains":["PROXY"]}]}`, n*100, n*200, n*100, n*200)
	}))
	defer server.Close()
	if err := os.MkdirAll(filepath.Dir(settings), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(fmt.Sprintf("[[targets]]\nid='fixture'\ncontroller='%s'\n", server.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, Dependencies{}, "--config", settings, "--target", "fixture", "analytics", "setup", "--source", "desktop", "--kind", "mihomo", "--enabled", "--poll-seconds", "1", "--yes"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, Dependencies{}, "analytics", "collect", "--duration", "2200ms", "--json"); err != nil {
		t.Fatal(err)
	}
	if reads.Load() < 2 {
		t.Fatalf("collector did not take multiple samples: %d", reads.Load())
	}
	out, _, err := run(t, Dependencies{}, "analytics", "report", "--group-by", "domain", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var report analytics.Report
	if err = json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	var up, down int64
	for _, row := range report.Rows {
		if row.Key == "download.example" {
			up += row.UploadBytes
			down += row.DownloadBytes
		}
	}
	if up != (reads.Load()-1)*100 || down != (reads.Load()-1)*200 {
		t.Fatalf("baseline/delta arithmetic: %d/%d reads=%d report=%s", up, down, reads.Load(), out)
	}
	prior := reads.Load()
	if _, _, err = run(t, Dependencies{}, "--read-only", "analytics", "report", "--json"); err != nil {
		t.Fatal(err)
	}
	if reads.Load() != prior {
		t.Fatal("report contacted a controller")
	}
	if _, _, err = run(t, Dependencies{}, "--read-only", "analytics", "collect", "--duration", "1s"); err == nil {
		t.Fatal("read-only collection allowed")
	}
}

func TestAnalyticsDoesNotInstallBySetupOrEnableRemoteTargets(t *testing.T) {
	settings, state := analyticsIsolation(t)
	if err := os.MkdirAll(filepath.Dir(settings), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte("[[targets]]\nid='remote'\ncontroller='http://127.0.0.1:9090'\nssh_host='fixture-host'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err := run(t, Dependencies{}, "--config", settings, "--target", "remote", "analytics", "setup", "--source", "remote", "--kind", "mihomo", "--enabled", "--yes")
	if err == nil || !strings.Contains(err.Error(), "host-local") {
		t.Fatalf("remote target was silently copied: %v", err)
	}
	entries, _ := os.ReadDir(state)
	if len(entries) > 0 {
		t.Fatal("setup installed service or initialized database")
	}
}

func TestAnalyticsRemoteSliceFlagsRoundTrip(t *testing.T) {
	analyticsIsolation(t)
	root := NewCommand()
	cmd, args, err := root.Find([]string{"analytics", "setup", "--collector-host", "fixture", "--threshold-gib", "25,60,120", "--alerts-enabled"})
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.ParseFlags(args); err != nil {
		t.Fatal(err)
	}
	forwarded := analyticsRemoteArgs(cmd)
	for _, arg := range forwarded {
		if strings.Contains(arg, "collector-host") || strings.Contains(arg, "remote-binary") {
			t.Fatalf("transport flag leaked into remote command: %q", arg)
		}
	}
	out, _, err := run(t, Dependencies{}, append([]string{"analytics"}, forwarded...)...)
	if err != nil {
		t.Fatalf("remote arguments invalid: %v: %v", forwarded, err)
	}
	var result struct {
		Config analytics.Config `json:"config"`
	}
	if err = json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(result.Config.Alerts.ThresholdGiB) != "[25 60 120]" {
		t.Fatalf("slice changed: %+v", result.Config.Alerts)
	}
}

func TestAnalyticsDisabledTargetDoesNotRequireSettings(t *testing.T) {
	analyticsIsolation(t)
	p, _ := analytics.DefaultPaths()
	cfg := analytics.DefaultConfig()
	cfg.SettingsPath = filepath.Join(t.TempDir(), "missing.toml")
	cfg.Sources = []analytics.SourceConfig{{ID: "disabled", Kind: "mihomo", Target: "gone", Enabled: false}}
	if err := analytics.SaveConfig(p.Config, cfg); err != nil {
		t.Fatal(err)
	}
	a := analyticsCLI{o: &options{}}
	targets, err := a.targets(NewCommand(), cfg)
	if err != nil || len(targets) != 0 {
		t.Fatalf("disabled source forced missing settings: %v %v", targets, err)
	}
	if _, _, err = run(t, Dependencies{}, "analytics", "setup", "--source", "disabled", "--enabled=false", "--yes"); err != nil {
		t.Fatalf("could not disable broken source: %v", err)
	}
}

func TestAnalyticsSetupCannotRetargetCollectedSource(t *testing.T) {
	analyticsIsolation(t)
	p, _ := analytics.DefaultPaths()
	cfg := analytics.DefaultConfig()
	source := analytics.SourceConfig{ID: "vps", Kind: "interface", Scope: "host", Interface: "eth0"}
	cfg.Sources = []analytics.SourceConfig{source}
	if err := analytics.SaveConfig(p.Config, cfg); err != nil {
		t.Fatal(err)
	}
	s, err := analytics.OpenStore(p.Database, false)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Ingest(context.Background(), analytics.Batch{SourceID: source.ID, Kind: source.Kind, Scope: source.Scope, Source: &source, At: time.Now()})
	s.Close()
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(p.Config)
	if _, _, err = run(t, Dependencies{}, "analytics", "setup", "--source", "vps", "--interface", "ens3", "--yes"); err == nil {
		t.Fatal("collected source was retargeted")
	}
	after, _ := os.ReadFile(p.Config)
	if string(before) != string(after) {
		t.Fatal("retarget changed config before failing")
	}
}

func TestAnalyticsFederatedCLIReadsNamespacedLocalSource(t *testing.T) {
	analyticsIsolation(t)
	p, _ := analytics.DefaultPaths()
	s, err := analytics.OpenStore(p.Database, false)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-time.Second)
	err = s.Ingest(context.Background(), analytics.Batch{SourceID: "fixture", Kind: "xray-access", Scope: "server", At: at, Events: []analytics.Event{{ID: "event", At: at, Domain: "example.test", Count: 1}}})
	s.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, tail := range [][]string{{"--also-host", "local"}, {"--source", "local::fixture"}} {
		args := append([]string{"analytics", "report", "--group-by", "domain", "--json"}, tail...)
		out, _, err := run(t, Dependencies{}, args...)
		if err != nil {
			t.Fatal(err)
		}
		var r analytics.Report
		if err = json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatal(err)
		}
		if len(r.Rows) != 1 || r.Rows[0].SourceID != "local::fixture" || r.Rows[0].Connections != 1 {
			t.Fatalf("wrong federated result: %s", out)
		}
	}
}
