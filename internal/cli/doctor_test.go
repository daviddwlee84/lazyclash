package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/doctor"
	"github.com/daviddwlee84/lazyclash/internal/networkcheck"
)

func doctorDeps(t *testing.T) Dependencies {
	t.Helper()
	return Dependencies{
		Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
			t.Error("unexpected open")
			return nil, nil, errors.New("fixture")
		},
		Discover: func(context.Context, string) ([]config.Target, error) {
			t.Error("general discovery used")
			return nil, errors.New("fixture")
		},
		Terminal: func(io.Reader, io.Writer) bool { t.Error("doctor must not prompt"); return false },
		Doctor: doctor.Options{
			Load:          func(string, bool) (config.Config, error) { return config.Config{}, nil },
			Getenv:        func(string) string { return "" },
			Environment:   func() map[string]any { return map[string]any{"variables": map[string]string{}} },
			DiscoverLocal: func(context.Context) ([]config.Target, error) { return nil, nil },
			ReadSystemProxy: func(context.Context, string, []string) (networkcheck.SystemProxySnapshot, error) {
				return networkcheck.SystemProxySnapshot{Unavailable: "fixture"}, nil
			},
			Inspect: func(context.Context, string, networkcheck.InspectOptions) (networkcheck.Report, error) {
				return networkcheck.Report{}, connection.ErrPythonUnavailable
			},
		},
	}
}

func decodeDoctor(t *testing.T, output string) doctor.Report {
	t.Helper()
	var r doctor.Report
	decoder := json.NewDecoder(strings.NewReader(output))
	if err := decoder.Decode(&r); err != nil {
		t.Fatalf("not a report: %q (%v)", output, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("second document: %s", output)
	}
	if r.SchemaVersion != 1 || r.Scope != "local-passive" || len(r.Checks) == 0 {
		t.Fatalf("invalid report: %+v", r)
	}
	return r
}

func TestDoctorSingleReportAndExitCodes(t *testing.T) {
	isolated(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("mutation")
		}
		switch r.URL.Path {
		case "/version":
			io.WriteString(w, `{"version":"v1"}`)
		case "/configs":
			io.WriteString(w, `{"mode":"rule","mixed-port":7897}`)
		default:
			t.Errorf("active request %s", r.URL.Path)
		}
	}))
	defer server.Close()
	deps := doctorDeps(t)
	deps.Open = connection.Open
	code, out, stderr := runProcess(t, deps, "--controller", server.URL, "doctor", "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	if r := decodeDoctor(t, out); r.Summary.ExitCode != code {
		t.Fatal("status mismatch")
	}
	code, out, stderr = runProcess(t, deps, "doctor", "--json")
	if code != 1 || stderr != "" {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	decodeDoctor(t, out)
	code, out, stderr = runProcess(t, deps, "--controller", server.URL, "doctor")
	if code != 0 || stderr != "" || !strings.Contains(out, "[pass] controller") || !strings.Contains(out, "Egress connectivity not tested") {
		t.Fatalf("human report: %d %s %s", code, out, stderr)
	}
	var stdout, errOut bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code = execute(ctx, []string{"doctor", "--json"}, strings.NewReader(""), &stdout, &errOut, deps)
	if code != 130 || errOut.Len() != 0 {
		t.Fatalf("cancellation %d %s", code, errOut.String())
	}
	if r := decodeDoctor(t, stdout.String()); !r.Summary.Canceled {
		t.Fatal("missing canceled state")
	}
}

func TestDoctorUsageAndHelpDoNotInitialize(t *testing.T) {
	isolated(t)
	deps := doctorDeps(t)
	deps.Doctor.Load = func(string, bool) (config.Config, error) {
		t.Error("initialized before validation/help")
		return config.Config{}, nil
	}
	deps.Doctor.Environment = func() map[string]any { t.Error("initialized environment before validation/help"); return nil }
	for _, args := range [][]string{{"doctor", "--timeout", "0"}, {"doctor", "--timeout", "-1s"}, {"doctor", "--timeout", "bad"}, {"doctor", "extra"}, {"doctor", "--target", "a", "--controller", "localhost:9090"}, {"doctor", "--controller", "http://user:password@localhost:9090/?token=private"}} {
		code, out, errOut := runProcess(t, deps, append(args, "--json")...)
		if code != 2 || out != "" {
			t.Errorf("%v => %d %q %q", args, code, out, errOut)
		}
		if strings.Contains(errOut, "password") || strings.Contains(errOut, "private") {
			t.Error("usage error leaked URL")
		}
	}
	code, out, errOut := runProcess(t, deps, "doctor", "--help")
	if code != 0 || errOut != "" || !strings.Contains(out, "--timeout") || !strings.Contains(out, "10s") {
		t.Fatalf("help %d %s %s", code, out, errOut)
	}
}

func TestDoctorBrokenSettingsAndExplicitRemote(t *testing.T) {
	isolated(t)
	path := filepath.Join(t.TempDir(), "bad.toml")
	original := []byte("default_target = [private-password")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	deps := doctorDeps(t)
	deps.Doctor.Load = config.Load
	code, out, errOut := runProcess(t, deps, "--config", path, "doctor", "--json")
	if code != 1 || errOut != "" {
		t.Fatalf("bad settings %d %s %s", code, out, errOut)
	}
	decodeDoctor(t, out)
	if strings.Contains(out, "private-password") {
		t.Fatal("TOML leaked")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(original, after) {
		t.Fatal("settings modified")
	}
	// Existing commands keep the old settings usage-error contract.
	code, out, errOut = runProcess(t, deps, "--config", path, "status", "--json")
	if code != 2 || out == "" && errOut == "" {
		t.Fatal("changed other command contract")
	}
	deps = doctorDeps(t)
	deps.Doctor.DiscoverLocal = func(context.Context) ([]config.Target, error) {
		t.Error("remote selection fell back to discovery")
		return nil, nil
	}
	for _, args := range [][]string{{"--controller", "http://example.invalid:9090", "doctor", "--json"}, {"--ssh", "fixture-host", "doctor", "--json"}} {
		code, out, errOut = runProcess(t, deps, args...)
		if code != 1 || errOut != "" || !strings.Contains(out, "not supported") {
			t.Fatalf("remote %d %s %s", code, out, errOut)
		}
		decodeDoctor(t, out)
	}
	t.Setenv("LAZYCLASH_TARGET", "remote")
	deps.Doctor.Load = func(string, bool) (config.Config, error) {
		return config.Config{Targets: []config.Target{{ID: "remote", Controller: "http://example.invalid:9090"}, {ID: "local", Controller: "http://127.0.0.1:9090"}}}, nil
	}
	code, out, errOut = runProcess(t, deps, "doctor", "--json")
	if code != 1 || errOut != "" || !strings.Contains(out, "not supported") {
		t.Fatalf("env remote %d %s %s", code, out, errOut)
	}
}

type doctorBrokenWriter struct{}

func (doctorBrokenWriter) Write([]byte) (int, error) { return 0, errors.New("fixture write failed") }

func TestDoctorWriterFailureIsNotReportedOutcome(t *testing.T) {
	isolated(t)
	deps := doctorDeps(t)
	var stderr bytes.Buffer
	code := execute(context.Background(), []string{"doctor", "--json"}, strings.NewReader(""), doctorBrokenWriter{}, &stderr, deps)
	if code != 1 || !strings.Contains(stderr.String(), "fixture write failed") {
		t.Fatalf("writer failure %d %s", code, stderr.String())
	}
	failure := decodeFailure(t, stderr.String())
	if failure.Code != "runtime" {
		t.Fatalf("%+v", failure)
	}
}

func TestDoctorOverallDefaultAndShortDeadline(t *testing.T) {
	isolated(t)
	deps := doctorDeps(t)
	deps.Doctor.Inspect = func(ctx context.Context, _ string, _ networkcheck.InspectOptions) (networkcheck.Report, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > doctor.DefaultTimeout {
			t.Error("not bounded by overall timeout")
		}
		return networkcheck.Report{}, connection.ErrPythonUnavailable
	}
	code, out, errOut := runProcess(t, deps, "doctor", "--json")
	if code != 1 || errOut != "" {
		t.Fatalf("default %d %s", code, errOut)
	}
	decodeDoctor(t, out)
	deps.Doctor.Load = func(string, bool) (config.Config, error) {
		return config.Config{Targets: []config.Target{{ID: "local", Controller: "http://127.0.0.1:9090"}}}, nil
	}
	deps.Open = func(ctx context.Context, _ config.Target, _ bool) (*core.Client, io.Closer, error) {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	code, out, errOut = runProcess(t, deps, "doctor", "--timeout", "20ms", "--json")
	if code != 1 || errOut != "" {
		t.Fatalf("timeout %d %s", code, errOut)
	}
	if r := decodeDoctor(t, out); !r.Summary.TimedOut {
		t.Fatal("no timeout flag")
	}
}
