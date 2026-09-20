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
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

func logsServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			_ = json.NewEncoder(w).Encode(core.Object{"version": "fixture", "meta": true})
			return
		}
		handler(w, r)
	}))
}

func TestLogsLimitCountsFilteredOutput(t *testing.T) {
	isolated(t)
	server := logsServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/logs" || r.URL.Query().Get("level") != "debug" {
			t.Errorf("unexpected log request: %s", r.URL)
		}
		for _, payload := range []string{"skip", "keep first", "skip again", "KEEP second", "keep extra"} {
			_ = json.NewEncoder(w).Encode(core.Object{"type": "info", "payload": payload})
		}
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	for _, jsonOutput := range []bool{false, true} {
		t.Run(map[bool]string{false: "text", true: "ndjson"}[jsonOutput], func(t *testing.T) {
			cmd := NewCommand()
			args := []string{"--controller", server.URL, "logs", "--level", "debug", "--filter", "KEEP", "--limit", "2", "--duration", "1s"}
			if jsonOutput {
				args = append(args, "--json")
			}
			cmd.SetArgs(args)
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(io.Discard)
			cmd.SetIn(strings.NewReader(""))
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := cmd.ExecuteContext(ctx); err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(out.String()), "\n")
			if len(lines) != 2 || !strings.Contains(lines[0], "keep first") || !strings.Contains(lines[1], "KEEP second") {
				t.Fatalf("wrong filtered output: %q", out.String())
			}
			if jsonOutput {
				for _, line := range lines {
					if !json.Valid([]byte(line)) {
						t.Fatalf("invalid NDJSON line: %q", line)
					}
				}
			}
		})
	}
}

func TestLogsInvalidBoundsDoNotOpenOrDiscover(t *testing.T) {
	settingsPath := isolated(t)
	deps := Dependencies{
		Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
			t.Fatal("invalid bound opened the core")
			return nil, nil, nil
		},
		Discover: func(context.Context, string) ([]config.Target, error) {
			t.Fatal("invalid bound discovered targets")
			return nil, nil
		},
	}
	for _, flags := range [][]string{{"--duration=-1s"}, {"--duration=forever"}, {"--limit=-1"}, {"--limit=one"}} {
		_, _, err := run(t, deps, append([]string{"logs"}, flags...)...)
		if err == nil || ExitCode(err) != 2 {
			t.Fatalf("%v: want usage error, got %v", flags, err)
		}
	}
	if _, err := os.Stat(settingsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid logs command created settings: %v", err)
	}
}

func TestLogsQuietStreamStopsAtDuration(t *testing.T) {
	isolated(t)
	server := logsServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	cmd := NewCommand()
	cmd.SetArgs([]string{"--controller", server.URL, "logs", "--duration", "30ms", "--json"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetIn(strings.NewReader(""))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("quiet stream produced output: %q", out.String())
	}
}

type cancelLogsWriter struct{ cancel context.CancelFunc }

func (w cancelLogsWriter) Write(p []byte) (int, error) {
	w.cancel()
	return len(p), nil
}

func TestLogsCallerCancellationRetainsExitCode(t *testing.T) {
	isolated(t)
	server := logsServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(core.Object{"type": "info", "payload": "one"})
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	for _, limits := range [][]string{{}, {"--duration", "1s", "--limit", "1"}} {
		ctx, cancel := context.WithCancel(context.Background())
		cmd := NewCommand()
		cmd.SetArgs(append([]string{"--controller", server.URL, "logs", "--json"}, limits...))
		cmd.SetOut(cancelLogsWriter{cancel})
		cmd.SetErr(io.Discard)
		cmd.SetIn(strings.NewReader(""))
		err := cmd.ExecuteContext(ctx)
		cancel()
		if !errors.Is(err, context.Canceled) || ExitCode(err) != 130 {
			t.Fatalf("%v: cancellation became success or wrong exit code: %v", limits, err)
		}
	}
}

func TestLogsOutputFailureAtLimitIsError(t *testing.T) {
	isolated(t)
	server := logsServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(core.Object{"type": "info", "payload": "one"})
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	failure := errors.New("output closed")
	cmd := NewCommand()
	cmd.SetArgs([]string{"--controller", server.URL, "logs", "--limit", "1", "--duration", "1s", "--json"})
	cmd.SetOut(brokenWriter{failure})
	cmd.SetErr(io.Discard)
	cmd.SetIn(strings.NewReader(""))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := cmd.ExecuteContext(ctx); !errors.Is(err, failure) {
		t.Fatalf("output failure became bounded success: %v", err)
	}
}

func TestLogsBoundedStreamFailuresRemainErrors(t *testing.T) {
	isolated(t)
	for _, test := range []struct {
		name   string
		status int
		kind   core.ErrorKind
	}{
		{"authentication", http.StatusUnauthorized, core.KindAuth},
		{"disconnect", http.StatusOK, core.KindUnreachable},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := logsServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(test.status) }))
			defer server.Close()
			_, _, err := run(t, Dependencies{}, "--controller", server.URL, "logs", "--duration", "1s", "--limit", "1", "--json")
			var apiErr *core.Error
			if !errors.As(err, &apiErr) || apiErr.Kind != test.kind || ExitCode(err) != 1 {
				t.Fatalf("want %s and exit 1, got %v", test.kind, err)
			}
		})
	}
}
