package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

func runProcess(t *testing.T, deps Dependencies, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := execute(context.Background(), args, strings.NewReader(""), &out, &errOut, deps)
	return code, out.String(), errOut.String()
}

func decodeFailure(t *testing.T, output string) errorDetails {
	t.Helper()
	var envelope errorEnvelope
	decoder := json.NewDecoder(strings.NewReader(output))
	if err := decoder.Decode(&envelope); err != nil {
		t.Fatalf("invalid error JSON %q: %v", output, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("extra error output: %q", output)
	}
	if envelope.Error.Code == "" || envelope.Error.Message == "" {
		t.Fatalf("missing error fields: %q", output)
	}
	return envelope.Error
}

func TestJSONErrorsIncludeSyntaxAndNeverPolluteStdout(t *testing.T) {
	isolated(t)
	for _, args := range [][]string{
		{"mode", "typo", "--json"},
		{"--unknown", "--json"},
		{"missing-command", "--json"},
		{"--config", "/not/present/lazyclash.toml", "status", "--json"},
		{"proxies", "select", "--json"},
		{"--skill", "--json"},
	} {
		code, out, errOut := runProcess(t, Dependencies{}, args...)
		if code != 2 || out != "" {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", args, code, out, errOut)
		}
		if got := decodeFailure(t, errOut); got.Code != "usage" {
			t.Fatalf("%v: %+v", args, got)
		}
	}
}

func TestJSONIntentRespectsValuesAndTerminator(t *testing.T) {
	cmd := NewCommand()
	for _, test := range []struct {
		args []string
		want bool
	}{
		{[]string{"--json"}, true},
		{[]string{"--json=false"}, false},
		{[]string{"--json=1"}, true},
		{[]string{"--json", "--json=false"}, false},
		{[]string{"--config", "--json", "status"}, false},
		{[]string{"logs", "--filter", "--json"}, false},
		{[]string{"logs", "--filter=--json", "--json"}, true},
		{[]string{"proxies", "select", "group", "--", "--json"}, false},
		{[]string{"--unknown", "--json"}, true},
	} {
		if got := jsonRequested(cmd, test.args); got != test.want {
			t.Fatalf("%v: %v want %v", test.args, got, test.want)
		}
	}
}

func TestJSONCoreFailureCategoriesAndRedaction(t *testing.T) {
	isolated(t)
	for _, status := range []int{http.StatusUnauthorized, http.StatusNotFound, http.StatusBadRequest} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"message":"private-secret-from-controller"}`)
		}))
		code, out, errOut := runProcess(t, Dependencies{}, "--controller", server.URL, "--json", "status")
		server.Close()
		if code != 1 || out != "" || strings.Contains(errOut, "private-secret") {
			t.Fatalf("unsafe failure: %d %q %q", code, out, errOut)
		}
		got := decodeFailure(t, errOut)
		if got.HTTPStatus != status || got.Operation == "" {
			t.Fatalf("missing core details: %+v", got)
		}
		want := map[int]string{401: "auth", 404: "unsupported", 400: "invalid"}[status]
		if got.Code != want {
			t.Fatalf("code=%q want %q", got.Code, want)
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	code, _, errOut := runProcess(t, Dependencies{}, "--controller", server.URL, "status", "--json")
	if got := decodeFailure(t, errOut); code != 1 || got.Code != "tls" {
		t.Fatalf("TLS failure: %d %+v", code, got)
	}
}

func TestJSONDisablesSSHAuthenticationEvenWithTerminal(t *testing.T) {
	isolated(t)
	for _, discovery := range []bool{false, true} {
		calls := 0
		deps := Dependencies{
			Terminal: func(io.Reader, io.Writer) bool { return true },
			Authenticate: func(context.Context, string) (*exec.Cmd, error) {
				calls++
				return nil, errors.New("must not authenticate")
			},
			Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
				return nil, nil, &connection.AuthRequiredError{Host: "fixture"}
			},
			Discover: func(context.Context, string) ([]config.Target, error) {
				return nil, &connection.AuthRequiredError{Host: "fixture"}
			},
		}
		args := []string{"--ssh", "fixture", "--controller", "http://127.0.0.1:9090", "--json", "status"}
		if discovery {
			args = []string{"--ssh", "fixture", "--json", "targets", "discover"}
		}
		code, out, errOut := runProcess(t, deps, args...)
		if code != 1 || out != "" || calls != 0 {
			t.Fatalf("interactive side effect: %d %q calls=%d", code, out, calls)
		}
		if got := decodeFailure(t, errOut); got.Code != "ssh-auth-required" {
			t.Fatalf("unexpected %+v", got)
		}
	}
}

func TestErrorClassificationPreservesUnknownWrite(t *testing.T) {
	for _, test := range []struct {
		err  error
		code string
		exit int
	}{
		{fmt.Errorf("settings: %w", config.ErrConflict), "config-conflict", 1},
		{context.Canceled, "canceled", 130},
		{context.DeadlineExceeded, "timeout", 1},
		{&core.Error{Kind: core.KindUnknownWrite, Operation: "apply config"}, "unknown-write-result", 1},
		{&core.Error{Kind: core.KindReadOnly, Operation: "select"}, "read-only", 1},
		{errors.New("output closed"), "runtime", 1},
	} {
		if got := describeError(test.err); got.Code != test.code || ExitCode(test.err) != test.exit {
			t.Fatalf("%v: %+v exit=%d", test.err, got, ExitCode(test.err))
		}
	}
}

func TestHumanErrorsRemainText(t *testing.T) {
	isolated(t)
	code, out, errOut := runProcess(t, Dependencies{}, "mode", "invalid")
	if code != 2 || out != "" || !strings.HasPrefix(errOut, "lazyclash: ") || json.Valid([]byte(errOut)) {
		t.Fatalf("human error: %d %q %q", code, out, errOut)
	}
	// A secret-reference filename named --json is a value, not output intent.
	code, _, errOut = runProcess(t, Dependencies{}, "--config", "--json", "status")
	if code != 2 || json.Valid([]byte(errOut)) {
		t.Fatalf("mistook flag value for JSON mode: %d %q", code, errOut)
	}
	if _, err := os.Stat("--json"); err == nil {
		t.Fatal("test must not create settings")
	}
}
