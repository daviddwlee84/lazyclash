package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/compare"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/testcore"
)

func savedComparisonPair(t *testing.T) (string, *testcore.Controller, *testcore.Controller) {
	t.Helper()
	path := isolated(t)
	left, right := testcore.NewHandler(), testcore.NewHandler()
	serve := func(handler *testcore.Controller, expected string) *httptest.Server {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+expected {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			handler.ServeHTTP(w, r)
		}))
		t.Cleanup(server.Close)
		return server
	}
	t.Setenv("LEFT_COMPARE_SECRET", "left-private-secret")
	t.Setenv("RIGHT_COMPARE_SECRET", "right-private-secret")
	a, b := serve(left, "left-private-secret"), serve(right, "right-private-secret")
	targets := []config.Target{{ID: "left", Controller: a.URL, SecretEnv: "LEFT_COMPARE_SECRET"}, {ID: "right", Controller: b.URL, SecretEnv: "RIGHT_COMPARE_SECRET"}}
	if err := config.Save(path, config.Config{Targets: targets}); err != nil {
		t.Fatal(err)
	}
	for index, target := range targets {
		client, err := core.New(core.Options{Endpoint: target.Controller, Secret: os.Getenv(target.SecretEnv)})
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			_, err = client.SetConfig(context.Background(), core.Object{"mode": "global", "log-level": "debug"})
		} else {
			err = client.Select(context.Background(), testcore.Selector, testcore.Tokyo)
		}
		_ = client.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	return path, left, right
}

func writeCount(handler *testcore.Controller) int {
	count := 0
	for _, request := range handler.Requests() {
		if request.Method != http.MethodGet {
			count++
		}
	}
	return count
}

func TestTargetDiffAndCopyKeepSavedCredentialsAndPreviewByDefault(t *testing.T) {
	path, left, right := savedComparisonPair(t)
	before, _ := os.ReadFile(path)
	leftWrites, rightWrites := writeCount(left), writeCount(right)
	t.Setenv("LAZYCLASH_TARGET", "unrelated")
	t.Setenv("LAZYCLASH_CONTROLLER", "http://must-not-be-used.invalid")
	deps := Dependencies{Discover: func(context.Context, string) ([]config.Target, error) {
		t.Fatal("two-target command discovered an endpoint")
		return nil, nil
	}}
	out, _, err := run(t, deps, "targets", "diff", "left", "right", "--read-only", "--json")
	var difference compare.DiffResult
	if err != nil || json.Unmarshal([]byte(out), &difference) != nil || difference.Equal || difference.Source.Target.ID != "left" || difference.Destination.Target.ID != "right" {
		t.Fatalf("diff: %s %v", out, err)
	}
	args := []string{"targets", "copy-settings", "left", "right", "--field", "mode", "--field", "log-level", "--group", testcore.Selector, "--json"}
	out, _, err = run(t, deps, append(append([]string{}, args...), "--read-only")...)
	var plan compare.Plan
	if err != nil || json.Unmarshal([]byte(out), &plan) != nil || plan.Digest == "" || len(plan.Steps) != 3 {
		t.Fatalf("preview: %s %v", out, err)
	}
	if writeCount(left) != leftWrites || writeCount(right) != rightWrites {
		t.Fatal("preview wrote runtime state")
	}
	out, _, err = run(t, deps, append(args, "--yes", "--expect", plan.Digest)...)
	var applied compare.ApplyResult
	if err != nil || json.Unmarshal([]byte(out), &applied) != nil || applied.Status != "applied" || writeCount(left) != leftWrites || writeCount(right) != rightWrites+3 {
		t.Fatalf("apply: %s %v writes %d/%d", out, err, writeCount(left), writeCount(right))
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("runtime copy rewrote saved settings")
	}
	if strings.Contains(out, "private-secret") {
		t.Fatal("credential leaked")
	}
}

func TestComparisonRejectsTemporaryOverridesAndUnreviewedWrites(t *testing.T) {
	savedComparisonPair(t)
	deps := Dependencies{Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		t.Fatal("invalid intent opened a controller")
		return nil, nil, nil
	}}
	for _, flag := range []string{"target", "controller", "ssh", "secret-file", "secret-env", "ca-cert"} {
		for _, operation := range []string{"diff", "copy-settings"} {
			args := []string{"--" + flag, "temporary", "targets", operation, "left", "right", "--json"}
			_, _, err := run(t, deps, args...)
			if err == nil || ExitCode(err) != 2 {
				t.Fatalf("accepted override %v: %v", args, err)
			}
		}
	}
	for _, extra := range [][]string{{}, {"--field", "tun"}, {"--field", "mode", "--yes"}, {"--field", "mode", "--expect", strings.Repeat("0", 64)}, {"--field", "mode", "--yes", "--expect", "bad"}} {
		args := append([]string{"targets", "copy-settings", "left", "right", "--json"}, extra...)
		_, _, err := run(t, deps, args...)
		if err == nil || ExitCode(err) != 2 {
			t.Fatalf("accepted unsupported request %v: %v", args, err)
		}
	}
}

func TestCopyJSONStaleReceiptAndReadOnlyFailure(t *testing.T) {
	_, left, right := savedComparisonPair(t)
	args := []string{"targets", "copy-settings", "left", "right", "--field", "mode", "--yes", "--expect", strings.Repeat("0", 64), "--json"}
	before := writeCount(left) + writeCount(right)
	var out, errOut bytes.Buffer
	code := execute(context.Background(), args, strings.NewReader(""), &out, &errOut, Dependencies{})
	var result compare.ApplyResult
	var envelope errorEnvelope
	if code != 1 || json.Unmarshal(out.Bytes(), &result) != nil || result.Status != "stale" || json.Unmarshal(errOut.Bytes(), &envelope) != nil {
		t.Fatalf("stale receipt: exit=%d out=%s err=%s", code, &out, &errOut)
	}
	out.Reset()
	errOut.Reset()
	code = execute(context.Background(), append(args, "--read-only"), strings.NewReader(""), &out, &errOut, Dependencies{})
	if code != 1 || out.Len() != 0 || json.Unmarshal(errOut.Bytes(), &envelope) != nil || envelope.Error.Code != "read-only" {
		t.Fatalf("read-only: exit=%d out=%s err=%s", code, &out, &errOut)
	}
	if writeCount(left)+writeCount(right) != before {
		t.Fatal("rejected apply performed a write")
	}
}
