package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/selfupdate"
)

func upgradeFixture() selfupdate.Result {
	return selfupdate.Result{
		Status: "checked", CurrentVersion: "v0.1.1", LatestVersion: "v0.1.2", UpdateAvailable: true, CanUpgrade: true,
		ReleaseURL:   "https://github.com/daviddwlee84/lazyclash/releases/tag/v0.1.2",
		Installation: selfupdate.Installation{Executable: "/test/link", ResolvedPath: "/test/custom/lazyclash", Version: "v0.1.1", BuildKind: "release", Method: "go-install", IdentityValid: true, Evidence: []string{"matching module/package metadata"}},
	}
}

func TestUpgradeBypassesSettingsCoreAndPrompts(t *testing.T) {
	path := isolated(t)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[[malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{
		Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
			t.Fatal("opened core")
			return nil, nil, nil
		},
		Discover: func(context.Context, string) ([]config.Target, error) { t.Fatal("discovered core"); return nil, nil },
		Terminal: func(io.Reader, io.Writer) bool { t.Fatal("attempted prompting decision"); return false },
		Upgrade: func(_ context.Context, request selfupdate.Request, progress io.Writer) (selfupdate.Result, error) {
			if !request.Check || request.Force {
				t.Fatalf("request %+v", request)
			}
			return upgradeFixture(), nil
		},
	}
	out, _, err := run(t, deps, "--config", path, "upgrade", "--check", "--json")
	var result selfupdate.Result
	if err != nil || json.Unmarshal([]byte(out), &result) != nil || !result.CanUpgrade {
		t.Fatalf("%s %v", out, err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "[[malformed" {
		t.Fatalf("settings changed: %s", data)
	}
}

func TestUpgradeJSONProgressAndForceContract(t *testing.T) {
	isolated(t)
	for _, test := range []struct {
		args []string
		want selfupdate.Request
	}{
		{[]string{"upgrade", "--json"}, selfupdate.Request{}},
		{[]string{"upgrade", "--force", "--json"}, selfupdate.Request{Force: true}},
		{[]string{"upgrade", "--check", "--force", "--json"}, selfupdate.Request{Check: true, Force: true}},
		{[]string{"upgrade", "--check=false", "--force=false", "--json"}, selfupdate.Request{}},
	} {
		deps := Dependencies{Upgrade: func(_ context.Context, got selfupdate.Request, progress io.Writer) (selfupdate.Result, error) {
			if got != test.want {
				t.Fatalf("got %+v want %+v", got, test.want)
			}
			fmtResult := upgradeFixture()
			fmtResult.Status = "updated"
			io.WriteString(progress, "download/build progress\n")
			return fmtResult, nil
		}}
		out, errOut, err := run(t, deps, test.args...)
		if err != nil || errOut != "" || !json.Valid([]byte(out)) || strings.Contains(out, "progress") {
			t.Fatalf("%v: %q %q %v", test.args, out, errOut, err)
		}
	}
}

func TestUpgradeErrorAndCancellationContracts(t *testing.T) {
	isolated(t)
	for _, test := range []struct {
		err  error
		exit int
		code string
	}{
		{errors.New("development build requires --force"), 1, "runtime"},
		{context.Canceled, 130, "canceled"},
		{context.DeadlineExceeded, 1, "timeout"},
	} {
		var out, errOut bytes.Buffer
		deps := Dependencies{Upgrade: func(context.Context, selfupdate.Request, io.Writer) (selfupdate.Result, error) {
			return upgradeFixture(), test.err
		}}
		code := execute(context.Background(), []string{"upgrade", "--json"}, strings.NewReader(""), &out, &errOut, deps)
		var envelope errorEnvelope
		if code != test.exit || out.Len() != 0 || json.Unmarshal(errOut.Bytes(), &envelope) != nil || envelope.Error.Code != test.code {
			t.Fatalf("exit %d stdout %s stderr %s", code, &out, &errOut)
		}
	}
}

func TestUpgradeHelpAndInvalidArgsDoNotRun(t *testing.T) {
	path := isolated(t)
	deps := Dependencies{Upgrade: func(context.Context, selfupdate.Request, io.Writer) (selfupdate.Result, error) {
		t.Fatal("upgrade ran")
		return selfupdate.Result{}, nil
	}}
	for _, args := range [][]string{{"upgrade", "--help"}, {"--config", "/missing/settings", "upgrade", "--help"}} {
		out, _, err := run(t, deps, args...)
		if err != nil || !strings.Contains(out, "--check") || !strings.Contains(out, "--force") {
			t.Fatalf("%s %v", out, err)
		}
	}
	for _, args := range [][]string{{"upgrade", "unexpected"}, {"upgrade", "--typo"}} {
		if _, _, err := run(t, deps, args...); err == nil || ExitCode(err) != 2 {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("created config directory: %v", err)
	}
}

func TestUpgradeHumanOutputAndOutputFailure(t *testing.T) {
	isolated(t)
	deps := Dependencies{Upgrade: func(_ context.Context, _ selfupdate.Request, progress io.Writer) (selfupdate.Result, error) {
		io.WriteString(progress, "Building pinned release\n")
		return upgradeFixture(), nil
	}}
	out, errOut, err := run(t, deps, "upgrade", "--check")
	if err != nil || !strings.Contains(out, "/test/custom/lazyclash") || !strings.Contains(out, "Can upgrade here: true") || !strings.Contains(errOut, "Building pinned") {
		t.Fatalf("%s %s %v", out, errOut, err)
	}
	want := errors.New("closed output")
	if err := printUpgrade(brokenWriter{want}, upgradeFixture()); !errors.Is(err, want) {
		t.Fatalf("lost output failure: %v", err)
	}
}
