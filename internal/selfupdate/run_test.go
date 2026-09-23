package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func updateFixture(t *testing.T) (Installation, runOptions) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix standalone executable replacement; Windows uses Scoop handoff")
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "custom-name")
	if err := os.WriteFile(path, []byte("original executable"), 0750); err != nil {
		t.Fatal(err)
	}
	installation := Installation{Executable: path, ResolvedPath: path, Version: "v0.1.1", BuildKind: "release", Method: "go-install", IdentityValid: true}
	opts := runOptions{
		inspect: func() (Installation, error) { return installation, nil },
		latest: func(context.Context) (Release, error) {
			return Release{Version: "v0.1.2", URL: "https://github.com/daviddwlee84/lazyclash/releases/tag/v0.1.2"}, nil
		},
		lookPath: func(name string) (string, error) { return "/test/go", nil },
		build: func(_ context.Context, goPath, stage, version string) error {
			if goPath != "/test/go" || version != "v0.1.2" {
				t.Errorf("build used %q, %q", goPath, version)
			}
			if filepath.Dir(stage) != filepath.Dir(path) {
				t.Errorf("staging is not next to destination: %s", stage)
			}
			info, err := os.Stat(stage)
			if err != nil || info.Mode().Perm() != 0700 {
				t.Errorf("staging permissions: %v, %v", info, err)
			}
			return os.WriteFile(filepath.Join(stage, "lazyclash"), []byte("verified replacement"), 0755)
		},
		inspectCandidate: func(path string) (Installation, error) {
			return Installation{Version: "v0.1.2", BuildKind: "release", IdentityValid: true, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}, nil
		},
		version: func(context.Context, string) (string, error) { return "lazyclash version v0.1.2\n", nil },
	}
	return installation, opts
}

func requireOriginal(t *testing.T, installation Installation) {
	t.Helper()
	body, err := os.ReadFile(installation.ResolvedPath)
	if err != nil || string(body) != "original executable" {
		t.Fatalf("original changed: %q, %v", body, err)
	}
	requireNoStage(t, installation)
}

func requireNoStage(t *testing.T, installation Installation) {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(filepath.Dir(installation.ResolvedPath), "."+filepath.Base(installation.ResolvedPath)+".upgrade-*"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging not cleaned: %v, %v", entries, err)
	}
}

func TestUpdateReplacesResolvedExecutableAndPreservesPermissions(t *testing.T) {
	installation, opts := updateFixture(t)
	link := filepath.Join(filepath.Dir(installation.Executable), "lazyclash")
	if err := os.Symlink(filepath.Base(installation.Executable), link); err != nil {
		t.Fatal(err)
	}
	installation.Executable = link
	opts.inspect = func() (Installation, error) { return installation, nil }
	var progress bytes.Buffer
	result, err := run(context.Background(), Request{}, &progress, opts)
	if err != nil || result.Status != "updated" || !result.UpdateAvailable || !result.CanUpgrade {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	body, err := os.ReadFile(installation.ResolvedPath)
	if err != nil || string(body) != "verified replacement" {
		t.Fatalf("replacement=%q, %v", body, err)
	}
	info, err := os.Stat(installation.ResolvedPath)
	if err != nil || info.Mode().Perm() != 0750 {
		t.Fatalf("permissions=%v, %v", info, err)
	}
	if _, err := os.Readlink(link); err != nil {
		t.Fatal("symlink was overwritten:", err)
	}
	if !strings.Contains(progress.String(), "v0.1.2") {
		t.Fatal("no progress", progress.String())
	}
	requireNoStage(t, installation)
}

func TestCheckDoesNotWriteOrBuild(t *testing.T) {
	installation, opts := updateFixture(t)
	opts.build = func(context.Context, string, string, string) error { t.Fatal("check built a release"); return nil }
	before, err := os.ReadDir(filepath.Dir(installation.ResolvedPath))
	if err != nil {
		t.Fatal(err)
	}
	result, err := run(context.Background(), Request{Check: true}, io.Discard, opts)
	if err != nil || result.Status != "checked" || !result.UpdateAvailable || !result.CanUpgrade {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	after, err := os.ReadDir(filepath.Dir(installation.ResolvedPath))
	if err != nil || len(before) != len(after) {
		t.Fatalf("check wrote files: before=%v after=%v error=%v", before, after, err)
	}
	requireOriginal(t, installation)
}

func TestUpdatePolicies(t *testing.T) {
	for _, test := range []struct {
		name, version, kind, method, manager string
		identity, force, check, noGo         bool
		wantStatus                           string
		wantErr, wantBuild                   bool
	}{
		{name: "same", version: "v0.1.2", identity: true, wantStatus: "up-to-date"},
		{name: "newer", version: "v0.1.3", identity: true, wantStatus: "up-to-date"},
		{name: "force same", version: "v0.1.2", identity: true, force: true, wantStatus: "updated", wantBuild: true},
		{name: "force downgrade", version: "v0.1.3", identity: true, force: true, wantStatus: "updated", wantBuild: true},
		{name: "dev", version: "dev", kind: "development", identity: true, wantStatus: "development", wantErr: true},
		{name: "force dev", version: "dev", kind: "development", identity: true, force: true, wantStatus: "updated", wantBuild: true},
		{name: "check dev", version: "dev", kind: "development", identity: true, check: true, wantStatus: "checked"},
		{name: "unknown force", version: "v0.1.1", force: true, wantStatus: "unsupported", wantErr: true},
		{name: "manager force", version: "v0.1.1", identity: true, method: "package-manager", manager: "homebrew", force: true, wantStatus: "unsupported", wantErr: true},
		{name: "missing go", version: "v0.1.1", identity: true, noGo: true, wantStatus: "unsupported", wantErr: true},
		{name: "same missing go", version: "v0.1.2", identity: true, noGo: true, wantStatus: "up-to-date"},
		{name: "newer missing go", version: "v0.1.3", identity: true, noGo: true, wantStatus: "up-to-date"},
		{name: "same force missing go", version: "v0.1.2", identity: true, noGo: true, force: true, wantStatus: "unsupported", wantErr: true},
		{name: "check missing go", version: "v0.1.1", identity: true, noGo: true, check: true, wantStatus: "checked"},
	} {
		t.Run(test.name, func(t *testing.T) {
			installation, opts := updateFixture(t)
			installation.Version, installation.IdentityValid = test.version, test.identity
			if test.kind != "" {
				installation.BuildKind = test.kind
			}
			if test.method != "" {
				installation.Method = test.method
			}
			installation.Manager = test.manager
			opts.inspect = func() (Installation, error) { return installation, nil }
			if test.noGo {
				opts.lookPath = func(string) (string, error) { return "", errors.New("missing") }
			}
			built := false
			build := opts.build
			opts.build = func(ctx context.Context, goPath, stage, version string) error {
				built = true
				return build(ctx, goPath, stage, version)
			}
			result, err := run(context.Background(), Request{Check: test.check, Force: test.force}, nil, opts)
			if (err != nil) != test.wantErr || result.Status != test.wantStatus || built != test.wantBuild {
				t.Fatalf("status=%s err=%v built=%v; want status=%s err=%v built=%v", result.Status, err, built, test.wantStatus, test.wantErr, test.wantBuild)
			}
			if !built {
				requireOriginal(t, installation)
			}
		})
	}
}

func TestFailuresRetainOriginalAndCleanup(t *testing.T) {
	for _, failure := range []string{"build", "identity", "metadata version", "metadata platform", "printed version", "version command", "candidate symlink", "cancel build", "cancel version", "build timeout", "version timeout"} {
		t.Run(failure, func(t *testing.T) {
			installation, opts := updateFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch failure {
			case "build":
				opts.build = func(context.Context, string, string, string) error {
					return errors.New("failed https://alice:secret@proxy.invalid?token=unsafe\x1b[2J")
				}
			case "identity", "metadata version":
				opts.inspectCandidate = func(string) (Installation, error) {
					return Installation{IdentityValid: failure != "identity", BuildKind: "release", Version: "v9.0.0"}, nil
				}
			case "metadata platform":
				opts.inspectCandidate = func(string) (Installation, error) {
					return Installation{IdentityValid: true, BuildKind: "release", Version: "v0.1.2", GOOS: runtime.GOOS, GOARCH: "another-architecture"}, nil
				}
			case "printed version":
				opts.version = func(context.Context, string) (string, error) { return "lazyclash version v9.0.0", nil }
			case "version command":
				opts.version = func(context.Context, string) (string, error) { return "", errors.New("unsafe") }
			case "candidate symlink":
				opts.build = func(_ context.Context, _, stage, _ string) error {
					return os.Symlink(installation.ResolvedPath, filepath.Join(stage, "lazyclash"))
				}
			case "cancel build":
				opts.build = func(context.Context, string, string, string) error { cancel(); return errors.New("killed") }
			case "cancel version":
				opts.version = func(context.Context, string) (string, error) { cancel(); return "", errors.New("killed") }
			case "build timeout":
				opts.build = func(context.Context, string, string, string) error { return context.DeadlineExceeded }
			case "version timeout":
				opts.version = func(context.Context, string) (string, error) { return "", context.DeadlineExceeded }
			}
			_, err := run(ctx, Request{}, nil, opts)
			if err == nil || strings.Contains(err.Error(), "unsafe") || strings.Contains(err.Error(), "secret") {
				t.Fatal("incorrect or leaking error:", err)
			}
			if strings.HasPrefix(failure, "cancel") && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost:", err)
			}
			if strings.HasSuffix(failure, "timeout") && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("timeout lost:", err)
			}
			requireOriginal(t, installation)
		})
	}
}

func TestRefusesConcurrentUpdate(t *testing.T) {
	installation, opts := updateFixture(t)
	unlock, err := acquireLock(installation.ResolvedPath)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	opts.build = func(context.Context, string, string, string) error { t.Fatal("concurrent build ran"); return nil }
	_, err = run(context.Background(), Request{}, nil, opts)
	if err == nil || !strings.Contains(err.Error(), "already updating") {
		t.Fatal("did not refuse concurrent upgrade:", err)
	}
	requireOriginal(t, installation)
}

func TestDestinationChangedDuringReleaseLookupIsNotOverwritten(t *testing.T) {
	installation, opts := updateFixture(t)
	latest := opts.latest
	opts.latest = func(ctx context.Context) (Release, error) {
		other := installation.ResolvedPath + ".new"
		if err := os.WriteFile(other, []byte("another installation"), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(other, installation.ResolvedPath); err != nil {
			t.Fatal(err)
		}
		return latest(ctx)
	}
	opts.build = func(context.Context, string, string, string) error { t.Fatal("build should not start"); return nil }
	_, err := run(context.Background(), Request{}, nil, opts)
	if err == nil || !strings.Contains(err.Error(), "changed during upgrade") {
		t.Fatal("lookup-time replacement not detected:", err)
	}
	requireNoStage(t, installation)
}

func TestReadonlyExecutableModeIsPreserved(t *testing.T) {
	installation, opts := updateFixture(t)
	if err := os.Chmod(installation.ResolvedPath, 0555); err != nil {
		t.Fatal(err)
	}
	if _, err := run(context.Background(), Request{}, nil, opts); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(installation.ResolvedPath)
	if err != nil || info.Mode().Perm() != 0555 {
		t.Fatalf("permissions not preserved: %v %v", info, err)
	}
}

func TestRefusesChangedDestination(t *testing.T) {
	for _, change := range []string{"replace", "edit with preserved metadata", "symlink"} {
		t.Run(change, func(t *testing.T) {
			installation, opts := updateFixture(t)
			if change == "symlink" {
				installation.Executable += "-link"
				if err := os.Symlink(installation.ResolvedPath, installation.Executable); err != nil {
					t.Fatal(err)
				}
				opts.inspect = func() (Installation, error) { return installation, nil }
			}
			build := opts.build
			opts.build = func(ctx context.Context, goPath, stage, version string) error {
				if err := build(ctx, goPath, stage, version); err != nil {
					return err
				}
				switch change {
				case "replace":
					other := installation.ResolvedPath + ".another"
					if err := os.WriteFile(other, []byte("another installation"), 0750); err != nil {
						return err
					}
					return os.Rename(other, installation.ResolvedPath)
				case "edit with preserved metadata":
					info, _ := os.Stat(installation.ResolvedPath)
					if err := os.WriteFile(installation.ResolvedPath, []byte("modified executable"), 0750); err != nil {
						return err
					}
					return os.Chtimes(installation.ResolvedPath, info.ModTime(), info.ModTime())
				case "symlink":
					if err := os.Remove(installation.Executable); err != nil {
						return err
					}
					return os.Symlink(installation.ResolvedPath, installation.Executable)
				}
				return nil
			}
			_, err := run(context.Background(), Request{}, nil, opts)
			if err == nil || !strings.Contains(err.Error(), "changed during upgrade") {
				t.Fatal("change was not detected:", err)
			}
			body, err := os.ReadFile(installation.ResolvedPath)
			if err != nil || string(body) == "verified replacement" {
				t.Fatalf("unexpected replacement: %q %v", body, err)
			}
			requireNoStage(t, installation)
		})
	}
}

func TestBuildEnvironmentUsesNativePlatformAndKeepsNetworkPolicy(t *testing.T) {
	env := buildEnvironment([]string{"GOBIN=/wrong/bin", "GOOS=windows", "GOARCH=386", "GOFLAGS=-race", "GOWORK=/wrong/work", "CGO_ENABLED=1", "GO111MODULE=off", "GOTOOLCHAIN=local", "GOPROXY=https://user:secret@proxy.invalid", "HTTPS_PROXY=https://proxy.invalid", "PATH=/test"}, "/stage")
	got := make(map[string]string)
	for _, pair := range env {
		key, value, _ := strings.Cut(pair, "=")
		if _, exists := got[key]; exists {
			t.Fatal("duplicate environment key", key)
		}
		got[key] = value
	}
	for key, want := range map[string]string{"GOBIN": "/stage", "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "GOFLAGS": "", "GOWORK": "off", "CGO_ENABLED": "0", "GO111MODULE": "on", "GOTOOLCHAIN": "local", "GOPROXY": "https://user:secret@proxy.invalid", "HTTPS_PROXY": "https://proxy.invalid", "PATH": "/test"} {
		if got[key] != want {
			t.Errorf("%s=%q want %q", key, got[key], want)
		}
	}
}

func TestVersionOutputIsBounded(t *testing.T) {
	w := &boundedOutput{limit: 5}
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Fatal("output exceeded limit")
	}
}
