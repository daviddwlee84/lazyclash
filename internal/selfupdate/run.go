package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Run inspects this process's executable and optionally replaces that same
// executable with a verified, pinned stable release. It does not load settings.
func Run(ctx context.Context, req Request, progress io.Writer) (Result, error) {
	return run(ctx, req, progress, runOptions{
		inspect: Inspect, latest: latestRelease, lookPath: exec.LookPath,
		build: buildRelease, inspectCandidate: InspectPath, version: candidateVersion,
	})
}

type runOptions struct {
	inspect          func() (Installation, error)
	latest           func(context.Context) (Release, error)
	lookPath         func(string) (string, error)
	build            func(context.Context, string, string, string) error
	inspectCandidate func(string) (Installation, error)
	version          func(context.Context, string) (string, error)
	download         func(context.Context, Release, string) error
}

func run(ctx context.Context, req Request, progress io.Writer, opts runOptions) (Result, error) {
	var result Result
	if progress == nil {
		progress = io.Discard
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	installation, err := opts.inspect()
	if err != nil {
		return result, fmt.Errorf("inspect current executable: %w", err)
	}
	result.Installation = installation
	result.CurrentVersion = installation.Version
	result.Status = "checked"
	var original installationSnapshot
	if !req.Check && installation.IdentityValid && installation.Manager == "" {
		original, err = snapshotInstallation(installation)
		if err != nil {
			return result, fmt.Errorf("inspect update destination: %w", err)
		}
	}
	release, err := opts.latest(ctx)
	if err != nil {
		return result, err
	}
	if !StableVersion(release.Version) {
		return result, errors.New("latest release is not a stable version")
	}
	result.LatestVersion, result.ReleaseURL = release.Version, release.URL
	if StableVersion(installation.Version) {
		comparison, _ := CompareVersions(release.Version, installation.Version)
		result.UpdateAvailable = comparison > 0
	}
	goPath, reason := upgradePrerequisites(installation, req.Force, opts.lookPath)
	if installation.Method == "release-asset" && reason == "" {
		if _, err := releaseAsset(release, runtime.GOOS, runtime.GOARCH); err != nil {
			reason = err.Error()
		}
	}
	result.CanUpgrade = reason == ""
	result.Reason = reason
	if req.Check {
		return result, nil
	}
	// A no-op does not need a compiler or a writable installation directory.
	// Ownership and development-build policies still take precedence.
	if !req.Force && !result.UpdateAvailable && installation.BuildKind == "release" && upgradePolicy(installation, false) == "" {
		result.Status = "up-to-date"
		return result, nil
	}
	if reason != "" {
		result.Status = "unsupported"
		if installation.BuildKind == "development" && !req.Force {
			result.Status = "development"
		}
		return result, errors.New(reason)
	}
	unlock, err := acquireLock(installation.ResolvedPath)
	if err != nil {
		return result, err
	}
	defer unlock()
	if err := original.validate(); err != nil {
		return result, err
	}
	stage, err := os.MkdirTemp(filepath.Dir(installation.ResolvedPath), "."+filepath.Base(installation.ResolvedPath)+".upgrade-")
	if err != nil {
		return result, fmt.Errorf("create update staging directory (the executable directory must be writable): %w", err)
	}
	defer os.RemoveAll(stage)
	if installation.Method == "release-asset" {
		fmt.Fprintf(progress, "Downloading lazyclash %s…\n", release.Version)
		download := opts.download
		if download == nil {
			download = downloadRelease
		}
		if err := download(ctx, release, stage); err != nil {
			return result, err
		}
	} else {
		fmt.Fprintf(progress, "Building lazyclash %s with Go…\n", release.Version)
		if err = opts.build(ctx, goPath, stage, release.Version); err != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return result, fmt.Errorf("building release: %w", context.DeadlineExceeded)
			}
			if errors.Is(err, context.Canceled) {
				return result, context.Canceled
			}
			// Toolchain errors can contain credential-bearing proxy URLs. Keep raw
			// child output out of both machine results and terminal diagnostics.
			return result, errors.New("go install failed; check the Go toolchain, GOPROXY and network settings (the existing binary was retained)")
		}
	}

	if err := ctx.Err(); err != nil {
		return result, err
	}
	candidate := filepath.Join(stage, "lazyclash")
	candidateFile, err := os.Lstat(candidate)
	if err != nil || !candidateFile.Mode().IsRegular() {
		return result, errors.New("built candidate must be a regular executable file (the existing binary was retained)")
	}
	info, err := opts.inspectCandidate(candidate)
	if err != nil || !info.IdentityValid || info.BuildKind != "release" || info.Version != release.Version || info.GOOS != runtime.GOOS || info.GOARCH != runtime.GOARCH || (installation.Method == "release-asset" && info.Method != "release-asset") {
		return result, errors.New("built candidate did not match the lazyclash package, platform and pinned release (the existing binary was retained)")
	}
	printed, err := opts.version(ctx, candidate)
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return result, fmt.Errorf("candidate version check: %w", context.DeadlineExceeded)
		}
		if errors.Is(err, context.Canceled) {
			return result, context.Canceled
		}
		return result, errors.New("built candidate failed its version check (the existing binary was retained)")
	}
	if strings.TrimSpace(printed) != "lazyclash version "+release.Version {
		return result, errors.New("built candidate reported an unexpected version (the existing binary was retained)")
	}
	file, err := os.OpenFile(candidate, os.O_RDWR, 0)
	if err != nil {
		return result, fmt.Errorf("open built executable: %w", err)
	}
	if err := file.Chmod(original.file.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)); err != nil {
		file.Close()
		return result, fmt.Errorf("preserve executable permissions: %w", err)
	}
	err = file.Sync()
	closeErr := file.Close()
	if err != nil {
		return result, fmt.Errorf("flush built executable: %w", err)
	}
	if closeErr != nil {
		return result, fmt.Errorf("close built executable: %w", closeErr)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := original.validate(); err != nil {
		return result, err
	}
	if err := os.Rename(candidate, installation.ResolvedPath); err != nil {
		return result, fmt.Errorf("replace executable (the existing binary was retained): %w", err)
	}
	result.Status = "updated"
	fmt.Fprintf(progress, "Installed lazyclash %s.\n", release.Version)
	return result, nil
}

func upgradePrerequisites(installation Installation, force bool, lookPath func(string) (string, error)) (string, string) {
	if reason := upgradePolicy(installation, force); reason != "" {
		return "", reason
	}
	var goPath string
	var err error
	if installation.Method == "go-install" {
		goPath, err = lookPath("go")
	}
	if err != nil {
		return "", "Go is required for this installation's upgrade method; install Go from https://go.dev/dl/ and retry"
	}
	if err := writableDirectory(filepath.Dir(installation.ResolvedPath)); err != nil {
		return "", "the executable directory is not writable; use an installation directory owned by your user"
	}
	return goPath, ""
}

func upgradePolicy(installation Installation, force bool) string {
	if installation.Manager != "" || !installation.IdentityValid || (installation.Method != "go-install" && installation.Method != "release-asset") {
		if installation.Reason != "" {
			return installation.Reason
		}
		return "this installation cannot be overwritten safely; use its package manager or reinstall lazyclash with Go"
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return "self-upgrade currently supports macOS and Linux; reinstall lazyclash with Go on this platform"
	}
	if installation.BuildKind == "development" && !force {
		return "this is a development build; use upgrade --force to replace it with the latest stable release"
	}
	return ""
}

func buildRelease(ctx context.Context, goPath, stage, version string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, goPath, "install", PackagePath+"@"+version)
	cmd.Dir = stage
	cmd.Env = buildEnvironment(os.Environ(), stage)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	configureCommand(cmd)
	err := cmd.Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func buildEnvironment(env []string, stage string) []string {
	overrides := []string{
		"GOBIN=" + stage, "GOWORK=off", "GOFLAGS=", "CGO_ENABLED=0",
		"GOOS=" + runtime.GOOS, "GOARCH=" + runtime.GOARCH, "GO111MODULE=on", "GOEXPERIMENT=",
		"GOAMD64=v1", "GOARM64=v8.0",
	}
	keys := make(map[string]bool, len(overrides))
	for _, entry := range overrides {
		key, _, _ := strings.Cut(entry, "=")
		keys[key] = true
	}
	result := make([]string, 0, len(env)+len(overrides))
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if !keys[key] {
			result = append(result, entry)
		}
	}
	return append(result, overrides...)
}

func candidateVersion(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output := &boundedOutput{limit: 4096}
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Stdout, cmd.Stderr = output, io.Discard
	configureCommand(cmd)
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", err
	}
	return output.text.String(), nil
}

type boundedOutput struct {
	text  strings.Builder
	limit int
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > w.limit-w.text.Len() {
		return 0, errors.New("output limit exceeded")
	}
	return w.text.Write(p)
}
