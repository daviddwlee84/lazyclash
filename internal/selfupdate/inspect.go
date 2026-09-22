package selfupdate

import (
	"debug/buildinfo"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
)

// Inspect always inspects the running process, never a command found on PATH or
// a binary selected using the current GOBIN/GOPATH environment.
func Inspect() (Installation, error) {
	executable, err := os.Executable()
	if err != nil {
		return Installation{}, fmt.Errorf("locate running executable: %w", err)
	}
	installation, err := InspectPath(executable)
	if err == nil && installation.Method == "release-asset" && ReleaseStamp != "archive-v1:"+installation.Version {
		return Installation{}, fmt.Errorf("running archive provenance does not match build metadata")
	}
	return installation, err
}

// InspectPath also verifies a staged candidate before it replaces the original.
// Unrecognized build metadata is a reportable unsupported installation, not an
// inspection error. Filesystem failures do prevent inspection.
func InspectPath(executable string) (Installation, error) {
	path, err := filepath.Abs(executable)
	if err != nil {
		return Installation{}, fmt.Errorf("resolve executable path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return Installation{}, fmt.Errorf("resolve executable symlinks: %w", err)
	}
	file, err := os.Open(resolved)
	if err != nil {
		return Installation{}, fmt.Errorf("inspect executable: %w", err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return Installation{}, fmt.Errorf("inspect executable: %w", err)
	}
	if !stat.Mode().IsRegular() {
		return Installation{}, fmt.Errorf("executable is not a regular file: %s", resolved)
	}
	info, readErr := buildinfo.Read(file)
	after, err := file.Stat()
	if err != nil || !sameInspectedFile(stat, after) {
		return Installation{}, fmt.Errorf("executable changed during build metadata inspection")
	}
	named, err := os.Stat(resolved)
	if err != nil || !sameInspectedFile(stat, named) {
		return Installation{}, fmt.Errorf("executable changed during build metadata inspection")
	}
	installation := classifyBuild(path, resolved, info)
	installation.fileInfo = stat
	if readErr != nil {
		installation.Reason = "executable has no readable Go build metadata; cannot verify lazyclash identity"
	}
	if manager, evidence := ownedByManager(resolved, managerEnvironment()); manager != "" {
		installation.Manager = manager
		installation.Method = "package-manager"
		installation.Evidence = append(installation.Evidence, evidence)
		installation.Reason = managerInstruction(manager)
	}
	return installation, nil
}

func sameInspectedFile(before, after os.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) &&
		before.Size() == after.Size() && before.Mode() == after.Mode() &&
		before.ModTime().Equal(after.ModTime())
}

func classifyBuild(executable, resolved string, info *debug.BuildInfo) Installation {
	installation := Installation{
		Executable: executable, ResolvedPath: resolved, Version: "dev",
		BuildKind: "unknown", Method: "unsupported", Evidence: []string{},
		Reason: "executable has no readable Go build metadata; cannot verify lazyclash identity",
	}
	if info == nil {
		return installation
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "GOOS":
			installation.GOOS = setting.Value
		case "GOARCH":
			installation.GOARCH = setting.Value
		}
	}
	if version := strings.TrimSpace(info.Main.Version); version != "" && version != "(devel)" {
		installation.Version = version
	}
	installation.Evidence = append(installation.Evidence,
		"Go main package: "+info.Path,
		"Go main module: "+info.Main.Path,
		"Go module version: "+info.Main.Version,
	)
	if info.Path != PackagePath || info.Main.Path != ModulePath {
		installation.Reason = "Go build metadata does not identify the lazyclash main package and module"
		return installation
	}
	if info.Main.Replace != nil {
		installation.Reason = "main module is replaced; cannot verify its source identity"
		installation.Evidence = append(installation.Evidence, "Go main module replacement is present")
		return installation
	}
	installation.IdentityValid = true
	installation.Method = "go-install"
	development := !StableVersion(info.Main.Version)
	if !validModuleSum(info.Main.Sum) {
		development = true
		installation.Evidence = append(installation.Evidence, "No versioned main-module checksum")
	} else {
		installation.Evidence = append(installation.Evidence, "Versioned main-module checksum is present")
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs" || strings.HasPrefix(setting.Key, "vcs.") {
			development = true
			installation.Evidence = append(installation.Evidence, "Local VCS build metadata is present")
			break
		}
	}
	for _, dependency := range info.Deps {
		if dependency != nil && dependency.Replace != nil {
			development = true
			installation.Evidence = append(installation.Evidence, "Go dependency replacement is present")
			break
		}
	}
	if version := archiveVersion(info); version != "" {
		installation.Version = version
		installation.Method = "release-asset"
		development = false
		installation.Evidence = append(installation.Evidence, "Archive release provenance is present")
	}
	if development {
		installation.BuildKind = "development"
		installation.Reason = "development build is preserved; use --force to replace it with the latest stable release"
	} else {
		installation.BuildKind = "release"
		installation.Reason = ""
	}
	return installation
}

func validModuleSum(sum string) bool {
	if !strings.HasPrefix(sum, "h1:") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sum, "h1:"))
	return err == nil && len(decoded) == 32
}

type managerEnv struct {
	HomebrewCellar  string
	MiseDataDir     string
	MiseInstallsDir string
	XDGDataHome     string
	Home            string
}

func managerEnvironment() managerEnv {
	home, _ := os.UserHomeDir()
	return managerEnv{
		HomebrewCellar:  os.Getenv("HOMEBREW_CELLAR"),
		MiseDataDir:     os.Getenv("MISE_DATA_DIR"),
		MiseInstallsDir: os.Getenv("MISE_INSTALLS_DIR"),
		XDGDataHome:     os.Getenv("XDG_DATA_HOME"),
		Home:            home,
	}
}

func ownedByManager(path string, env managerEnv) (string, string) {
	if parts := relativeParts(path, "/nix/store"); len(parts) >= 2 {
		return "nix", "Executable is inside the Nix store"
	}
	cellars := []string{env.HomebrewCellar, "/opt/homebrew/Cellar", "/usr/local/Cellar", "/home/linuxbrew/.linuxbrew/Cellar"}
	for _, cellar := range cellars {
		if parts := relativeParts(path, resolveRoot(cellar)); len(parts) >= 3 {
			return "homebrew", "Executable is inside a Homebrew Cellar keg"
		}
	}
	// A custom prefix can be recognized by the actual keg receipt. Merely
	// containing a directory named "homebrew" or "Cellar" is insufficient.
	for dir := filepath.Dir(path); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if filepath.Base(filepath.Dir(filepath.Dir(dir))) != "Cellar" {
			continue
		}
		if receipt, err := os.Stat(filepath.Join(dir, "INSTALL_RECEIPT.json")); err == nil && receipt.Mode().IsRegular() {
			return "homebrew", "Homebrew keg INSTALL_RECEIPT.json is present"
		}
	}
	miseRoots := []string{env.MiseInstallsDir, joinAbsolute(env.MiseDataDir, "installs")}
	if env.XDGDataHome != "" {
		miseRoots = append(miseRoots, joinAbsolute(env.XDGDataHome, "mise", "installs"))
	}
	miseRoots = append(miseRoots, joinAbsolute(env.Home, ".local", "share", "mise", "installs"))
	for _, root := range miseRoots {
		if parts := relativeParts(path, resolveRoot(root)); len(parts) >= 3 {
			return "mise", "Executable is inside a mise tool installation"
		}
	}
	return "", ""
}

func managerInstruction(manager string) string {
	switch manager {
	case "homebrew":
		return "Homebrew owns this executable; upgrade uses brew upgrade for its installed formula"
	case "mise":
		return "mise owns this executable; update its registered tool with mise upgrade"
	case "nix":
		return "Nix owns this executable; update it through the Nix profile or configuration that installed it"
	default:
		return "update this executable through its package manager"
	}
}

func relativeParts(path, root string) []string {
	if root == "" || !filepath.IsAbs(root) {
		return nil
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil
	}
	return strings.Split(relative, string(filepath.Separator))
}

func resolveRoot(root string) string {
	if root == "" || !filepath.IsAbs(root) {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		return resolved
	}
	return filepath.Clean(root)
}

func joinAbsolute(root string, parts ...string) string {
	if root == "" || !filepath.IsAbs(root) {
		return ""
	}
	return filepath.Join(append([]string{root}, parts...)...)
}
