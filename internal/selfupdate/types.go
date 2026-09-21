// Package selfupdate checks releases and updates the running executable.
package selfupdate

import "os"

const (
	ModulePath  = "github.com/daviddwlee84/lazyclash"
	PackagePath = ModulePath + "/cmd/lazyclash"
)

// Request is independent of controller and preference configuration.
type Request struct {
	Check bool
	Force bool
}

// Installation describes observable build provenance and path ownership. It
// does not claim to recover which command originally installed an executable.
type Installation struct {
	Executable    string   `json:"executable"`
	ResolvedPath  string   `json:"resolved_path"`
	Version       string   `json:"version"`
	GOOS          string   `json:"goos,omitempty"`
	GOARCH        string   `json:"goarch,omitempty"`
	BuildKind     string   `json:"build_kind"`
	Manager       string   `json:"manager,omitempty"`
	Method        string   `json:"method"`
	Evidence      []string `json:"evidence"`
	Reason        string   `json:"reason,omitempty"`
	IdentityValid bool     `json:"identity_valid"`

	// Binds the build metadata inspection to the file captured by the updater.
	// It is deliberately absent from the public machine-readable result.
	fileInfo os.FileInfo
}

// ReleaseStamp is set only by the reviewed archive release workflow.
var ReleaseStamp string

type Release struct {
	Assets  []string `json:"assets,omitempty"`
	Version string   `json:"version"`
	URL     string   `json:"url"`
}

type Result struct {
	Status          string       `json:"status"`
	Installation    Installation `json:"installation"`
	CurrentVersion  string       `json:"current_version"`
	LatestVersion   string       `json:"latest_version,omitempty"`
	ReleaseURL      string       `json:"release_url,omitempty"`
	UpdateAvailable bool         `json:"update_available"`
	CanUpgrade      bool         `json:"can_upgrade"`
	Reason          string       `json:"reason,omitempty"`
}
