// Package analyticsservice manages an opt-in, user-owned analytics collector.
// It does not install packages, elevate privileges, or change network settings.
package analyticsservice

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/connection"
)

//go:embed host.py
var hostScript string

// Request paths refer to the selected host. An SSH installation requires an
// explicit executable already present on that host; local binaries are never
// uploaded. Mutations require Apply and the Digest from a fresh preview.
type Request struct {
	Action     string `json:"action"`
	SSHHost    string `json:"-"`
	Executable string `json:"executable,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`
	StateDir   string `json:"state_dir"`
	Apply      bool   `json:"apply,omitempty"`
	Expect     string `json:"expect,omitempty"`
}

type Options struct {
	Execute  func(context.Context, string, string, []byte, int) ([]byte, error)
	ReadOnly bool
}

type Result struct {
	Action           string   `json:"action"`
	Platform         string   `json:"platform"`
	Manager          string   `json:"manager"`
	Service          string   `json:"service"`
	Available        bool     `json:"available"`
	Installed        bool     `json:"installed"`
	Loaded           bool     `json:"loaded"`
	Enabled          bool     `json:"enabled"`
	Running          bool     `json:"running"`
	SessionDependent bool     `json:"session_dependent"`
	Owned            bool     `json:"owned"`
	Drifted          bool     `json:"drifted"`
	Preview          bool     `json:"preview"`
	Digest           string   `json:"digest,omitempty"`
	Changed          bool     `json:"changed"`
	StateDir         string   `json:"state_dir"`
	ConfigPath       string   `json:"config_path,omitempty"`
	Executable       string   `json:"executable,omitempty"`
	UnitPath         string   `json:"unit_path"`
	Details          []string `json:"details"`
	Error            string   `json:"error,omitempty"`
}

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Run returns an inspection or preview by default. Install does not start the
// collector. Remove unregisters only owned artifacts and preserves all data and
// the caller's configuration. Start and stop also support reviewed previews.
func Run(ctx context.Context, r Request, o Options) (Result, error) {
	switch r.Action {
	case "status", "install", "start", "stop", "remove":
	default:
		return Result{}, errors.New("analytics service action must be status, install, start, stop, or remove")
	}
	if r.StateDir == "" || !filepath.IsAbs(r.StateDir) {
		return Result{}, errors.New("analytics service state directory must be absolute on the selected host")
	}
	for _, path := range []string{r.StateDir, r.ConfigPath, r.Executable} {
		if path != "" && !filepath.IsAbs(path) {
			return Result{}, errors.New("analytics service paths must be absolute on the selected host")
		}
	}
	if r.Apply && (o.ReadOnly || r.Action == "status") {
		return Result{}, errors.New("analytics service mutation is not allowed in read-only/status mode")
	}
	if r.Apply && !digestPattern.MatchString(r.Expect) {
		return Result{}, errors.New("analytics service apply requires the reviewed --expect digest")
	}
	if !r.Apply && r.Expect != "" {
		return Result{}, errors.New("analytics service --expect requires apply")
	}
	if r.Action == "install" {
		if r.ConfigPath == "" {
			return Result{}, errors.New("analytics service install requires an absolute collector config path")
		}
		if r.Executable == "" {
			if r.SSHHost != "" {
				return Result{}, errors.New("remote analytics service install requires an absolute executable already installed on that host")
			}
			var err error
			r.Executable, err = os.Executable()
			if err != nil {
				return Result{}, err
			}
			r.Executable, err = filepath.EvalSymlinks(r.Executable)
			if err != nil {
				return Result{}, err
			}
		}
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return Result{}, err
	}
	execute := o.Execute
	if execute == nil {
		execute = connection.ExecutePython
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	out, err := execute(ctx, r.SSHHost, hostScript, raw, 1<<20)
	if err != nil {
		return Result{}, err
	}
	var result Result
	if json.Unmarshal(out, &result) != nil {
		return result, errors.New("invalid analytics service helper response")
	}
	if result.Error != "" {
		return result, errors.New(result.Error)
	}
	return result, nil
}
