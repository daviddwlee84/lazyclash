// Package clientservice controls only explicitly bound existing client services.
// It never installs, recreates or deletes a core, container or daemon.
package clientservice

import (
	"context"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/sourceowner"
)

type DockerSource = sourceowner.DockerSource

type Options struct {
	ReadOnly bool
	StateDir string
	Host     func(context.Context, config.Target, Request) (Status, error)
}

type Request struct {
	Op               string               `json:"op"`
	Service          config.ClientService `json:"service"`
	Expected         string               `json:"expected,omitempty"`
	DisableAutostart bool                 `json:"disable_autostart,omitempty"`
	SourcePath       string               `json:"source_path,omitempty"`
	SourceContainer  string               `json:"source_container,omitempty"`
	CorePath         string               `json:"core_path,omitempty"`
	SourceSHA256     string               `json:"source_sha256,omitempty"`
}

type Status struct {
	Binding          config.ClientService `json:"binding"`
	Running          bool                 `json:"running"`
	State            string               `json:"state"`
	Autostart        bool                 `json:"autostart"`
	RestartPolicy    string               `json:"restart_policy,omitempty"`
	ComposeSHA256    string               `json:"compose_sha256,omitempty"`
	ComposeRestart   string               `json:"compose_restart,omitempty"`
	ComposeEditable  bool                 `json:"compose_editable,omitempty"`
	StateDigest      string               `json:"state_digest"`
	SourceMatches    bool                 `json:"source_matches,omitempty"`
	SourceSingleFile bool                 `json:"source_single_file,omitempty"`
	BackupPath       string               `json:"backup_path,omitempty"`
	Error            string               `json:"error,omitempty"`
}

type Plan struct {
	TargetID         string   `json:"target_id"`
	Action           string   `json:"action"`
	DisableAutostart bool     `json:"disable_autostart,omitempty"`
	Before           Status   `json:"before"`
	Digest           string   `json:"digest"`
	Changes          []string `json:"changes"`
}

type Receipt struct {
	SourcePath   string    `json:"source_path,omitempty"`
	SourceSHA256 string    `json:"source_sha256,omitempty"`
	ID           string    `json:"id"`
	TargetID     string    `json:"target_id"`
	Action       string    `json:"action"`
	Status       string    `json:"status"`
	Digest       string    `json:"digest"`
	Before       Status    `json:"before"`
	After        *Status   `json:"after,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	Error        string    `json:"error,omitempty"`
}
