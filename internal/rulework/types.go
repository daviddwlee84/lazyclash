// Package rulework prepares and records changes to explicitly bound rule owners.
package rulework

import (
	"context"
	"io"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

type Options struct {
	ReadOnly bool
	StateDir string
	Open     func(context.Context, config.Target, bool) (*core.Client, io.Closer, error)
	// Validate is a narrow injection point for isolated fixtures. Production
	// leaves it nil to enforce host sandboxing and exact core-version matching.
	Validate func(context.Context, config.Target, []byte, string) error
}

type Source struct {
	Kind       string   `json:"kind"`
	File       string   `json:"file"`
	ProfileUID string   `json:"profile_uid,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
	guards     []fileGuard
	file       hostFile
}

type Plan struct {
	TargetID            string `json:"target_id"`
	Owner               Source `json:"owner"`
	Domain              string `json:"domain"`
	Policy              string `json:"policy"`
	Rule                string `json:"rule"`
	Digest              string `json:"digest"`
	Diff                string `json:"diff"`
	NoChange            bool   `json:"no_change"`
	CoreVersion         string `json:"core_version"`
	after               []byte
	beforeRuntimeDigest string
}

type Receipt struct {
	ID                  string    `json:"id"`
	TargetID            string    `json:"target_id"`
	Owner               string    `json:"owner"`
	File                string    `json:"file"`
	Rule                string    `json:"rule"`
	Domain              string    `json:"domain"`
	Policy              string    `json:"policy"`
	Status              string    `json:"status"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	Digest              string    `json:"digest"`
	BeforeSHA256        string    `json:"before_sha256"`
	AfterSHA256         string    `json:"after_sha256"`
	AfterFingerprint    string    `json:"after_fingerprint,omitempty"`
	RestoredFingerprint string    `json:"restored_fingerprint,omitempty"`
	RuntimeVerified     bool      `json:"runtime_verified"`
	Message             string    `json:"message,omitempty"`
	Binding             string    `json:"binding"`
	ProfileUID          string    `json:"profile_uid,omitempty"`
	BeforeRuntimeDigest string    `json:"before_runtime_digest"`
	Restored            bool      `json:"restored,omitempty"`
}

type hostFile struct {
	Path        string `json:"path"`
	Resolved    string `json:"resolved"`
	Data        []byte `json:"data"`
	Fingerprint string `json:"fingerprint"`
	SHA256      string `json:"sha256"`
	Mode        uint32 `json:"mode"`
}
type fileGuard struct {
	Path        string `json:"path"`
	Fingerprint string `json:"fingerprint"`
}
