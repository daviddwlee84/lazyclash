// Package diagnostics provides explicit target connectivity and data-plane
// probes shared by the command line and terminal UI.
package diagnostics

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

var ErrReadOnly = errors.New("active diagnostics are disabled in read-only mode")
var ErrNoProxy = errors.New("configure this target's probe_proxy before running active diagnostics")
var ErrPartial = errors.New("one or more website probes failed; inspect the per-site results")

// Options supplies policy and narrow injection points for deterministic tests.
// Normal callers only need ReadOnly and, if applicable, their shared Open hook.
type Options struct {
	ReadOnly       bool
	Open           func(context.Context, config.Target, bool) (*core.Client, io.Closer, error)
	OpenTunnel     func(context.Context, string, string) (string, io.Closer, error)
	IPURL          string
	Sites          []Site
	IPTimeout      time.Duration
	LatencyTimeout time.Duration
	Now            func() time.Time
}

type TestResult struct {
	TargetID        string    `json:"target_id"`
	Route           string    `json:"route"`
	SampledAt       time.Time `json:"sampled_at"`
	Connected       bool      `json:"connected"`
	Version         string    `json:"version,omitempty"`
	ConfigsReadable bool      `json:"configs_readable"`
	Milliseconds    float64   `json:"milliseconds"`
}

type IPResult struct {
	TargetID     string    `json:"target_id"`
	Route        string    `json:"route"`
	SampledAt    time.Time `json:"sampled_at"`
	Source       string    `json:"source"`
	IP           string    `json:"ip,omitempty"`
	Country      string    `json:"country"`
	City         string    `json:"city"`
	Organization string    `json:"organization"`
	ASN          string    `json:"asn"`
}

type Site struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type SiteResult struct {
	Name         string  `json:"name"`
	URL          string  `json:"url"`
	Milliseconds float64 `json:"milliseconds"`
	StatusCode   int     `json:"status_code,omitempty"`
	Error        string  `json:"error,omitempty"`
}

type LatencyResult struct {
	TargetID  string       `json:"target_id"`
	Route     string       `json:"route"`
	SampledAt time.Time    `json:"sampled_at"`
	Sites     []SiteResult `json:"sites"`
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func route(t config.Target, endpoint string) string {
	if t.SSHHost != "" {
		return endpoint + " via SSH " + t.SSHHost
	}
	return endpoint
}
