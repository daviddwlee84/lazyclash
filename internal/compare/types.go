// Package compare compares observed runtime state and copies an explicitly
// selected subset between registered targets. It never edits saved settings.
package compare

import (
	"context"
	"errors"
	"io"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

var ErrStale = errors.New("copy preview is stale; preview again before applying")

type ValidationError struct{ Message string }

func (e *ValidationError) Error() string { return e.Message }

type Options struct {
	Open     func(context.Context, config.Target, bool) (*core.Client, io.Closer, error)
	ReadOnly bool
}

type TargetRef struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Controller string `json:"controller"`
	SSHHost    string `json:"ssh_host,omitempty"`
}

type Group struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Members  []string `json:"members"`
	Selected string   `json:"selected,omitempty"`
}

type Snapshot struct {
	Target         TargetRef   `json:"target"`
	Version        string      `json:"version"`
	General        core.Object `json:"general"`
	Groups         []Group     `json:"groups"`
	RedactedFields []string    `json:"redacted_fields"`
}

// Path is a JSON pointer rooted at the general runtime settings object.
// Presence distinguishes a missing field from a reported null or zero value.
type FieldDiff struct {
	Path               string `json:"path"`
	Source             any    `json:"source"`
	Destination        any    `json:"destination"`
	SourcePresent      bool   `json:"source_present"`
	DestinationPresent bool   `json:"destination_present"`
}

type GroupDiff struct {
	Name        string   `json:"name"`
	Source      *Group   `json:"source"`
	Destination *Group   `json:"destination"`
	Differences []string `json:"differences"`
}

type DiffResult struct {
	Source      Snapshot    `json:"source"`
	Destination Snapshot    `json:"destination"`
	Fields      []FieldDiff `json:"fields"`
	Groups      []GroupDiff `json:"groups"`
	NotCompared []string    `json:"not_compared"`
	// Equality covers compared state only; opaque fields remain NotCompared.
	Equal bool `json:"equal_compared_state"`
}

type Selection struct {
	Fields []string `json:"fields"`
	Groups []string `json:"groups"`
}

type Step struct {
	Kind               string   `json:"kind"`
	Name               string   `json:"name"`
	Before             string   `json:"before"`
	After              string   `json:"after"`
	Changed            bool     `json:"changed"`
	DestinationMembers []string `json:"destination_members,omitempty"`
}

type Plan struct {
	Source             TargetRef `json:"source"`
	Destination        TargetRef `json:"destination"`
	Selection          Selection `json:"selection"`
	Digest             string    `json:"digest"`
	Steps              []Step    `json:"steps"`
	SourceVersion      string    `json:"source_version"`
	DestinationVersion string    `json:"destination_version"`
}

type StepResult struct {
	Step
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type ApplyResult struct {
	Plan   Plan         `json:"plan"`
	Status string       `json:"status"`
	Steps  []StepResult `json:"steps"`
}
