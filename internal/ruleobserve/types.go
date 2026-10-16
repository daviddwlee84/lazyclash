// Package ruleobserve summarizes observed controller logs. Its counters describe
// log observations, never distinct failed requests or complete network coverage.
package ruleobserve

import "time"

const (
	MaxGroups        = 5000
	MaxVariants      = 64
	MaxSamples       = 3
	MaxGapDetails    = 128
	KindDialError    = "dial_error"
	KindDialSuccess  = "dial_success"
	KindOtherWarning = "other_warning"
)

// Event contains only parsed metadata and a fixed, safe error description.
// Raw log payloads and arbitrary error strings are deliberately absent.
type Event struct {
	At          time.Time `json:"at"`
	Kind        string    `json:"kind"`
	Level       string    `json:"level"`
	Host        string    `json:"host,omitempty"`
	IsIP        bool      `json:"is_ip,omitempty"`
	Network     string    `json:"network,omitempty"`
	Port        int       `json:"port,omitempty"`
	Process     string    `json:"process,omitempty"`
	Rule        string    `json:"rule,omitempty"`
	RulePayload string    `json:"rule_payload,omitempty"`
	Policy      string    `json:"policy,omitempty"`
	ErrorKind   string    `json:"error_kind,omitempty"`
	Summary     string    `json:"summary"`
}

// Evidence is an alias for callers presenting an individual observation.
type Evidence = Event

type Variant struct {
	Kind        string    `json:"kind"`
	Network     string    `json:"network,omitempty"`
	Port        int       `json:"port,omitempty"`
	Process     string    `json:"process,omitempty"`
	Rule        string    `json:"rule,omitempty"`
	RulePayload string    `json:"rule_payload,omitempty"`
	Policy      string    `json:"policy,omitempty"`
	ErrorKind   string    `json:"error_kind,omitempty"`
	Count       int64     `json:"count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Samples     []string  `json:"samples"`
}

type Group struct {
	Key             string    `json:"key"`
	Host            string    `json:"host,omitempty"`
	IsIP            bool      `json:"is_ip,omitempty"`
	Count           int64     `json:"count"`
	ErrorCount      int64     `json:"error_count"`
	SuccessCount    int64     `json:"success_count"`
	OtherCount      int64     `json:"other_count"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	Variants        []Variant `json:"variants"`
	DroppedVariants int64     `json:"dropped_variants,omitempty"`
}

type Gap struct {
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
}

type Snapshot struct {
	Version           int       `json:"version"`
	ID                string    `json:"id"`
	TargetID          string    `json:"target_id"`
	TargetIdentity    string    `json:"target_identity,omitempty"`
	Mode              string    `json:"mode"`
	Status            string    `json:"status"`
	FallbackPolicy    string    `json:"fallback_policy,omitempty"`
	PreviousSelection string    `json:"previous_selection,omitempty"`
	GuardID           string    `json:"guard_id,omitempty"`
	StartedAt         time.Time `json:"started_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	FinishedAt        time.Time `json:"finished_at,omitempty"`
	Groups            []Group   `json:"groups"`
	Observed          int64     `json:"observed"`
	Dropped           int64     `json:"dropped"`
	Unparsed          int64     `json:"unparsed"`
	Gaps              int64     `json:"gaps"`
	GapDetails        []Gap     `json:"gap_details"`
}
