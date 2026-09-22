// Package analytics stores explicitly collected observations. Sources are never
// combined: client counters, server events and host interface bytes have different scopes.
package analytics

import (
	"encoding/json"
	"time"
)

const DefaultTimezone = "Asia/Shanghai"

type Paths struct {
	Config   string `json:"config"`
	Database string `json:"database"`
}
type RetentionConfig struct {
	DetailDays int `toml:"detail_days" json:"detail_days"`
	MinuteDays int `toml:"minute_days" json:"minute_days"`
	DayMonths  int `toml:"day_months" json:"day_months"`
}
type SourceConfig struct {
	ID          string `toml:"id" json:"id"`
	Kind        string `toml:"kind" json:"kind"`
	Scope       string `toml:"scope,omitempty" json:"scope,omitempty"`
	Timezone    string `toml:"timezone,omitempty" json:"timezone,omitempty"`
	Enabled     bool   `toml:"enabled" json:"enabled"`
	Target      string `toml:"target,omitempty" json:"target,omitempty"`
	Interface   string `toml:"interface,omitempty" json:"interface,omitempty"`
	Path        string `toml:"path,omitempty" json:"path,omitempty"`
	Format      string `toml:"format,omitempty" json:"format,omitempty"`
	Binary      string `toml:"binary,omitempty" json:"binary,omitempty"`
	Address     string `toml:"address,omitempty" json:"address,omitempty"`
	ServerID    string `toml:"server_id,omitempty" json:"server_id,omitempty"`
	HostID      string `toml:"host_id,omitempty" json:"host_id,omitempty"`
	PollSeconds int    `toml:"poll_seconds,omitempty" json:"poll_seconds,omitempty"`
}
type AlertConfig struct {
	Enabled      bool     `toml:"enabled" json:"enabled"`
	SourceIDs    []string `toml:"source_ids,omitempty" json:"source_ids,omitempty"`
	ThresholdGiB []int64  `toml:"threshold_gib,omitempty" json:"threshold_gib,omitempty"`
	Timezone     string   `toml:"timezone,omitempty" json:"timezone,omitempty"`
	WebhookFile  string   `toml:"webhook_file,omitempty" json:"webhook_file,omitempty"`
	WebhookEnv   string   `toml:"webhook_env,omitempty" json:"webhook_env,omitempty"`
}
type Config struct {
	Version      int             `toml:"version" json:"version"`
	Timezone     string          `toml:"timezone" json:"timezone"`
	SettingsPath string          `toml:"settings_path,omitempty" json:"settings_path,omitempty"`
	Sources      []SourceConfig  `toml:"sources" json:"sources"`
	Retention    RetentionConfig `toml:"retention" json:"retention"`
	MaxBytes     int64           `toml:"max_bytes" json:"max_bytes"`
	Alerts       AlertConfig     `toml:"alerts" json:"alerts"`
}

type Event struct {
	ID        string    `json:"id"`
	At        time.Time `json:"at"`
	ClientIP  string    `json:"client_ip,omitempty"`
	Domain    string    `json:"domain,omitempty"`
	Process   string    `json:"process,omitempty"`
	Route     string    `json:"route,omitempty"`
	Principal string    `json:"principal,omitempty"`
	Count     int64     `json:"count"`
}
type Delta struct {
	ID            string    `json:"id"`
	Granularity   string    `json:"granularity,omitempty"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
	UploadBytes   int64     `json:"upload_bytes"`
	DownloadBytes int64     `json:"download_bytes"`
	ClientIP      string    `json:"client_ip,omitempty"`
	Domain        string    `json:"domain,omitempty"`
	Process       string    `json:"process,omitempty"`
	Route         string    `json:"route,omitempty"`
	Principal     string    `json:"principal,omitempty"`
}
type Checkpoint struct {
	Key       string          `json:"key"`
	Value     json.RawMessage `json:"value"`
	UpdatedAt time.Time       `json:"updated_at"`
}
type SourceStatus struct {
	Source           *SourceConfig `json:"source,omitempty"`
	SourceID         string        `json:"source_id"`
	Kind             string        `json:"kind"`
	Scope            string        `json:"scope"`
	State            string        `json:"state"`
	Message          string        `json:"message,omitempty"`
	LastAttempt      time.Time     `json:"last_attempt"`
	LastSuccess      time.Time     `json:"last_success"`
	GapCount         int64         `json:"gap_count"`
	ResetCount       int64         `json:"reset_count"`
	DroppedEvents    int64         `json:"dropped_events"`
	RetentionDropped int64         `json:"retention_dropped"`
}
type Batch struct {
	Source                          *SourceConfig
	Binding                         string
	Compact                         bool
	SourceID, Kind, Scope, Timezone string
	At                              time.Time
	Events                          []Event
	Deltas                          []Delta
	Checkpoint                      *Checkpoint
	Status                          *SourceStatus
	// CoverageStart records only a known observed interval, never collector downtime.
	CoverageStart time.Time
}
type Query struct {
	From, To                                                           time.Time
	SourceID, GroupBy, Domain, Process, Route, IP, Principal, Timezone string
	Limit                                                              int
}
type ReportRow struct {
	BytesAvailable         bool      `json:"bytes_available"`
	ConnectionsAvailable   bool      `json:"connections_available"`
	ActiveMinutesAvailable bool      `json:"active_minutes_available"`
	SourceID               string    `json:"source_id"`
	Kind                   string    `json:"kind"`
	Scope                  string    `json:"scope"`
	Key                    string    `json:"key"`
	UploadBytes            int64     `json:"upload_bytes"`
	DownloadBytes          int64     `json:"download_bytes"`
	Connections            int64     `json:"connections"`
	ActiveMinutes          int64     `json:"active_minutes"`
	First                  time.Time `json:"first"`
	Last                   time.Time `json:"last"`
}
type Coverage struct {
	SourceID        string       `json:"source_id"`
	ObservedSeconds float64      `json:"observed_seconds"`
	ExpectedSeconds float64      `json:"expected_seconds"`
	Partial         bool         `json:"partial"`
	Status          SourceStatus `json:"status"`
}
type Report struct {
	From       time.Time   `json:"from"`
	To         time.Time   `json:"to"`
	Timezone   string      `json:"timezone"`
	Resolution string      `json:"resolution"`
	GroupBy    string      `json:"group_by"`
	Rows       []ReportRow `json:"rows"`
	Coverage   []Coverage  `json:"coverage"`
	Warnings   []string    `json:"warnings"`
	Truncated  bool        `json:"truncated"`
}
type Status struct {
	Path          string         `json:"path"`
	SchemaVersion int            `json:"schema_version"`
	Timezone      string         `json:"timezone"`
	Bytes         int64          `json:"bytes"`
	Sources       []SourceStatus `json:"sources"`
	OldestDetail  time.Time      `json:"oldest_detail"`
	OldestMinute  time.Time      `json:"oldest_minute"`
	OldestDay     time.Time      `json:"oldest_day"`
}
type RetentionResult struct {
	DeletedDetails, DeletedMinutes, DeletedDays int64
	Bytes                                       int64
	Pressure                                    bool
}
type Alert struct {
	Attempts      int       `json:"attempts"`
	NextAttempt   time.Time `json:"next_attempt,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	ID            string    `json:"id"`
	SourceID      string    `json:"source_id"`
	Day           string    `json:"day"`
	ThresholdGiB  int64     `json:"threshold_gib"`
	UploadBytes   int64     `json:"upload_bytes"`
	DownloadBytes int64     `json:"download_bytes"`
	CreatedAt     time.Time `json:"created_at"`
	State         string    `json:"state"`
}
