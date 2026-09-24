package configwork

import "errors"

var ErrConfigUnavailable = errors.New("configuration source is unavailable")

type ResourceChange struct {
	Provider     string `json:"provider"`
	Section      string `json:"section"`
	Path         string `json:"path"`
	CorePath     string `json:"core_path"`
	SHA256       string `json:"sha256"`
	Bytes        int    `json:"bytes"`
	Mutable      bool   `json:"mutable"`
	Created      bool   `json:"created,omitempty"`
	Status       string `json:"status,omitempty"`
	data         []byte
	root         string
	sourceObject ConfigObject
	sourceSHA256 string
}
type ChangeSetPlan struct {
	TargetID       string                `json:"target_id"`
	SourceTargetID string                `json:"source_target_id"`
	Digest         string                `json:"digest"`
	Status         string                `json:"status"`
	Owner          string                `json:"owner"`
	Composition    StructuralComposition `json:"composition"`
	Changes        []Change              `json:"changes"`
	Resources      []ResourceChange      `json:"resources"`
	Warnings       []string              `json:"warnings,omitempty"`
	source         *source
	version        string
	effective      []byte
	ruleBinding    string
}
type ChangeSetRecord struct {
	Version          int               `json:"version"`
	RuleBinding      string            `json:"rule_binding,omitempty"`
	Resources        []ResourceChange  `json:"resources,omitempty"`
	ExpectedSections map[string]string `json:"expected_sections"`
	SourceTargetID   string            `json:"source_target_id"`
}
type ChangeSetReceipt = Receipt
