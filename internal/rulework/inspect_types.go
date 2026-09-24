package rulework

import "github.com/daviddwlee84/lazyclash/internal/rulecheck"

// RuleTargetInfo describes evidence, without embedding complete configurations
// or repeating every rule in query and comparison results.
type RuleTargetInfo struct {
	TargetID      string   `json:"target_id"`
	ObservedAt    string   `json:"observed_at"`
	Version       string   `json:"version,omitempty"`
	Mode          string   `json:"mode,omitempty"`
	SourceBinding string   `json:"source_binding,omitempty"`
	Owner         *Source  `json:"owner,omitempty"`
	Limitations   []string `json:"limitations,omitempty"`
}

type RuleDiffReport struct {
	Status   string           `json:"status"`
	Scope    string           `json:"scope"`
	Complete bool             `json:"complete"`
	Baseline RuleTargetInfo   `json:"baseline"`
	Targets  []TargetRuleDiff `json:"targets"`
}
type TargetRuleDiff struct {
	Target  RuleTargetInfo `json:"target"`
	Source  *RuleLayerDiff `json:"source,omitempty"`
	Runtime *RuleLayerDiff `json:"runtime,omitempty"`
}
type RuleLayerDiff struct {
	Status      string                `json:"status"`
	LeftShape   string                `json:"left_shape,omitempty"`
	RightShape  string                `json:"right_shape,omitempty"`
	Message     string                `json:"message,omitempty"`
	Result      *rulecheck.DiffReport `json:"result,omitempty"`
	Limitations []string              `json:"limitations,omitempty"`
}

type RuleFindReport struct {
	Status   string           `json:"status"`
	Scope    string           `json:"scope"`
	Complete bool             `json:"complete"`
	Query    string           `json:"query"`
	Targets  []TargetRuleFind `json:"targets"`
}
type TargetRuleFind struct {
	Target  RuleTargetInfo `json:"target"`
	Source  *RuleLayerFind `json:"source,omitempty"`
	Runtime *RuleLayerFind `json:"runtime,omitempty"`
}
type RuleLayerFind struct {
	Status      string                `json:"status"`
	Shape       string                `json:"shape,omitempty"`
	Message     string                `json:"message,omitempty"`
	Result      *rulecheck.FindReport `json:"result,omitempty"`
	Limitations []string              `json:"limitations,omitempty"`
}

type RuleLookupReport struct {
	Status   string                `json:"status"`
	Scope    string                `json:"scope"`
	Complete bool                  `json:"complete"`
	Input    rulecheck.LookupInput `json:"input"`
	Targets  []TargetRuleLookup    `json:"targets"`
}
type TargetRuleLookup struct {
	Target  RuleTargetInfo   `json:"target"`
	Source  *RuleLayerLookup `json:"source,omitempty"`
	Runtime *RuleLayerLookup `json:"runtime,omitempty"`
}
type RuleLayerLookup struct {
	Status      string                  `json:"status"`
	Shape       string                  `json:"shape,omitempty"`
	Message     string                  `json:"message,omitempty"`
	Result      *rulecheck.LookupReport `json:"result,omitempty"`
	Limitations []string                `json:"limitations,omitempty"`
}
