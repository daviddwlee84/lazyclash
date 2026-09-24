package rulework

import "github.com/daviddwlee84/lazyclash/internal/rulecheck"

// QuickPlan is a snapshot of every selected saved target, including skips.
// Its digest guards both the candidate and the reviewed destination set.
type QuickPlan struct {
	Rule    string            `json:"rule"`
	Digest  string            `json:"digest"`
	Status  string            `json:"status"`
	Targets []QuickTargetPlan `json:"targets"`
}

type QuickTargetPlan struct {
	TargetID        string              `json:"target_id"`
	Status          string              `json:"status"`
	Message         string              `json:"message,omitempty"`
	Digest          string              `json:"digest,omitempty"`
	Diff            string              `json:"diff,omitempty"`
	Owner           *Source             `json:"owner,omitempty"`
	Findings        []rulecheck.Finding `json:"findings"`
	Limitations     []string            `json:"limitations,omitempty"`
	RuntimeVerified bool                `json:"runtime_verified"`
	plan            Plan
	cause           error
}

func (p QuickPlan) HasChanges() bool {
	for _, t := range p.Targets {
		if t.Status == "ready" {
			return true
		}
	}
	return false
}

type QuickResult struct {
	Rule    string              `json:"rule"`
	Digest  string              `json:"digest"`
	Status  string              `json:"status"`
	Results []QuickTargetResult `json:"results"`
}

type QuickTargetResult struct {
	TargetID        string              `json:"target_id"`
	Status          string              `json:"status"`
	Message         string              `json:"message,omitempty"`
	Findings        []rulecheck.Finding `json:"findings"`
	Receipt         *Receipt            `json:"receipt,omitempty"`
	RuntimeVerified bool                `json:"runtime_verified"`
}

type HealthReport struct {
	Status  string         `json:"status"`
	Targets []TargetHealth `json:"targets"`
}

type TargetHealth struct {
	TargetID    string              `json:"target_id"`
	Status      string              `json:"status"`
	Message     string              `json:"message,omitempty"`
	ObservedAt  string              `json:"observed_at"`
	Owner       *Source             `json:"owner,omitempty"`
	Mode        string              `json:"mode,omitempty"`
	Providers   int                 `json:"providers"`
	Source      *rulecheck.Report   `json:"source,omitempty"`
	Runtime     *rulecheck.Report   `json:"runtime,omitempty"`
	Findings    []rulecheck.Finding `json:"findings"`
	Limitations []string            `json:"limitations,omitempty"`
}
