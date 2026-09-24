package rulecheck

import (
	"errors"
	"net/netip"
	"strings"
)

type LookupInput struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type LookupStep struct {
	Entry   Entry  `json:"entry"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason"`
}

type LookupReport struct {
	Status      string       `json:"status"`
	Steps       []LookupStep `json:"steps"`
	Winner      *Entry       `json:"first_candidate,omitempty"`
	Limitations []string     `json:"limitations"`
}

func ParseLookup(raw string) (LookupInput, error) {
	raw = strings.TrimSpace(raw)
	if addr, err := netip.ParseAddr(raw); err == nil {
		if addr.Zone() != "" || addr.Is4In6() {
			return LookupInput{}, errors.New("lookup requires an IP without a zone or mapped address family")
		}
		return LookupInput{Kind: "ip", Value: addr.String()}, nil
	}
	host, err := domain(raw)
	if err != nil {
		return LookupInput{}, errors.New("lookup requires one ASCII hostname or IP address, without a URL, port or CIDR")
	}
	return LookupInput{Kind: "domain", Value: host}, nil
}

// LookupEntries is a hypothetical trace over the supplied ordered snapshot.
// Missing metadata and opaque matchers remain unknown. Callers must further
// qualify incomplete owner composition, especially Verge companion sections.
func LookupEntries(entries []Entry, input LookupInput) LookupReport {
	report := LookupReport{Status: "unmatched", Steps: []LookupStep{}, Limitations: []string{"Static lookup sends no traffic or DNS requests. It does not establish provider contents, process/source metadata, policy behavior or observed routing.", "A candidate is the first supported match in the supplied declarations; groups can select PASS and UDP fallback can continue evaluation, so this is not a verified route."}}
	uncertain, candidateSeen := false, false
	for _, entry := range entries {
		step := LookupStep{Entry: *copyEntry(entry)}
		switch {
		case entry.Section == "delete":
			step.Outcome, step.Reason = "skipped", "Owner delete directive is not an active rule."
		case entry.Rule.Disabled:
			step.Outcome, step.Reason = "skipped", "The runtime rule is disabled."
		default:
			step.Outcome, step.Reason = lookupMatch(entry.Rule, input)
		}
		if step.Outcome == "unknown" && !candidateSeen {
			uncertain = true
		}
		if step.Outcome == "match" && (entry.Rule.Policy == "PASS" || entry.Rule.Policy == "PASS-RULE") {
			step.Outcome, step.Reason = "continued", "The matcher succeeds but the PASS/PASS-RULE action continues evaluation."
		}
		if candidateSeen && step.Outcome != "skipped" {
			step.Reason += " This entry follows the first confirmed candidate and is retained to show coverage."
		}
		report.Steps = append(report.Steps, step)
		if step.Outcome == "match" && !candidateSeen {
			candidateSeen = true
			if uncertain {
				report.Status = "unknown"
				report.Limitations = append(report.Limitations, "An earlier unknown matcher may win before the later confirmed match; no winner is inferred.")
			} else {
				report.Status, report.Winner = "candidate", copyEntry(entry)
			}
		}
	}
	if uncertain && !candidateSeen {
		report.Status = "unknown"
	}
	return report
}

func lookupMatch(rule Rule, input LookupInput) (outcome, reason string) {
	if rule.Invalid != "" || rule.Opaque {
		return "unknown", "This rule's matcher or modifiers are outside the supported static analysis."
	}
	if rule.Type == "MATCH" {
		return "match", "MATCH accepts any destination."
	}
	if rule.SourceIP {
		return "unknown", "The destination lookup does not supply a source IP."
	}
	matched := false
	switch {
	case domainRule(rule):
		if input.Kind != "domain" {
			return "unknown", "An IP alone does not supply the hostname or sniffed domain metadata."
		}
		matched = matchesDomain(rule, input.Value)
	case ipRule(rule):
		if input.Kind != "ip" {
			return "unknown", "A hostname has no known destination IP; static lookup does not resolve DNS."
		}
		prefix, err := netip.ParsePrefix(rule.Payload)
		address, addressErr := netip.ParseAddr(input.Value)
		if err != nil || addressErr != nil {
			return "unknown", "The IP rule or lookup address could not be interpreted."
		}
		matched = prefix.Contains(address)
	default:
		return "unknown", "This rule requires metadata or matcher data not supplied by the lookup."
	}
	if matched {
		return "match", "The supplied destination satisfies this matcher."
	}
	return "miss", "The supplied destination does not satisfy this matcher."
}
