package ruleobserve

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
)

// Parse recognizes Mihomo's TCP/UDP dial error and matched-success grammar.
// Other warnings remain visible, but cannot produce a guessed destination.
// Errors are classified using the original text, then replaced with fixed
// descriptions: arbitrary error text can contain credentials, URLs or queries.
func Parse(record core.Object, at time.Time) (Event, bool) {
	level, _ := record["type"].(string)
	level = strings.ToLower(level)
	if level == "warn" {
		level = "warning"
	}
	if level != "info" && level != "warning" && level != "error" {
		return Event{}, false
	}
	unknown := Event{At: at, Kind: KindOtherWarning, Level: level, ErrorKind: "unparsed", Summary: errorSummary("unparsed")}
	payload, _ := record["payload"].(string)
	if len(payload) > 64<<10 {
		return unknown, level != "info"
	}
	network, body, ok := strings.Cut(payload, "] ")
	if !ok || network != "[TCP" && network != "[UDP" {
		return unknown, level != "info"
	}
	e := Event{At: at, Level: level, Network: network[1:]}
	left, right, ok := strings.Cut(body, " --> ")
	if !ok {
		return unknown, level != "info"
	}
	var destination, source string
	if level == "info" {
		var route string
		destination, route, ok = strings.Cut(right, " match ")
		if !ok {
			return Event{}, false
		}
		var matched, chain string
		matched, chain, ok = strings.Cut(route, " using ")
		if !ok || strings.Contains(chain, "\n") {
			return Event{}, false
		}
		e.Rule, e.RulePayload, ok = successRule(matched)
		if !ok {
			return Event{}, false
		}
		// Chains are rendered as outer-policy[leaf]. The policy is evidence
		// about this observation, not a claim that its current leaf is DIRECT.
		e.Policy, _, _ = strings.Cut(chain, "[")
		e.Policy = metadataText(e.Policy)
		if e.Policy == "" {
			return Event{}, false
		}
		source = left
		e.Kind, e.Summary = KindDialSuccess, "Outbound dial succeeded; application success is unknown."
	} else {
		if !strings.HasPrefix(left, "dial ") {
			return unknown, true
		}
		var detail string
		destination, detail, ok = strings.Cut(right, " error: ")
		if !ok {
			return unknown, true
		}
		left = strings.TrimPrefix(left, "dial ")
		if policy, match, found := strings.Cut(left, " (match "); found {
			var rule string
			rule, source, ok = strings.Cut(match, ") ")
			if !ok {
				return unknown, true
			}
			e.Rule, e.RulePayload, ok = strings.Cut(rule, "/")
			if !ok || !validRuleType(e.Rule) {
				return unknown, true
			}
			e.Policy = metadataText(policy)
			e.RulePayload = metadataText(e.RulePayload)
		} else {
			// Without a rule, locate the final source tuple instead of
			// splitting on the policy's spaces. INNER flows use "mihomo".
			cut := sourceStart(left)
			if cut < 0 {
				return unknown, true
			}
			e.Policy, source = metadataText(left[:cut]), left[cut+1:]
		}
		if e.Policy == "" {
			return unknown, true
		}
		e.Kind, e.ErrorKind = KindDialError, classifyError(detail)
		e.Summary = errorSummary(e.ErrorKind)
	}
	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		return unknown, level != "info"
	}
	e.Host, e.IsIP, err = normalizeHost(host)
	if err != nil {
		return unknown, level != "info"
	}
	e.Port, err = strconv.Atoi(port)
	if err != nil || e.Port < 1 || e.Port > 65535 {
		return unknown, level != "info"
	}
	if !validSource(source) {
		return unknown, level != "info"
	}
	if _, rest, found := strings.Cut(source, "("); found && strings.HasSuffix(rest, ")") {
		process := strings.TrimSuffix(rest, ")")
		process, _, _ = strings.Cut(process, ", uid=")
		if !strings.HasPrefix(process, "uid=") {
			e.Process = metadataText(process)
		}
	}
	return e, true
}

func sourceStart(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ' ' && validSource(s[i+1:]) {
			return i
		}
	}
	return -1
}

func validSource(s string) bool {
	if strings.EqualFold(s, "mihomo") || strings.EqualFold(s, "clash") {
		return true
	}
	address, extra, _ := strings.Cut(s, "(")
	if extra != "" && (!strings.HasSuffix(extra, ")") || strings.ContainsAny(extra, "\r\n")) {
		return false
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if _, err = netip.ParseAddr(host); err != nil {
		return false
	}
	p, err := strconv.Atoi(port)
	return err == nil && p >= 0 && p <= 65535
}

func successRule(s string) (string, string, bool) {
	kind, payload, found := strings.Cut(s, "(")
	if !validRuleType(kind) {
		return "", "", false
	}
	if !found {
		return kind, "", true
	}
	if !strings.HasSuffix(payload, ")") {
		return "", "", false
	}
	return kind, metadataText(strings.TrimSuffix(payload, ")")), true
}

func validRuleType(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func metadataText(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 256 || strings.IndexFunc(s, unicode.IsControl) >= 0 || core.Sanitize(s) != s {
		return ""
	}
	return s
}

func normalizeHost(s string) (string, bool, error) {
	if ip, err := netip.ParseAddr(s); err == nil && ip.Zone() == "" {
		return ip.Unmap().String(), true, nil
	}
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if s == "" || len(s) > 253 {
		return "", false, errors.New("invalid destination hostname")
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false, errors.New("invalid destination hostname")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", false, errors.New("invalid destination hostname")
			}
		}
	}
	return s, false, nil
}

func classifyError(s string) string {
	s = strings.ToLower(s)
	switch {
	case strings.Contains(s, "no such host"), strings.Contains(s, "dns"), strings.Contains(s, "resolve"), strings.Contains(s, "ip not found"):
		return "dns"
	case strings.Contains(s, "timeout"), strings.Contains(s, "timed out"), strings.Contains(s, "deadline exceeded"):
		return "timeout"
	case strings.Contains(s, "refused"):
		return "refused"
	case strings.Contains(s, "reset by peer"):
		return "reset"
	case strings.Contains(s, "network is unreachable"), strings.Contains(s, "no route to host"), strings.Contains(s, "host is unreachable"):
		return "unreachable"
	case strings.Contains(s, "tls"), strings.Contains(s, "x509"), strings.Contains(s, "certificate"):
		return "tls"
	case strings.Contains(s, "reject"):
		return "rejected"
	case strings.Contains(s, "cancel"):
		return "canceled"
	case strings.Contains(s, "eof"):
		return "eof"
	default:
		return "other"
	}
}

func errorSummary(kind string) string {
	switch kind {
	case "dns":
		return "Name resolution failed during outbound dial."
	case "timeout":
		return "Outbound dial timed out."
	case "refused":
		return "Outbound connection was refused."
	case "reset":
		return "Outbound connection was reset."
	case "unreachable":
		return "Outbound destination or network was unreachable."
	case "tls":
		return "Outbound TLS or certificate negotiation failed."
	case "rejected":
		return "Outbound connection was rejected."
	case "canceled":
		return "Outbound dial was canceled."
	case "eof":
		return "Outbound connection closed during dial."
	case "unparsed":
		return "Unrecognized warning or error; raw payload omitted."
	default:
		return "Outbound dial failed; raw error omitted."
	}
}

// Candidate builds a user-selected override. It does not infer that the
// destination needs this policy, or widen an observed host automatically.
func Candidate(host, policy string, suffix bool) (string, error) {
	host, ip, err := normalizeHost(host)
	if err != nil {
		return "", err
	}
	if policy == "" || metadataText(policy) != policy || strings.ContainsAny(policy, ",\r\n") {
		return "", errors.New("an explicit valid policy is required")
	}
	kind, payload, ending := "DOMAIN", host, ""
	if ip {
		if suffix {
			return "", errors.New("suffix rules require a hostname")
		}
		addr, _ := netip.ParseAddr(host)
		kind, payload, ending = "IP-CIDR", netip.PrefixFrom(addr, addr.BitLen()).String(), ",no-resolve"
		if addr.Is6() {
			kind = "IP-CIDR6"
		}
	} else if suffix {
		kind = "DOMAIN-SUFFIX"
	}
	rule, err := rulecheck.Parse(kind + "," + payload + "," + policy + ending)
	if err != nil {
		return "", err
	}
	return rule.String(), nil
}
