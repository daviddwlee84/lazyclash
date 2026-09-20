package configwork

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/core"
)

func definitionDiff(before, after []Definition) []FieldChange {
	old, next := map[string]Definition{}, map[string]Definition{}
	for _, d := range before {
		old[d.Kind+"/"+d.Name] = d
	}
	for _, d := range after {
		next[d.Kind+"/"+d.Name] = d
	}
	ids := map[string]bool{}
	for k := range old {
		ids[k] = true
	}
	for k := range next {
		ids[k] = true
	}
	sorted := make([]string, 0, len(ids))
	for k := range ids {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	var out []FieldChange
	for _, kind := range []string{"proxy", "group"} {
		var a, b []string
		for _, d := range before {
			if d.Kind == kind {
				a = append(a, d.Name)
			}
		}
		for _, d := range after {
			if d.Kind == kind {
				b = append(b, d.Name)
			}
		}
		av, _ := json.Marshal(a)
		bv, _ := json.Marshal(b)
		if string(av) != string(bv) {
			out = append(out, FieldChange{Kind: kind, Name: "(source order)", Field: "order", Operation: "changed", Before: a, After: b})
		}
	}
	for _, id := range sorted {
		a, oldOK := old[id]
		b, newOK := next[id]
		name, kind := b.Name, b.Kind
		if !newOK {
			name, kind = a.Name, a.Kind
		}
		av, bv := a.Map(), b.Map()
		keys := map[string]bool{}
		for k := range av {
			keys[k] = true
		}
		for k := range bv {
			keys[k] = true
		}
		fields := make([]string, 0, len(keys))
		for k := range keys {
			fields = append(fields, k)
		}
		sort.Strings(fields)
		for _, key := range fields {
			va, pa := av[key]
			vb, pb := bv[key]
			aa, _ := json.Marshal(va)
			bb, _ := json.Marshal(vb)
			if oldOK && newOK && pa == pb && string(aa) == string(bb) {
				continue
			}
			op := "changed"
			if !pa {
				op = "added"
			} else if !pb {
				op = "removed"
			}
			shownA, maskA := displayField(key, va)
			shownB, maskB := displayField(key, vb)
			if !pa {
				shownA = nil
			}
			if !pb {
				shownB = nil
			}
			out = append(out, FieldChange{Kind: kind, Name: name, Field: core.Sanitize(key), Operation: op, Before: shownA, After: shownB, Masked: maskA || maskB})
		}
	}
	return out
}
func displayField(key string, value any) (any, bool) {
	if value == nil {
		return nil, false
	}
	switch key {
	case "name", "type", "server", "port", "cipher", "alterId", "network", "tls", "udp", "tfo", "mptcp", "servername", "sni", "alpn", "client-fingerprint", "flow", "skip-cert-verify", "proxies", "use", "filter", "exclude-filter", "exclude-type", "interval", "timeout", "tolerance", "lazy", "strategy", "hidden", "include-all", "include-all-providers", "include-all-proxies":
		return value, false
	case "url":
		text, ok := value.(string)
		if !ok {
			return "[redacted]", true
		}
		parsed, e := url.Parse(text)
		if e != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
			return "[redacted]", true
		}
		masked := parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != ""
		shown := parsed.Scheme + "://" + parsed.Host
		if parsed.Path != "" {
			shown += "/[path]"
		}
		if parsed.RawQuery != "" {
			shown += "?[redacted]"
		}
		return shown, masked
	default:
		return "[redacted]", true
	}
}
func diffText(changes []FieldChange) string {
	var out strings.Builder
	for _, change := range changes {
		a, b := "(absent)", "(absent)"
		if change.Before != nil {
			raw, _ := json.Marshal(change.Before)
			a = string(raw)
		}
		if change.After != nil {
			raw, _ := json.Marshal(change.After)
			b = string(raw)
		}
		fmt.Fprintf(&out, "%s %s · %s [%s]\n  %s → %s\n", change.Kind, core.Sanitize(change.Name), core.Sanitize(change.Field), change.Operation, a, b)
	}
	return out.String()
}
