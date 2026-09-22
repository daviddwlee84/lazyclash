package config

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

func patchDiagnosticChecks(raw []byte, checks []DiagnosticCheck) ([]byte, error) {
	var current Config
	if err := toml.Unmarshal(raw, &current); err != nil {
		return nil, err
	}
	if len(current.Targets) == 1 && (reflect.DeepEqual(current.Targets[0].Checks, checks) || len(current.Targets[0].Checks) == 0 && len(checks) == 0) {
		return raw, nil
	}
	exprs, err := expressions(raw)
	if err != nil {
		return nil, err
	}
	for _, e := range exprs {
		if e.kind == unstable.KeyValue && e.table == "targets" && (e.key == "checks" || strings.HasPrefix(e.key, "checks.")) {
			return nil, errors.New("inline or dotted diagnostic checks cannot be edited while preserving comments; use [[targets.checks]] tables or edit manually")
		}
	}
	old, err := arrayBlocks(raw, "targets.checks")
	if err != nil {
		return nil, err
	}
	byID := map[string][]byte{}
	for _, b := range old {
		byID[b.id] = b.data
	}
	var updated [][]byte
	for _, check := range checks {
		b := byID[check.ID]
		if b == nil {
			b = []byte("\n[[targets.checks]]\n")
		}
		b, err = patchFields(b, "targets.checks", []field{{"id", check.ID}, {"name", check.Name}, {"url", check.URL}, {"via", check.Via}})
		if err != nil {
			return nil, err
		}
		b, err = patchDiagnosticStatuses(b, check.ExpectedStatuses)
		if err != nil {
			return nil, err
		}
		updated = append(updated, b)
	}
	return replaceBlocks(raw, old, updated), nil
}

// The TOML parser does not provide a Raw range for array values. This scanner
// operates only on an already-parsed integer array and preserves its comments
// and whitespace while replacing integers and their separators.
func diagnosticStatusArray(raw []byte, expressionStart int) (int, int, []edit, []int, error) {
	fail := errors.New("cannot preserve diagnostic expected_statuses; edit the configuration manually")
	equals := bytes.IndexByte(raw[expressionStart:], '=')
	if equals < 0 {
		return 0, 0, nil, nil, fail
	}
	start := expressionStart + equals + 1
	for start < len(raw) && (raw[start] == ' ' || raw[start] == '\t') {
		start++
	}
	if start >= len(raw) || raw[start] != '[' {
		return 0, 0, nil, nil, fail
	}
	var integers []edit
	var commas []int
	for pos := start + 1; pos < len(raw); {
		switch raw[pos] {
		case ' ', '\t', '\r', '\n':
			pos++
		case '#':
			for pos < len(raw) && raw[pos] != '\n' {
				pos++
			}
		case ',':
			commas = append(commas, pos)
			pos++
		case ']':
			return start, pos + 1, integers, commas, nil
		default:
			begin := pos
			for pos < len(raw) && !bytes.ContainsRune([]byte(" \t\r\n,#]"), rune(raw[pos])) {
				pos++
			}
			if begin == pos {
				return 0, 0, nil, nil, fail
			}
			integers = append(integers, edit{start: begin, end: pos})
		}
	}
	return 0, 0, nil, nil, fail
}

func patchDiagnosticStatuses(raw []byte, statuses []int) ([]byte, error) {
	exprs, err := expressions(raw)
	if err != nil {
		return nil, err
	}
	insertAt := len(raw)
	for _, e := range exprs {
		if e.kind == unstable.Table || e.kind == unstable.ArrayTable {
			if e.key != "targets.checks" && e.start < insertAt {
				insertAt = e.start
			}
			continue
		}
		if e.table != "targets.checks" || e.key != "expected_statuses" {
			continue
		}
		start, end, integers, commas, err := diagnosticStatusArray(raw, e.start)
		if err != nil {
			return nil, err
		}
		var decoded struct {
			Value []int `toml:"value"`
		}
		if err := toml.Unmarshal(append([]byte("value = "), raw[start:end]...), &decoded); err != nil || len(integers) != len(decoded.Value) {
			return nil, errors.New("cannot preserve diagnostic expected_statuses; edit the configuration manually")
		}
		if slices.Equal(decoded.Value, statuses) {
			return raw, nil
		}
		var edits []edit
		for i, integer := range integers {
			if i < len(statuses) {
				if decoded.Value[i] == statuses[i] {
					continue
				}
				integer.replacement = []byte(strconv.Itoa(statuses[i]))
			}
			edits = append(edits, integer)
		}
		for i, comma := range commas {
			if i >= len(statuses) {
				edits = append(edits, edit{start: comma, end: comma + 1})
			}
		}
		if len(statuses) > len(integers) {
			var additions []string
			for _, status := range statuses[len(integers):] {
				additions = append(additions, strconv.Itoa(status))
			}
			text := strings.Join(additions, ", ")
			if len(integers) > 0 && len(commas) < len(integers) {
				text = ", " + text
			}
			edits = append(edits, edit{start: end - 1, end: end - 1, replacement: []byte(text)})
		}
		return applyEdits(raw, edits), nil
	}
	if len(statuses) == 0 {
		return raw, nil
	}
	var values []string
	for _, status := range statuses {
		values = append(values, strconv.Itoa(status))
	}
	text := "expected_statuses = [" + strings.Join(values, ", ") + "]\n"
	if insertAt > 0 && raw[insertAt-1] != '\n' {
		text = "\n" + text
	}
	return applyEdits(raw, []edit{{start: insertAt, end: insertAt, replacement: []byte(text)}}), nil
}
