package config

import (
	"bytes"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

// The application owns a small set of string fields. Patch just their values;
// array-table blocks move with their comments and unknown fields when reordered.
// Nonstandard inline-array layouts are deliberately not rewritten destructively.
type expression struct {
	kind                        unstable.Kind
	key, table                  string
	start, valueStart, valueEnd int
	value                       string
}
type edit struct {
	start, end  int
	replacement []byte
}
type block struct {
	start, end int
	id         string
	data       []byte
}

func expressions(raw []byte) ([]expression, error) {
	var parser unstable.Parser
	parser.Reset(raw)
	var out []expression
	table := ""
	for parser.NextExpression() {
		n := parser.Expression()
		if n.Kind != unstable.Table && n.Kind != unstable.ArrayTable && n.Kind != unstable.KeyValue {
			continue
		}
		var keys []string
		start := len(raw)
		it := n.Key()
		for it.Next() {
			k := it.Node()
			part := string(k.Data)
			// A quoted literal dot must not be mistaken for a nested table.
			if strings.Contains(part, ".") {
				part = "\x00" + part
			}
			keys = append(keys, part)
			if int(k.Raw.Offset) < start {
				start = int(k.Raw.Offset)
			}
		}
		key := strings.Join(keys, ".")
		for start > 0 && raw[start-1] != '\n' {
			start--
		}
		e := expression{kind: n.Kind, key: key, table: table, start: start}
		if n.Kind == unstable.Table || n.Kind == unstable.ArrayTable {
			table = key
			e.table = table
		} else {
			v := n.Value()
			rawRange := v.Raw
			// The pinned parser exposes booleans via Data rather than Raw.
			if v.Kind == unstable.Bool {
				rawRange = parser.Range(v.Data)
			}
			e.valueStart, e.valueEnd, e.value = int(rawRange.Offset), int(rawRange.Offset+rawRange.Length), string(v.Data)
		}
		out = append(out, e)
	}
	return out, parser.Error()
}

func applyEdits(raw []byte, edits []edit) []byte {
	sort.SliceStable(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	out := append([]byte(nil), raw...)
	for _, e := range edits {
		next := make([]byte, 0, len(out)+len(e.replacement)-(e.end-e.start))
		next = append(next, out[:e.start]...)
		next = append(next, e.replacement...)
		next = append(next, out[e.end:]...)
		out = next
	}
	return out
}

func quote(value string) []byte {
	encoded, _ := toml.Marshal(map[string]string{"v": value})
	return bytes.TrimSpace(bytes.SplitN(encoded, []byte("="), 2)[1])
}

func patchFields(raw []byte, scope string, fields []field) ([]byte, error) {
	exprs, err := expressions(raw)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	wanted := map[string]string{}
	for _, f := range fields {
		wanted[f.key] = f.value
	}
	var edits []edit
	insertAt := len(raw)
	for _, e := range exprs {
		if e.kind == unstable.Table || e.kind == unstable.ArrayTable {
			if e.key != scope && e.start < insertAt {
				insertAt = e.start
			}
			continue
		}
		if e.table != scope {
			continue
		}
		value, ok := wanted[e.key]
		if !ok {
			continue
		}
		if e.valueEnd <= e.valueStart {
			return nil, errors.New("cannot preserve this TOML field layout; edit configuration manually")
		}
		seen[e.key] = true
		if e.value != value {
			edits = append(edits, edit{e.valueStart, e.valueEnd, quote(value)})
		}
	}
	var additions strings.Builder
	for _, f := range fields {
		if !seen[f.key] && f.value != "" {
			additions.WriteString(f.key + " = " + string(quote(f.value)) + "\n")
		}
	}
	if additions.Len() > 0 {
		text := additions.String()
		if insertAt > 0 && raw[insertAt-1] != '\n' {
			text = "\n" + text
		}
		edits = append(edits, edit{insertAt, insertAt, []byte(text)})
	}
	return applyEdits(raw, edits), nil
}

type field struct{ key, value string }

func arrayBlocks(raw []byte, scope string) ([]block, error) {
	exprs, err := expressions(raw)
	if err != nil {
		return nil, err
	}
	var blocks []block
	active := -1
	for _, e := range exprs {
		isHeader := e.kind == unstable.ArrayTable || e.kind == unstable.Table
		if isHeader && active >= 0 && (e.key == scope || !strings.HasPrefix(e.key, scope+".")) {
			blocks[active].end = e.start
			active = -1
		}
		if e.kind == unstable.ArrayTable && e.key == scope {
			blocks = append(blocks, block{start: e.start, end: len(raw)})
			active = len(blocks) - 1
		}
		if active >= 0 && e.kind == unstable.KeyValue && e.table == scope && e.key == "id" {
			blocks[active].id = e.value
		}
	}
	for i := range blocks {
		blocks[i].data = raw[blocks[i].start:blocks[i].end]
	}
	return blocks, nil
}

func replaceBlocks(raw []byte, old []block, replacements [][]byte) []byte {
	var joined []byte
	for _, b := range replacements {
		if len(joined) > 0 && joined[len(joined)-1] != '\n' {
			joined = append(joined, '\n')
		}
		joined = append(joined, b...)
		if len(joined) > 0 && joined[len(joined)-1] != '\n' {
			joined = append(joined, '\n')
		}
	}
	if len(old) == 0 {
		out := append([]byte(nil), raw...)
		if len(out) > 0 && out[len(out)-1] != '\n' {
			out = append(out, '\n')
		}
		return append(out, joined...)
	}
	edits := []edit{{old[0].start, old[0].end, joined}}
	for _, b := range old[1:] {
		edits = append(edits, edit{b.start, b.end, nil})
	}
	return applyEdits(raw, edits)
}

func preserve(raw []byte, cfg Config) ([]byte, error) {
	exprs, err := expressions(raw)
	if err != nil {
		return nil, errors.New("cannot parse existing TOML for editing")
	}
	for _, e := range exprs {
		if e.kind == unstable.KeyValue && e.table == "" && e.key == "targets" {
			return nil, errors.New("inline targets arrays cannot be edited while preserving comments; use [[targets]] tables or edit manually")
		}
	}
	raw, err = patchFields(raw, "", []field{{"default_target", cfg.DefaultTarget}})
	if err != nil {
		return nil, err
	}
	raw, err = patchPreferences(raw, cfg.TUI)
	if err != nil {
		return nil, err
	}
	old, err := arrayBlocks(raw, "targets")
	if err != nil {
		return nil, err
	}
	byID := map[string][]byte{}
	for _, b := range old {
		byID[b.id] = b.data
	}
	var out [][]byte
	for _, t := range cfg.Targets {
		b := byID[t.ID]
		if b == nil {
			b = []byte("\n[[targets]]\n")
		}
		b, err = patchFields(b, "targets", []field{
			{"id", t.ID}, {"name", t.Name}, {"controller", t.Controller}, {"secret_file", t.SecretFile},
			{"secret_env", t.SecretEnv}, {"ca_file", t.CAFile}, {"ssh_host", t.SSHHost}, {"source_config", t.SourceConfig},
			{"probe_proxy", t.ProbeProxy}, {"probe_username", t.ProbeUsername}, {"probe_password_env", t.ProbePasswordEnv},
			{"probe_password_file", t.ProbePasswordFile}, {"probe_ca_file", t.ProbeCAFile},
		})
		if err != nil {
			return nil, err
		}
		bs, err := arrayBlocks(b, "targets.configs")
		if err != nil {
			return nil, err
		}
		configsByID := map[string][]byte{}
		for _, c := range bs {
			configsByID[c.id] = c.data
		}
		var configs [][]byte
		for _, c := range t.Configs {
			cb := configsByID[c.ID]
			if cb == nil {
				cb = []byte("\n[[targets.configs]]\n")
			}
			cb, err = patchFields(cb, "targets.configs", []field{{"id", c.ID}, {"name", c.Name}, {"path", c.Path}})
			if err != nil {
				return nil, err
			}
			configs = append(configs, cb)
		}
		b = replaceBlocks(b, bs, configs)
		out = append(out, b)
	}
	return replaceBlocks(raw, old, out), nil
}

func patchPreferences(raw []byte, p TUIPreferences) ([]byte, error) {
	var current Config
	if err := toml.Unmarshal(raw, &current); err != nil {
		return nil, err
	}
	if reflect.DeepEqual(current.TUI, p) {
		return raw, nil
	}
	exprs, err := expressions(raw)
	if err != nil {
		return nil, err
	}
	start, end := -1, len(raw)
	for _, e := range exprs {
		if e.kind == unstable.KeyValue && e.table == "" && (e.key == "tui" || strings.HasPrefix(e.key, "tui.")) {
			return nil, errors.New("inline or dotted tui preferences cannot be edited while preserving comments; use a [tui] table or edit manually")
		}
		if e.kind == unstable.Table && e.key == "tui" {
			start = e.start
			continue
		}
		if start >= 0 && (e.kind == unstable.Table || e.kind == unstable.ArrayTable) && e.start > start {
			end = e.start
			break
		}
	}
	var b []byte
	if start < 0 {
		start, end = len(raw), len(raw)
		b = []byte("\n[tui]\n")
	} else {
		b = raw[start:end]
	}
	b, err = patchFields(b, "tui", []field{{"start_page", p.StartPage}, {"graph_style", p.GraphStyle}, {"history_window", p.HistoryWindow}})
	if err != nil {
		return nil, err
	}
	exprs, err = expressions(b)
	if err != nil {
		return nil, err
	}
	seen := false
	for _, e := range exprs {
		if e.kind != unstable.KeyValue || e.table != "tui" || e.key != "mouse" {
			continue
		}
		seen = true
		if p.Mouse != nil {
			b = applyEdits(b, []edit{{e.valueStart, e.valueEnd, []byte(strconv.FormatBool(*p.Mouse))}})
		} else {
			// Resetting to the default removes only the owned assignment.
			b = applyEdits(b, []edit{{e.start, e.valueEnd, nil}})
		}
		break
	}
	if !seen && p.Mouse != nil {
		if len(b) > 0 && b[len(b)-1] != '\n' {
			b = append(b, '\n')
		}
		b = append(b, []byte("mouse = "+strconv.FormatBool(*p.Mouse)+"\n")...)
	}
	return applyEdits(raw, []edit{{start, end, b}}), nil
}
