package serverstate

import (
	"bytes"
	"errors"
	"reflect"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

type expression struct {
	kind              unstable.Kind
	key, table, value string
	start, from, to   int
}
type edit struct {
	from, to int
	data     []byte
}
type block struct {
	from, to     int
	id           string
	resourceKind string
	data         []byte
}

func expressions(raw []byte) ([]expression, error) {
	var p unstable.Parser
	p.Reset(raw)
	table := ""
	var out []expression
	for p.NextExpression() {
		n := p.Expression()
		if n.Kind != unstable.Table && n.Kind != unstable.ArrayTable && n.Kind != unstable.KeyValue {
			continue
		}
		var keys []string
		start := len(raw)
		it := n.Key()
		for it.Next() {
			k := it.Node()
			part := string(k.Data)
			if strings.Contains(part, ".") {
				part = "\x00" + part
			}
			keys = append(keys, part)
			if int(k.Raw.Offset) < start {
				start = int(k.Raw.Offset)
			}
		}
		for start > 0 && raw[start-1] != '\n' {
			start--
		}
		e := expression{kind: n.Kind, key: strings.Join(keys, "."), table: table, start: start}
		if n.Kind == unstable.Table || n.Kind == unstable.ArrayTable {
			table = e.key
			e.table = table
		} else {
			v := n.Value()
			r := v.Raw
			if r.Length == 0 && v.Kind == unstable.Array {
				from, to, err := arrayValueRange(raw, start)
				if err != nil {
					return nil, err
				}
				e.from, e.to = from, to
				out = append(out, e)
				continue
			}
			if r.Length == 0 && len(v.Data) > 0 {
				r = p.Range(v.Data)
			}
			e.from = int(r.Offset)
			e.to = int(r.Offset + r.Length)
			e.value = string(v.Data)
		}
		out = append(out, e)
	}
	return out, p.Error()
}

func applyEdits(raw []byte, edits []edit) []byte {
	sort.SliceStable(edits, func(i, j int) bool { return edits[i].from > edits[j].from })
	out := append([]byte(nil), raw...)
	for _, e := range edits {
		next := append([]byte(nil), out[:e.from]...)
		next = append(next, e.data...)
		next = append(next, out[e.to:]...)
		out = next
	}
	return out
}

func blocks(raw []byte, scope string) ([]block, error) {
	exprs, err := expressions(raw)
	if err != nil {
		return nil, err
	}
	var out []block
	active := -1
	for _, e := range exprs {
		header := e.kind == unstable.Table || e.kind == unstable.ArrayTable
		if header && active >= 0 && (e.key == scope || !strings.HasPrefix(e.key, scope+".")) {
			out[active].to = e.start
			active = -1
		}
		if e.kind == unstable.ArrayTable && e.key == scope {
			out = append(out, block{from: e.start, to: len(raw)})
			active = len(out) - 1
		}
		if active >= 0 && e.kind == unstable.KeyValue && e.table == scope && e.key == "id" {
			out[active].id = e.value
		}
		if active >= 0 && e.kind == unstable.KeyValue && e.table == scope && e.key == "kind" {
			out[active].resourceKind = e.value
		}
		if e.kind == unstable.KeyValue && e.table == "" && e.key == scope {
			return nil, errors.New("server inventory uses an inline table array; use [[hosts]] / [[deployments]] tables to preserve edits")
		}
	}
	for i := range out {
		out[i].data = raw[out[i].from:out[i].to]
	}
	return out, nil
}

func fields(v any) map[string]any {
	r := reflect.ValueOf(v)
	t := r.Type()
	out := map[string]any{}
	for i := 0; i < t.NumField(); i++ {
		name := strings.Split(t.Field(i).Tag.Get("toml"), ",")[0]
		if name == "" || name == "-" || name == "resources" {
			continue
		}
		out[name] = r.Field(i).Interface()
	}
	return out
}

func scalar(v any) ([]byte, error) {
	data, err := toml.Marshal(map[string]any{"v": v})
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(bytes.SplitN(data, []byte("="), 2)[1]), nil
}

func patchFields(raw []byte, scope string, wanted map[string]any) ([]byte, error) {
	exprs, err := expressions(raw)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	insert := len(raw)
	var edits []edit
	for _, e := range exprs {
		if e.kind == unstable.Table || e.kind == unstable.ArrayTable {
			if e.key != scope && e.start < insert {
				insert = e.start
			}
			continue
		}
		if e.table != scope {
			continue
		}
		v, ok := wanted[e.key]
		if !ok {
			continue
		}
		seen[e.key] = true
		if e.to <= e.from {
			return nil, errors.New("cannot preserve this TOML value; edit server inventory manually")
		}
		encoded, err := scalar(v)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(raw[e.from:e.to], encoded) {
			edits = append(edits, edit{e.from, e.to, encoded})
		}
	}
	var keys []string
	for k := range wanted {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var add bytes.Buffer
	for _, k := range keys {
		encoded, err := scalar(wanted[k])
		if err != nil {
			return nil, err
		}
		add.WriteString(k + " = ")
		add.Write(encoded)
		add.WriteByte('\n')
	}
	if add.Len() > 0 {
		data := add.Bytes()
		if insert > 0 && raw[insert-1] != '\n' {
			data = append([]byte{'\n'}, data...)
		}
		edits = append(edits, edit{insert, insert, data})
	}
	return applyEdits(raw, edits), nil
}

func reconcile(raw []byte, scope string, values any) ([]byte, error) {
	old, err := blocks(raw, scope)
	if err != nil {
		return nil, err
	}
	byID := map[string]block{}
	for _, b := range old {
		byID[preservationKey(scope, b.id, b.resourceKind)] = b
	}
	r := reflect.ValueOf(values)
	var joined []byte
	for n := 0; n < r.Len(); n++ {
		v := r.Index(n).Interface()
		f := fields(v)
		id, _ := f["id"].(string)
		kind, _ := f["kind"].(string)
		b, ok := byID[preservationKey(scope, id, kind)]
		var data []byte
		if ok {
			data = b.data
		} else {
			data = []byte("[[" + scope + "]]\n")
		}
		data, err = patchFields(data, scope, f)
		if err != nil {
			return nil, err
		}
		if h, ok := v.(Host); ok {
			data, err = reconcile(data, scope+".resources", h.Resources)
			if err != nil {
				return nil, err
			}
		}
		joined = append(joined, data...)
		if len(joined) > 0 && joined[len(joined)-1] != '\n' {
			joined = append(joined, '\n')
		}
	}
	if len(old) == 0 {
		if len(joined) == 0 {
			return raw, nil
		}
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			raw = append(raw, '\n')
		}
		return append(raw, joined...), nil
	}
	edits := []edit{{old[0].from, old[0].to, joined}}
	for _, b := range old[1:] {
		edits = append(edits, edit{b.from, b.to, nil})
	}
	return applyEdits(raw, edits), nil
}

func preservationKey(scope, id, kind string) string {
	if strings.HasSuffix(scope, ".resources") {
		return kind + "\x00" + id
	}
	return id
}

func preserve(raw []byte, inv Inventory) ([]byte, error) {
	out, err := patchFields(raw, "", map[string]any{"version": inv.Version})
	if err != nil {
		return nil, err
	}
	out, err = reconcile(out, "hosts", inv.Hosts)
	if err != nil {
		return nil, err
	}
	out, err = reconcile(out, "deployments", inv.Deployments)
	if err != nil {
		return nil, err
	}
	out, err = reconcile(out, "tailnet", inv.TailnetNodes)
	if err != nil {
		return nil, err
	}
	out, err = reconcile(out, "tailnet_proxies", inv.TailnetProxies)
	if err != nil {
		return nil, err
	}
	if _, err = decode(out); err != nil {
		return nil, err
	}
	return out, nil
}

// The TOML parser does not expose a Raw range for arrays. Scan delimiters
// without interpreting string content, including TOML multiline strings and
// quote runs at their closing delimiters. Unknown fields retain their bytes.
func arrayValueRange(raw []byte, start int) (int, int, error) {
	at := start
	for at < len(raw) {
		switch raw[at] {
		case '\'', '"':
			next, err := tomlStringEnd(raw, at)
			if err != nil {
				return 0, 0, err
			}
			at = next
			continue
		case '=':
			at++
			for at < len(raw) && (raw[at] == ' ' || raw[at] == '\t' || raw[at] == '\n' || raw[at] == '\r') {
				at++
			}
			if at >= len(raw) || raw[at] != '[' {
				return 0, 0, errors.New("cannot locate TOML array value")
			}
			from, depth := at, 0
			for at < len(raw) {
				switch raw[at] {
				case '\'', '"':
					next, err := tomlStringEnd(raw, at)
					if err != nil {
						return 0, 0, err
					}
					at = next
					continue
				case '#':
					for at < len(raw) && raw[at] != '\n' {
						at++
					}
					continue
				case '[':
					depth++
				case ']':
					depth--
					if depth == 0 {
						return from, at + 1, nil
					}
				}
				at++
			}
			return 0, 0, errors.New("unterminated TOML array value")
		}
		at++
	}
	return 0, 0, errors.New("cannot locate TOML array value")
}

func tomlStringEnd(raw []byte, start int) (int, error) {
	quote := raw[start]
	multiline := start+2 < len(raw) && raw[start+1] == quote && raw[start+2] == quote
	at := start + 1
	if multiline {
		at = start + 3
	}
	for at < len(raw) {
		if quote == '"' && raw[at] == '\\' {
			at += 2
			continue
		}
		if raw[at] == quote {
			if !multiline {
				return at + 1, nil
			}
			end := at
			for end < len(raw) && raw[end] == quote {
				end++
			}
			// Three close a multiline string. A valid four/five-quote run also
			// contains one/two literal trailing quotes; all belong to this value.
			if end-at >= 3 {
				return end, nil
			}
			at = end
			continue
		}
		at++
	}
	return 0, errors.New("unterminated TOML string")
}
