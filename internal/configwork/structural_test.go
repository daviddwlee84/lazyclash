package configwork

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"go.yaml.in/yaml/v3"
)

func structuralFixture(t *testing.T, id, raw string) ConfigSnapshot {
	t.Helper()
	root, err := decode([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	objects, err := structuralObjects(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	target := config.Target{ID: id, ConfigSource: &config.ConfigSource{Kind: "native"}}
	return ConfigSnapshot{TargetID: id, Owner: "native", Shape: "complete-yaml", Complete: true, Objects: objects, Root: root, Target: target, target: target, Digest: typedFingerprint(root)}
}

func structuralObject(t *testing.T, s ConfigSnapshot, id string) ConfigObject {
	t.Helper()
	for _, o := range s.Objects {
		if o.ID == id {
			return o
		}
	}
	t.Fatalf("missing object %s", id)
	return ConfigObject{}
}
func structuralRow(t *testing.T, d ConfigDiff, id string) ObjectDiff {
	t.Helper()
	for _, o := range d.Objects {
		if o.ID == id {
			return o
		}
	}
	t.Fatalf("missing row %s", id)
	return ObjectDiff{}
}
func structuralBlock(c StructuralComposition, code string) bool {
	for _, b := range c.Blockers {
		if b.Code == code {
			return true
		}
	}
	return false
}
func structuralRule(t *testing.T, s ConfigSnapshot, index int) ConfigObject {
	t.Helper()
	for _, o := range s.Objects {
		if o.Kind == "rule" && o.Index == index {
			return o
		}
	}
	t.Fatal("rule not found")
	return ConfigObject{}
}
func structuralRules(root *yaml.Node) []string {
	out := []string{}
	for _, n := range membersContent(get(root, "rules")) {
		out = append(out, n.Value)
	}
	return out
}

const structuralEmpty = "proxies: []\nproxy-groups: []\nrules: [\"MATCH,DIRECT\"]\n"

func TestStructuralTypedComparisonMasksChangedSecretsBeforeRendering(t *testing.T) {
	before := structuralFixture(t, "destination", sourceFixture)
	raw := strings.Replace(sourceFixture, "password: original-secret", "password: private-replacement", 1)
	raw = strings.Replace(raw, "port: 443", "port: '443'", 1)
	raw = strings.Replace(raw, "x-future: {mode: untouched}", "x-future: {mode: changed}\n  hidden: null", 1)
	after := structuralFixture(t, "source", raw)
	diff := CompareConfig(after, before)
	row := structuralRow(t, diff, "/proxies/node1")
	if row.Status != "changed" || !row.ReplacementRequired {
		t.Fatalf("%+v", row)
	}
	fields := map[string]StructuralFieldChange{}
	for _, f := range row.Fields {
		fields[f.Path] = f
	}
	if f := fields["/password"]; !f.Masked || f.Before != "[redacted]" || f.After != "[redacted]" || f.Operation != "changed" {
		t.Fatalf("secret difference lost: %+v", f)
	}
	if f := fields["/port"]; f.BeforeType == f.AfterType || f.BeforeType != "!!int" || f.AfterType != "!!str" {
		t.Fatalf("scalar types collapsed: %+v", f)
	}
	if f := fields["/hidden"]; f.BeforePresent || !f.AfterPresent || f.AfterType != "!!null" || f.Operation != "added" {
		t.Fatalf("absent/null collapsed: %+v", f)
	}
	encoded, _ := json.Marshal(diff)
	for _, secret := range []string{"original-secret", "private-replacement", "never-in-output"} {
		if strings.Contains(string(encoded), secret) || strings.Contains(row.Unified, secret) || strings.Contains(FormatConfigDiff(diff, "tree"), secret) {
			t.Fatalf("credential exposed: %s", secret)
		}
	}
	if !strings.Contains(row.Unified, "values hidden; compared before masking") {
		t.Fatal("masked-only change lacks explicit preview evidence")
	}
	if fields["/x-future/mode"].Before != "[redacted]" {
		t.Fatal("safe-looking nested key inside unknown options was exposed")
	}
}

func TestStructuralFormattingMapOrderAndSchemaOrder(t *testing.T) {
	a := structuralFixture(t, "a", "proxies:\n- {name: node, type: ss, server: host, port: 443, password: private, cipher: aes-128-gcm}\nproxy-groups:\n- {name: G, type: fallback, proxies: [node, DIRECT]}\nrules: [\"MATCH,G\"]\n")
	b := structuralFixture(t, "b", "# comment\nproxies:\n- {cipher: aes-128-gcm, password: private, port: 0x1bb, server: host, type: ss, name: node}\nproxy-groups:\n- {proxies: [node, DIRECT], type: fallback, name: G}\nrules: [\"MATCH,G\"]\n")
	if !CompareConfig(a, b).Equal {
		t.Fatal("formatting or mapping order became a value difference")
	}
	reordered := structuralFixture(t, "c", "proxies:\n- {name: node, type: ss, server: host, port: 443, password: private, cipher: aes-128-gcm}\nproxy-groups:\n- {name: G, type: fallback, proxies: [DIRECT, node]}\nrules: [\"MATCH,G\"]\n")
	if r := structuralRow(t, CompareConfig(a, reordered), "/proxy-groups/G"); r.Status != "changed" || len(r.Fields) != 1 || r.Fields[0].Path != "/proxies" {
		t.Fatalf("ordered group membership lost: %+v", r)
	}
	absent := structuralFixture(t, "absent", "mode: rule\n")
	empty := structuralFixture(t, "empty", "mode: rule\nrules: []\nproxy-providers: {}\n")
	diff := CompareConfig(empty, absent)
	if diff.Equal || structuralRow(t, diff, "/_shape/rules").Status != "changed" || structuralRow(t, diff, "/_shape/proxy-providers").Status != "changed" {
		t.Fatalf("absent containers became empty: %+v", diff)
	}
}

func TestStructuralDependenciesAutoIncludeAndExplicitReuseReplace(t *testing.T) {
	from := structuralFixture(t, "from", sourceFixture)
	to := structuralFixture(t, "to", structuralEmpty)
	selection := StructuralSelection{Objects: []ObjectSelection{{ID: "/proxy-groups/G1"}}}
	c, err := ComposeConfig(from, to, selection)
	if err != nil || !containsString(c.AutoSelected, "/proxies/node1") || !reflect.DeepEqual(c.RequiredBy["/proxies/node1"], []string{"/proxy-groups/G1"}) {
		t.Fatalf("closure missing: %+v %v", c, err)
	}
	if _, ok := find(c.Definitions, "node1"); !ok {
		t.Fatal("auto node absent from expected definitions")
	}
	conflictRaw := strings.Replace(sourceFixture, "original-secret", "destination-secret", 1)
	conflictRaw = strings.Replace(conflictRaw, "- name: G1\n  type: select\n  proxies: [node1, DIRECT]\n  x-keep: yes\n", "", 1)
	conflictRaw = strings.Replace(conflictRaw, "- MATCH,G1", "- MATCH,G2", 1)
	to = structuralFixture(t, "to", conflictRaw)
	c, err = ComposeConfig(from, to, selection)
	if err == nil || !structuralBlock(c, "dependency_conflict") {
		t.Fatalf("different credentials silently reused: %+v %v", c, err)
	}
	for _, action := range []string{"reuse", "replace"} {
		selection.Dependencies = []DependencyDecision{{ID: "/proxies/node1", Action: action}}
		c, err = ComposeConfig(from, to, selection)
		if err != nil {
			t.Fatalf("%s: %+v %v", action, c, err)
		}
		defs, _ := definitions(c.Root, "proxies", "proxy", "")
		node, _ := find(defs, "node1")
		want := "destination-secret"
		if action == "replace" {
			want = "original-secret"
		}
		if scalar(node.Node, "password") != want {
			t.Fatalf("%s did not retain chosen identity", action)
		}
	}
}

func TestStructuralPrimaryReplacementReadOnlyAndNoDeletion(t *testing.T) {
	from := structuralFixture(t, "from", sourceFixture+"dns: {enable: true}\n")
	to := structuralFixture(t, "to", strings.Replace(sourceFixture, "original-secret", "target-secret", 1)+"dns: {enable: false}\nx-target: preserve\n")
	c, err := ComposeConfig(from, to, StructuralSelection{Objects: []ObjectSelection{{ID: "/proxies/node1"}}})
	if err == nil || !structuralBlock(c, "replacement_required") {
		t.Fatal("replacement was implicit")
	}
	c, err = ComposeConfig(from, to, StructuralSelection{Objects: []ObjectSelection{{ID: "/dns", Replace: true}}})
	if err == nil || !structuralBlock(c, "read_only_object") {
		t.Fatal("read-only host block was selectable")
	}
	c, err = ComposeConfig(from, to, StructuralSelection{Objects: []ObjectSelection{{ID: "/proxies/node1", Replace: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if scalar(c.Root, "x-target") != "preserve" || scalar(get(c.Root, "dns"), "enable") != "false" {
		t.Fatal("unselected target-only/host data changed")
	}
}

func TestStructuralRuleAnchorsPrependMovesAndDuplicateOccurrences(t *testing.T) {
	from := structuralFixture(t, "from", "rules: [\"DOMAIN,a.example,DIRECT\", \"DOMAIN,new.example,DIRECT\", \"MATCH,DIRECT\"]\n")
	to := structuralFixture(t, "to", "rules: [\"DOMAIN,a.example,DIRECT\", \"MATCH,DIRECT\"]\n")
	selected := StructuralSelection{Objects: []ObjectSelection{{ID: structuralRule(t, from, 1).ID}}}
	c, err := ComposeConfig(from, to, selected)
	if err != nil || !reflect.DeepEqual(structuralRules(c.Root), structuralRules(from.Root)) {
		t.Fatalf("unique anchored placement: %+v %v", c, err)
	}
	to = structuralFixture(t, "to", "rules: [\"DOMAIN,a.example,DIRECT\", \"DOMAIN,local.example,DIRECT\", \"MATCH,DIRECT\"]\n")
	c, err = ComposeConfig(from, to, selected)
	if err == nil || !structuralBlock(c, "rule_placement_ambiguous") {
		t.Fatal("ambiguous target-only gap accepted")
	}
	selected.RulePlacement = "prepend"
	c, err = ComposeConfig(from, to, selected)
	if err != nil || !reflect.DeepEqual(structuralRules(c.Root), []string{"DOMAIN,new.example,DIRECT", "DOMAIN,a.example,DIRECT", "DOMAIN,local.example,DIRECT", "MATCH,DIRECT"}) {
		t.Fatalf("explicit prepend removed target extras: %v %v", structuralRules(c.Root), err)
	}
	movedFrom := structuralFixture(t, "from", "rules: [\"DOMAIN,a.example,DIRECT\", \"DOMAIN,b.example,DIRECT\", \"MATCH,DIRECT\"]\n")
	movedTo := structuralFixture(t, "to", "rules: [\"DOMAIN,b.example,DIRECT\", \"DOMAIN,a.example,DIRECT\", \"MATCH,DIRECT\"]\n")
	c, err = ComposeConfig(movedFrom, movedTo, StructuralSelection{Objects: []ObjectSelection{{ID: structuralRule(t, movedFrom, 1).ID}}})
	if err != nil || !reflect.DeepEqual(structuralRules(c.Root), structuralRules(movedFrom.Root)) {
		t.Fatalf("move duplicated occurrence: %v %v", structuralRules(c.Root), err)
	}
	dupes := structuralFixture(t, "dup", "rules: [\"DOMAIN,a.example,DIRECT\", \"DOMAIN,a.example,DIRECT\", \"MATCH,DIRECT\"]\n")
	c, err = ComposeConfig(dupes, dupes, StructuralSelection{Objects: []ObjectSelection{{ID: structuralRule(t, dupes, 1).ID}}})
	if err == nil || !structuralBlock(c, "rule_placement_ambiguous") {
		t.Fatal("duplicate anchor ambiguity hidden")
	}
	c, err = ComposeConfig(dupes, dupes, StructuralSelection{Objects: []ObjectSelection{{ID: structuralRule(t, dupes, 1).ID}}, RulePlacement: "prepend"})
	if err != nil || len(structuralRules(c.Root)) != 3 {
		t.Fatalf("explicit duplicate occurrence copied again: %v", err)
	}
}

func TestStructuralAliasesAttachmentsAndDynamicMembership(t *testing.T) {
	from := structuralFixture(t, "from", "defaults: &d {type: ss, server: host, port: 443, cipher: aes-128-gcm, password: source-secret}\nproxies:\n- {<<: *d, name: A}\nproxy-groups:\n- {name: Dynamic, type: select, include-all: true}\n")
	to := structuralFixture(t, "to", "proxies:\n- &a {name: A, type: ss, server: host, port: 443, cipher: aes-128-gcm, password: target-secret}\n- {<<: *a, name: B}\nproxy-groups:\n- {name: G, type: select, proxies: [DIRECT]}\n")
	beforeB := structuralObject(t, to, "/proxies/B")
	c, err := ComposeConfig(from, to, StructuralSelection{Objects: []ObjectSelection{{ID: "/proxies/A", Replace: true}}, AttachGroups: []GroupAttachment{{ProxyID: "/proxies/A", Groups: []string{"G"}}}})
	if err != nil {
		t.Fatal(err)
	}
	defs, _ := definitions(c.Root, "proxies", "proxy", "")
	b, _ := find(defs, "B")
	if typedFingerprint(beforeB.Node) != typedFingerprint(b.Node) || scalar(b.Node, "password") != "target-secret" {
		t.Fatal("unselected alias effective value changed")
	}
	raw, _ := encode(c.Root)
	if strings.Contains(string(raw), "*a") || strings.Contains(string(raw), "*d") {
		t.Fatal("orphan aliases retained")
	}
	if _, err := decode(raw); err != nil {
		t.Fatal("candidate alias materialization invalid", err)
	}
	groups, _ := definitions(c.Root, "proxy-groups", "group", "")
	g, _ := find(groups, "G")
	if !reflect.DeepEqual(g.Members, []string{"DIRECT", "A"}) {
		t.Fatalf("attachment order: %v", g.Members)
	}
	if scalar(structuralObject(t, to, "/proxies/A").Node, "password") != "target-secret" {
		t.Fatal("composition mutated input snapshot")
	}
	c, err = ComposeConfig(from, to, StructuralSelection{Objects: []ObjectSelection{{ID: "/proxy-groups/Dynamic"}}})
	if err != nil || len(c.Warnings) == 0 {
		t.Fatal("dynamic destination membership was silently treated as source membership", err)
	}
}

func TestStructuralDependencyCyclesAndAttachmentConflict(t *testing.T) {
	from := structuralFixture(t, "from", "proxies:\n- {name: A, type: ss, server: host, port: 443, password: a, dialer-proxy: B}\n- {name: B, type: ss, server: host, port: 443, password: b, dialer-proxy: A}\n")
	to := structuralFixture(t, "to", structuralEmpty)
	c, err := ComposeConfig(from, to, StructuralSelection{Objects: []ObjectSelection{{ID: "/proxies/A"}}})
	if err == nil || !structuralBlock(c, "dependency_cycle") {
		t.Fatal("dialer dependency cycle accepted")
	}
	from = structuralFixture(t, "from", sourceFixture)
	to = structuralFixture(t, "to", sourceFixture)
	c, err = ComposeConfig(from, to, StructuralSelection{Objects: []ObjectSelection{{ID: "/proxies/node1"}, {ID: "/proxy-groups/G1"}}, AttachGroups: []GroupAttachment{{ProxyID: "/proxies/node1", Groups: []string{"G1"}}}})
	if err == nil || !structuralBlock(c, "attachment_conflict") {
		t.Fatal("whole group and derived attachment silently combined")
	}
}

func TestStructuralFileProviderBytesDifferAndResolveNodeOwner(t *testing.T) {
	raw := "proxy-providers:\n  local: {type: file, path: local.yaml}\nproxy-groups:\n- {name: G, type: select, proxies: [cached-node]}\n"
	a, b := structuralFixture(t, "a", raw), structuralFixture(t, "b", raw)
	for _, s := range []*ConfigSnapshot{&a, &b} {
		for i := range s.Objects {
			if s.Objects[i].Kind == "proxy-provider" {
				s.Objects[i].ResourceStatus = "available"
				s.Objects[i].ResourceSHA256 = "same"
			}
		}
	}
	if !CompareConfig(a, b).Equal {
		t.Fatal("same proven file bytes differ")
	}
	for i := range b.Objects {
		if b.Objects[i].Kind == "proxy-provider" {
			b.Objects[i].ResourceSHA256 = "different"
		}
	}
	row := structuralRow(t, CompareConfig(a, b), "/proxy-providers/local")
	if row.Status != "changed" || len(row.Fields) != 1 || row.Fields[0].Path != "/@resource" {
		t.Fatalf("content-only difference hidden: %+v", row)
	}
	file := HostFile{Data: []byte("proxies:\n- {name: cached-node, type: ss, server: host, port: 443, password: hidden}\n")}
	for i := range a.Objects {
		if a.Objects[i].Kind == "proxy-provider" {
			a.Objects[i].resource = &file
		}
	}
	c, err := ComposeConfig(a, structuralFixture(t, "to", structuralEmpty), StructuralSelection{Objects: []ObjectSelection{{ID: "/proxy-groups/G"}}})
	if err != nil || !containsString(c.AutoSelected, "/proxy-providers/local") {
		t.Fatalf("file-backed node owner not included: %+v %v", c, err)
	}
}

func TestStructuralSnapshotProviderReadsAreBoundedAndHTTPIsNotFetched(t *testing.T) {
	target := config.Target{ID: "fixture", Configs: []config.CoreConfig{{ID: "main", Path: "/home/core/config.yaml"}}, ConfigSource: &config.ConfigSource{Kind: "native", ConfigID: "main", Binary: "/bin/mihomo", Home: "/home/core"}}
	raw := []byte("proxy-providers:\n  local: {type: file, path: local.yaml}\n  remote: {type: http, path: cache.yaml, url: 'https://example.com/private?token=secret'}\nproxies: []\nproxy-groups: []\n")
	data := []byte("proxies: []\n")
	reads := 0
	opts := Options{Host: func(_ context.Context, _ config.Target, req HostRequest) (HostResponse, error) {
		switch req.Op {
		case "read":
			return HostResponse{File: HostFile{Path: req.Path, Resolved: req.Path, Data: raw, SHA256: hash(raw), Fingerprint: "config"}}, nil
		case "source-resource-read":
			reads++
			if req.Path != "/home/core/local.yaml" {
				t.Fatal("HTTP cache unexpectedly read", req.Path)
			}
			return HostResponse{File: HostFile{Path: req.Path, Resolved: req.Path, Data: data, SHA256: hash(data), Fingerprint: "resource"}}, nil
		default:
			t.Fatal("snapshot performed nonread operation", req.Op)
		}
		return HostResponse{}, nil
	}}
	s, err := SnapshotConfig(context.Background(), target, opts)
	if err != nil || reads != 1 || !s.Complete || structuralObject(t, s, "/proxy-providers/local").ResourceSHA256 != hash(data) {
		t.Fatalf("snapshot resource proof missing: %+v %v", s, err)
	}
	encoded, _ := json.Marshal(s)
	if strings.Contains(string(encoded), "token=secret") || strings.Contains(string(encoded), "/private?") {
		t.Fatal("snapshot provider URL leaked")
	}
	read := opts.Host
	opts.Host = func(ctx context.Context, target config.Target, req HostRequest) (HostResponse, error) {
		if req.Op == "source-resource-read" {
			return HostResponse{}, errors.New("missing file")
		}
		return read(ctx, target, req)
	}
	s, err = SnapshotConfig(context.Background(), target, opts)
	if err != nil || s.Complete || structuralObject(t, s, "/proxy-providers/local").Selectable {
		t.Fatalf("unavailable file became equal/transferable: %+v %v", s, err)
	}
}

func structuralCachedDialerFixture(t *testing.T, kind string) ConfigSnapshot {
	t.Helper()
	raw := "proxies:\n- {name: upstream, type: ss, server: source.example, port: 443, password: source-secret}\nproxy-providers:\n  pool: {type: " + kind + ", path: pool.yaml}\nproxy-groups:\n- {name: G, type: select, use: [pool]}\nrules: [\"MATCH,DIRECT\"]\n"
	s := structuralFixture(t, "source", raw)
	data := []byte("proxies:\n- {name: cached, type: ss, server: cached.example, port: 443, password: private-cache-secret, dialer-proxy: upstream}\n")
	for i := range s.Objects {
		if s.Objects[i].ID == "/proxy-providers/pool" {
			file := HostFile{Data: data, SHA256: hash(data), Fingerprint: "cache"}
			s.Objects[i].resource = &file
			if kind == "file" {
				s.Objects[i].ResourceStatus = "available"
				s.Objects[i].ResourceSHA256 = file.SHA256
			}
		}
	}
	return s
}

func TestStructuralFileProviderPayloadDialersJoinDependencyClosure(t *testing.T) {
	for _, primary := range []string{"/proxy-providers/pool", "/proxy-groups/G"} {
		t.Run(primary, func(t *testing.T) {
			source := structuralCachedDialerFixture(t, "file")
			selection := StructuralSelection{Objects: []ObjectSelection{{ID: primary}}}
			c, err := ComposeConfig(source, structuralFixture(t, "target", structuralEmpty), selection)
			if err != nil || !containsString(c.AutoSelected, "/proxies/upstream") || !containsString(c.RequiredBy["/proxies/upstream"], "/proxy-providers/pool") {
				t.Fatalf("cached dialer not included: %+v %v", c, err)
			}
			target := structuralFixture(t, "target", "proxies:\n- {name: upstream, type: ss, server: destination.example, port: 443, password: destination-secret}\nproxy-groups: []\nrules: [\"MATCH,DIRECT\"]\n")
			c, err = ComposeConfig(source, target, selection)
			if err == nil || !structuralBlock(c, "dependency_conflict") {
				t.Fatalf("same-name differing cached dialer was silently reused: %+v %v", c, err)
			}
			for _, action := range []string{"reuse", "replace"} {
				selection.Dependencies = []DependencyDecision{{ID: "/proxies/upstream", Action: action}}
				c, err = ComposeConfig(source, target, selection)
				if err != nil {
					t.Fatalf("%s decision failed: %+v %v", action, c, err)
				}
				defs, _ := definitions(c.Root, "proxies", "proxy", "")
				node, _ := find(defs, "upstream")
				want := "destination-secret"
				if action == "replace" {
					want = "source-secret"
				}
				if scalar(node.Node, "password") != want {
					t.Fatalf("%s cached dialer decision not honored", action)
				}
			}
		})
	}
}

func TestStructuralCapturedHTTPDialersAreAnalyzedWithoutCacheDrift(t *testing.T) {
	source := structuralCachedDialerFixture(t, "http")
	other := structuralCachedDialerFixture(t, "http")
	for i := range other.Objects {
		if other.Objects[i].Kind == "proxy-provider" {
			different := HostFile{Data: []byte("proxies: []\n")}
			other.Objects[i].resource = &different
		}
	}
	if !CompareConfig(source, other).Equal {
		t.Fatal("private HTTP cache bytes became configuration drift")
	}
	c, err := ComposeConfig(source, structuralFixture(t, "target", structuralEmpty), StructuralSelection{Objects: []ObjectSelection{{ID: "/proxy-providers/pool"}}})
	if err != nil || !containsString(c.AutoSelected, "/proxies/upstream") {
		t.Fatalf("captured HTTP payload was not enriched into closure: %+v %v", c, err)
	}
	for i := range source.Objects {
		if source.Objects[i].Kind == "proxy-provider" {
			data := []byte("proxies:\n- {name: cached, type: ss, server: host, port: 443, password: hidden, dialer-proxy: G}\n")
			file := HostFile{Data: data}
			source.Objects[i].resource = &file
		}
	}
	c, err = ComposeConfig(source, structuralFixture(t, "target", structuralEmpty), StructuralSelection{Objects: []ObjectSelection{{ID: "/proxy-groups/G"}}})
	if err == nil || !structuralBlock(c, "dependency_cycle") {
		t.Fatalf("cached payload cycle escaped closure: %+v %v", c, err)
	}
}

func TestStructuralComparisonDeduplicatesOwnerWarnings(t *testing.T) {
	s := structuralFixture(t, "one", structuralEmpty)
	s.Warnings = []string{"Owner reload replaces runtime settings.", "Owner reload replaces runtime settings."}
	diff := CompareConfig(s, s)
	if len(diff.Warnings) != 1 || strings.Count(FormatConfigDiff(diff, "tree"), "Owner reload replaces runtime settings.") != 1 {
		t.Fatal("duplicate source/destination owner warning retained")
	}
}
