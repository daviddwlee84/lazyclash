package rulework

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/managedrpi"
)

func TestManagedRuleKeepsProviderGuardFirst(t *testing.T) {
	before := []byte("rules:\n  - RULE-SET,rpi-local-proxy,PROXY\n  - MATCH,DIRECT\n")
	after, noChange, err := addRule(before, managedrpi.Kind, "DOMAIN,example.com,PROXY")
	if err != nil || noChange {
		t.Fatalf("add rule: %v", err)
	}
	node, err := decodeYAML(after)
	if err != nil {
		t.Fatal(err)
	}
	rules := mappingValue(node.Content[0], "rules").Content
	if len(rules) != 3 || rules[0].Value != "RULE-SET,rpi-local-proxy,PROXY" || rules[1].Value != "DOMAIN,example.com,PROXY" {
		t.Fatalf("managed provider prefix changed: %s", after)
	}
	unchanged, noChange, err := addRule(after, managedrpi.Kind, "DOMAIN,example.com,PROXY")
	if err != nil || !noChange || string(unchanged) != string(after) {
		t.Fatalf("existing managed rule should be no-op: %v", err)
	}
}

func TestManagedRuleOwnerNeverWritesSnapshotOrReloads(t *testing.T) {
	f := newFixture(t, false)
	endpoint := f.target.Controller
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Mkdir(filepath.Join(root, "private"), 0700)
	f.target.Controller = "https://192.0.2.1:9090"
	f.target.CAFile = "/ca.pem"
	f.target.ManagedRPi = &config.ManagedRPi{ProjectDir: root, ConnectionFile: filepath.Join(root, "private", "connection.json")}
	f.target.RuleSource = &config.RuleSource{Kind: managedrpi.Kind}
	before := append([]byte{}, f.source...)
	current := before
	id := managedrpi.Identity{ProfileSHA256: sha(current), NetworkBundleSHA256: strings.Repeat("a", 64), BootID: "boot", CoreIdentity: "core"}
	var candidate []byte
	count := 0
	writes := 0
	f.opts.Open = func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		c, e := core.New(core.Options{Endpoint: endpoint})
		return c, c, e
	}
	f.opts.Validate = func(context.Context, config.Target, []byte, string) error {
		t.Fatal("generic validator reached")
		return nil
	}
	f.opts.Broker = func(_ context.Context, _ config.Target, q managedrpi.Request) (managedrpi.Response, error) {
		out := managedrpi.Response{Schema: 1, Identity: id}
		switch q.Operation {
		case "inspect":
			count++
			out.ProfilePath = filepath.Join(root, "private", fmt.Sprintf("source-%d.yaml", count))
			os.WriteFile(out.ProfilePath, current, 0600)
			out.Controller = f.target.Controller
			out.CACert = f.target.CAFile
		case "preview":
			candidate = append([]byte{}, q.Candidate...)
			out.ReceiptPath = filepath.Join(root, "private", fmt.Sprintf("receipt-%d.json", count))
			os.WriteFile(out.ReceiptPath, []byte("{}"), 0600)
			out.BaseIdentity = id
			out.ProfileSHA256 = sha(candidate)
			out.State = "prepared"
			out.RequiresProxyInterruption = true
		case "apply":
			writes++
			current = candidate
			id.ProfileSHA256 = sha(current)
			out.Identity = id
			out.ProfileSHA256 = id.ProfileSHA256
			out.State = "confirmed"
		case "verify":
			out.State = "confirmed"
			out.ProfileSHA256 = id.ProfileSHA256
		case "restore":
			writes++
			current = before
			id.ProfileSHA256 = sha(current)
			out.Identity = id
			out.ProfileSHA256 = id.ProfileSHA256
			out.State = "restored"
		default:
			t.Fatal(q.Operation)
		}
		return out, nil
	}
	ctx := context.Background()
	p, e := Preview(ctx, f.target, "example.com", "PROXY", f.opts)
	if e != nil {
		t.Fatal(e)
	}
	p2, e := Preview(ctx, f.target, "example.com", "PROXY", f.opts)
	if e != nil || p.Digest != p2.Digest {
		t.Fatalf("unstable snapshot digest: %v", e)
	}
	if writes != 0 {
		t.Fatal("preview mutated owner")
	}
	r, e := Apply(ctx, f.target, "example.com", "PROXY", p.Digest, f.opts)
	if e != nil || r.Status != "applied_verified" {
		t.Fatalf("apply %s: %v", r.Status, e)
	}
	if _, e = Verify(ctx, f.target, r.ID, f.opts); e != nil {
		t.Fatal(e)
	}
	if r, e = Restore(ctx, f.target, r.ID, f.opts); e != nil || !r.Restored {
		t.Fatal(e)
	}
	if writes != 2 || f.writes != 0 {
		t.Fatalf("owner writes %d generic PUT %d", writes, f.writes)
	}
	entries, e := os.ReadDir(filepath.Join(f.opts.StateDir, r.ID))
	if e != nil || len(entries) != 1 || entries[0].Name() != "receipt.json" {
		t.Fatal("generic before.yaml receipt created")
	}
	raw, e := os.ReadFile(f.target.Configs[0].Path)
	if e != nil || string(raw) != string(before) {
		t.Fatal("generic source changed")
	}
}
