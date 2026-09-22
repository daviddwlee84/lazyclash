package configwork

import (
	"context"
	"errors"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportCreatesGroupsInSingleReceipt(t *testing.T) {
	for _, verge := range []bool{false, true} {
		f := newConfigFixture(t, verge)
		req := Request{Kind: "proxy", Action: "import", Input: []byte("trojan://p@example.test:443#new"), Groups: []string{"G1"}, CreateGroups: []string{"Private, 東京"}}
		p, err := Preview(context.Background(), f.target, req, f.opts)
		if err != nil {
			t.Fatal(err)
		}
		g, ok := find(p.source.Groups, "Private, 東京")
		if !ok || len(g.Members) != 1 || g.Members[0] != "new" {
			t.Fatalf("new group: %+v", g)
		}
		if _, err = Apply(context.Background(), f.target, req, p.Digest, f.opts); err != nil {
			t.Fatal(err)
		}
		catalog, err := Inspect(context.Background(), f.target, f.opts)
		if err != nil || len(catalog.Proxies) != 2 || len(catalog.Groups) != 3 {
			t.Fatalf("%+v %v", catalog, err)
		}
	}
}

func TestAdoptExactExistingNodeDoesNotWriteOrReload(t *testing.T) {
	for _, verge := range []bool{false, true} {
		f := newConfigFixture(t, verge)
		d, err := ReadDefinition(context.Background(), f.target, "proxy", "node1", f.opts)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := d.Raw()
		req := Request{Kind: "proxy", Action: "import", Input: raw, Groups: []string{"G1"}, AdoptExisting: true}
		p, err := Preview(context.Background(), f.target, req, f.opts)
		if err != nil || len(p.Changes) != 0 {
			t.Fatalf("adoption changed files: %+v %v", p, err)
		}
		r, err := Apply(context.Background(), f.target, req, p.Digest, f.opts)
		if err != nil || !r.SourceVerified || f.writes.Load() != 0 {
			t.Fatalf("adoption reloaded: %+v %v", r, err)
		}
		req.Input = []byte(strings.ReplaceAll(string(raw), "original-secret", "different"))
		if _, err = Preview(context.Background(), f.target, req, f.opts); err == nil || !strings.Contains(err.Error(), "differs") {
			t.Fatalf("conflict accepted: %v", err)
		}
	}
}

func TestAdoptCanAddMembershipWithoutOverridingVergeNode(t *testing.T) {
	f := newConfigFixture(t, true)
	d, _ := ReadDefinition(context.Background(), f.target, "proxy", "node1", f.opts)
	raw, _ := d.Raw()
	p, err := Preview(context.Background(), f.target, Request{Kind: "proxy", Action: "import", Input: raw, AdoptExisting: true, CreateGroups: []string{"New"}}, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range p.Changes {
		if strings.HasSuffix(ch.Path, "proxies.yaml") {
			t.Fatal("adoption created redundant node override")
		}
	}
}

func TestPreviewValidatesAndClassicFailsBeforeSourceBinding(t *testing.T) {
	f := newConfigFixture(t, false)
	before, _ := os.ReadFile(f.base)
	f.opts.Validate = func(context.Context, config.Target, []byte, string) error {
		return errors.New("validator rejected candidate")
	}
	_, err := Preview(context.Background(), f.target, Request{Kind: "proxy", Action: "import", Input: []byte("trojan://p@a.test:443#new")}, f.opts)
	after, _ := os.ReadFile(f.base)
	if err == nil || !strings.Contains(err.Error(), "validator rejected") || string(before) != string(after) || f.writes.Load() != 0 {
		t.Fatalf("validation did not fail before write: %v", err)
	}
	classic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			t.Error("unexpected classic core access", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"version":"v1.18.0"}`))
	}))
	defer classic.Close()
	target := config.Target{ID: "classic", Controller: classic.URL}
	_, err = Preview(context.Background(), target, Request{Kind: "proxy", Action: "import", Input: []byte("name: reality\ntype: vless\nserver: example.test\nport: 443\nuuid: hidden\n")}, Options{})
	if err == nil || !strings.Contains(err.Error(), "classic Clash") || strings.Contains(err.Error(), "hidden") {
		t.Fatalf("missing early compatibility diagnostic: %v", err)
	}
}

func TestVergeNativeEmptyMergeTemplateIsValidContext(t *testing.T) {
	f := newConfigFixture(t, true)
	manifest := filepath.Join(f.target.ConfigSource.DataDir, "profiles.yaml")
	raw, _ := os.ReadFile(manifest)
	raw = []byte(strings.Replace(string(raw), "proxies: px, groups: gr", "proxies: px, groups: gr, merge: mg", 1) + "- {uid: mg, type: merge, file: merge.yaml}\n")
	os.WriteFile(manifest, raw, 0600)
	merge := filepath.Join(f.target.ConfigSource.DataDir, "profiles", "merge.yaml")
	for _, template := range []string{"# Profile Enhancement Merge Template for Clash Verge\n\n", "null\n"} {
		os.WriteFile(merge, []byte(template), 0600)
		catalog, err := Inspect(context.Background(), f.target, f.opts)
		if err != nil || len(catalog.Proxies) != 1 {
			t.Fatalf("native empty template failed: %v", err)
		}
	}
	os.WriteFile(merge, []byte("null\n---\nproxies: []\n"), 0600)
	if _, err := Inspect(context.Background(), f.target, f.opts); err == nil {
		t.Fatal("multiple merge documents accepted")
	}
}
