package configwork

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/managedrpi"
)

func TestManagedOwnerDispatchAndChangingSnapshotPaths(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(root, "private"), 0700); err != nil {
		t.Fatal(err)
	}
	before := []byte(sourceFixture)
	current := before
	identity := managedrpi.Identity{ProfileSHA256: hash(current), NetworkBundleSHA256: strings.Repeat("a", 64), BootID: "boot", CoreIdentity: "core"}
	target := config.Target{ID: "pi", Controller: "https://192.0.2.1:9090", CAFile: "/private/ca.pem", ManagedRPi: &config.ManagedRPi{ProjectDir: root, ConnectionFile: filepath.Join(root, "private", "connection.json")}, ConfigSource: &config.ConfigSource{Kind: managedrpi.Kind}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Fatalf("generic network write: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(core.Object{"version": "v1.19.29", "meta": true})
	}))
	defer server.Close()
	calls := []string{}
	snapshot := 0
	var candidate []byte
	failApply := false
	runner := func(_ context.Context, _ config.Target, q managedrpi.Request) (managedrpi.Response, error) {
		calls = append(calls, q.Operation)
		out := managedrpi.Response{Schema: 1, Identity: identity}
		switch q.Operation {
		case "inspect":
			snapshot++
			out.ProfilePath = filepath.Join(root, "private", fmt.Sprintf("snapshot-%d.yaml", snapshot))
			if e := os.WriteFile(out.ProfilePath, current, 0600); e != nil {
				t.Fatal(e)
			}
			out.Controller = target.Controller
			out.CACert = target.CAFile
		case "preview":
			if q.BaseIdentity == nil || *q.BaseIdentity != identity {
				t.Fatal("wrong base identity")
			}
			candidate = append([]byte{}, q.Candidate...)
			out.ReceiptPath = filepath.Join(root, "private", fmt.Sprintf("receipt-%d.json", snapshot))
			os.WriteFile(out.ReceiptPath, []byte("{}"), 0600)
			out.BaseIdentity = identity
			out.ProfileSHA256 = hash(candidate)
			out.State = "prepared"
			out.RequiresProxyInterruption = true
		case "apply":
			if failApply {
				return out, errors.New("fixture unknown result")
			}
			current = candidate
			identity.ProfileSHA256 = hash(current)
			out.State = "confirmed"
			out.Identity = identity
			out.ProfileSHA256 = identity.ProfileSHA256
		case "verify":
			out.State = "confirmed"
			out.ProfileSHA256 = identity.ProfileSHA256
		case "restore":
			current = before
			identity.ProfileSHA256 = hash(current)
			out.State = "restored"
			out.Identity = identity
			out.ProfileSHA256 = identity.ProfileSHA256
		default:
			t.Fatal(q.Operation)
		}
		return out, nil
	}
	opts := Options{StateDir: filepath.Join(root, "state"), Broker: runner, Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		c, e := core.New(core.Options{Endpoint: server.URL})
		return c, c, e
	}, Host: func(context.Context, config.Target, HostRequest) (HostResponse, error) {
		t.Fatal("generic filesystem path reached")
		return HostResponse{}, nil
	}, Validate: func(context.Context, config.Target, []byte, string) error {
		t.Fatal("generic validator reached")
		return nil
	}}
	req := Request{Kind: "proxy", Action: "edit", Name: "node1", Input: []byte("port: 8443\n")}
	ctx := context.Background()
	p, e := Preview(ctx, target, req, opts)
	if e != nil {
		t.Fatal(e)
	}
	second, e := Preview(ctx, target, req, opts)
	if e != nil || second.Digest != p.Digest {
		t.Fatalf("snapshot path changed digest: %v", e)
	}
	if !reflect.DeepEqual(calls, []string{"inspect", "preview", "inspect", "preview"}) {
		t.Fatal(calls)
	}
	r, e := Apply(ctx, target, req, p.Digest, opts)
	if e != nil || r.Status != "source_and_structure_verified" {
		t.Fatalf("apply: %#v %v", r, e)
	}
	if r.BrokerReceipt == "" {
		t.Fatal("broker receipt absent")
	}
	files, e := os.ReadDir(filepath.Join(opts.StateDir, r.ID))
	if e != nil || len(files) != 1 || files[0].Name() != "receipt.json" {
		t.Fatalf("generic profile copies created: %v %v", files, e)
	}
	if _, e = Verify(ctx, target, r.ID, opts); e != nil {
		t.Fatal(e)
	}
	if r, e = Restore(ctx, target, r.ID, opts); e != nil || !r.Restored {
		t.Fatal(e)
	}
	p, e = Preview(ctx, target, req, opts)
	if e != nil {
		t.Fatal(e)
	}
	failApply = true
	r, e = Apply(ctx, target, req, p.Digest, opts)
	if e == nil || r.Status != "owner_result_unknown" || r.BrokerReceipt == "" {
		t.Fatalf("unknown result lost receipt: %#v %v", r, e)
	}
	loaded, e := loadReceipt(opts, r.ID)
	if e != nil || loaded.Status != r.Status {
		t.Fatal("unknown result not durable")
	}
}
