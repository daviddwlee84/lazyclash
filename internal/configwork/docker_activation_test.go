package configwork

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/clientservice"
	"github.com/daviddwlee84/lazyclash/internal/config"
)

type dockerActivationFixture struct {
	target                   config.Target
	opts                     Options
	mu                       sync.Mutex
	current, visible         []byte
	restarts, puts, notReady int
	failPut                  bool
}

func newDockerActivationFixture(t *testing.T, bound bool) *dockerActivationFixture {
	t.Helper()
	f := &dockerActivationFixture{current: []byte(sourceFixture), visible: []byte(sourceFixture)}
	root := t.TempDir()
	hostPath := "/host/config.yaml"
	service := config.ClientService{Kind: "docker", DockerHost: "unix:///fixture", Container: strings.Repeat("a", 64), Image: "sha256:" + strings.Repeat("b", 64), MountsSHA256: strings.Repeat("c", 64)}
	f.target = config.Target{ID: "fixture", ConfigSource: &config.ConfigSource{Kind: "docker", DockerHost: service.DockerHost, Container: service.Container, HostPath: hostPath, CorePath: "/core/config.yaml", Binary: "/core/mihomo", Home: "/core"}}
	if bound {
		f.target.Service = &service
	}
	f.opts = Options{StateDir: filepath.Join(root, "config-receipts"), Validate: func(context.Context, config.Target, []byte, string) error { return nil }, Host: func(_ context.Context, _ config.Target, r HostRequest) (HostResponse, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		file := func() HostFile {
			return HostFile{Path: hostPath, Resolved: hostPath, Data: append([]byte{}, f.current...), SHA256: hash(f.current), Fingerprint: hash(f.current), Mode: 0600}
		}
		switch r.Op {
		case "read":
			return HostResponse{File: file()}, nil
		case "docker-inspect", "docker-validate":
			return HostResponse{ContainerID: service.Container, Image: service.Image, SourceSHA256: hash(f.visible), SingleFile: true}, nil
		case "check", "write":
			for _, guard := range r.Guards {
				if guard.Fingerprint != hash(f.current) {
					return HostResponse{}, errors.New("source changed")
				}
			}
			if r.Op == "write" {
				f.current = append([]byte{}, r.Data...)
			}
			return HostResponse{File: file()}, nil
		}
		return HostResponse{}, errors.New("unexpected host operation")
	}, ClientServices: clientservice.Options{StateDir: filepath.Join(root, "service-receipts"), Host: func(_ context.Context, _ config.Target, r clientservice.Request) (clientservice.Status, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		s := clientservice.Status{Binding: service, Running: true, State: "running", StateDigest: "stable", SourceSingleFile: true}
		if r.Op == "source-status" || r.SourceSHA256 != "" {
			if r.SourceSHA256 != hash(f.current) {
				return s, errors.New("source changed")
			}
			s.SourceMatches = hash(f.visible) == hash(f.current)
		}
		if r.Op == "restart" {
			f.restarts++
			f.visible = append([]byte{}, f.current...)
			f.notReady = 2
		}
		return s, nil
	}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			if f.notReady > 0 {
				f.notReady--
				w.WriteHeader(503)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"version": "fixture-version", "meta": true})
		case "/configs":
			if r.Method == "PUT" {
				f.puts++
				if f.failPut {
					w.WriteHeader(503)
					return
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"mode": "rule"})
		case "/proxies":
			node, err := decode(f.visible)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			proxies, _ := proxyDefinitions(node, "")
			groups, _ := definitions(node, "proxy-groups", "group", "")
			entries := map[string]any{}
			for _, d := range append(proxies, groups...) {
				entry := map[string]any{"name": d.Name, "type": d.Type}
				if d.Kind == "group" {
					entry["all"] = d.Members
				}
				entries[d.Name] = entry
			}
			json.NewEncoder(w).Encode(map[string]any{"proxies": entries})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	f.target.Controller = server.URL
	return f
}
func (f *dockerActivationFixture) apply(t *testing.T) Receipt {
	t.Helper()
	req := Request{Kind: "proxy", Action: "edit", Name: "node1", Input: []byte("password: next-secret\n")}
	p, err := Preview(context.Background(), f.target, req, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Apply(context.Background(), f.target, req, p.Digest, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestDockerActivationWaitsForReadinessAndRestoreRemounts(t *testing.T) {
	f := newDockerActivationFixture(t, true)
	r := f.apply(t)
	if !r.SourceVerified || !r.GeneratedVerified || !r.RuntimeObserved || f.restarts != 1 || f.puts != 1 {
		t.Fatal(r, f.restarts, f.puts)
	}
	restored, err := Restore(context.Background(), f.target, r.ID, f.opts)
	if err != nil || restored.Status != "restored_runtime_apply_confirmed" || f.restarts != 2 || f.puts != 2 || string(f.visible) != sourceFixture {
		t.Fatal(restored, err, f.restarts, f.puts)
	}
}
func TestUnboundDockerStaleMountSkipsReloadAndReportsSourceDrift(t *testing.T) {
	f := newDockerActivationFixture(t, false)
	r := f.apply(t)
	if r.Status != "persisted_pending_owner_reload" || f.puts != 0 || f.restarts != 0 {
		t.Fatal(r, f.puts, f.restarts)
	}
	f.mu.Lock()
	f.current = append(f.current, []byte("# changed separately\n")...)
	f.mu.Unlock()
	r, err := Verify(context.Background(), f.target, r.ID, f.opts)
	if err != nil || r.Status != "source_changed" || r.SourceVerified {
		t.Fatal(r, err)
	}
}
func TestDockerRestoreWithoutBoundOwnerLeavesStaleMountPending(t *testing.T) {
	f := newDockerActivationFixture(t, false)
	r := f.apply(t)
	f.mu.Lock()
	f.visible = append([]byte{}, f.current...)
	f.mu.Unlock()
	restored, err := Restore(context.Background(), f.target, r.ID, f.opts)
	if err != nil || restored.Status != "restored_pending_owner_reload" || !restored.Restored || f.puts != 0 || f.restarts != 0 {
		t.Fatal(restored, err)
	}
}
func TestDockerReloadFailureIsNeverRetried(t *testing.T) {
	f := newDockerActivationFixture(t, true)
	req := Request{Kind: "proxy", Action: "edit", Name: "node1", Input: []byte("password: next-secret\n")}
	p, err := Preview(context.Background(), f.target, req, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	f.failPut = true
	r, err := Apply(context.Background(), f.target, req, p.Digest, f.opts)
	if err == nil || r.Status != "runtime_result_unknown" || f.puts != 1 || f.restarts != 1 {
		t.Fatal(r, err, f.puts, f.restarts)
	}
}
func TestReadinessCancellationDoesNotSendReload(t *testing.T) {
	f := newDockerActivationFixture(t, true)
	f.notReady = 1000
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := applySourceOnce(ctx, f.target, "/core/config.yaml", true, f.opts); err == nil || f.puts != 0 {
		t.Fatal(err, f.puts)
	}
}
