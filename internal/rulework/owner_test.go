package rulework

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

func TestDockerRuleOwnerUsesExplicitDescriptorAndContainerReloadPath(t *testing.T) {
	ctx := context.Background()
	target := config.Target{ID: "rules", Controller: "http://127.0.0.1:9090", RuleSource: &config.RuleSource{Kind: "docker", HostPath: "/host/config.yaml", CorePath: "/core/config.yaml", Container: "rules-container", Binary: "/mihomo", Home: "/core"}, ConfigSource: &config.ConfigSource{Kind: "docker", Container: "unrelated-node-owner"}}
	visible := "before"
	opts := Options{Host: func(_ context.Context, _ config.Target, req HostRequest) (HostFile, error) {
		return HostFile{Path: req.Path, Resolved: req.Path, Data: []byte("rules: [MATCH,DIRECT]\n"), SHA256: "before", Fingerprint: "guard"}, nil
	}, Docker: func(_ context.Context, _ config.Target, req DockerRequest) (DockerInfo, error) {
		if req.Container != "rules-container" || req.HostPath != "/host/config.yaml" || req.CorePath != "/core/config.yaml" {
			t.Fatal("wrong source descriptor", req)
		}
		return DockerInfo{ContainerID: "identity", Image: "image", SourceSHA256: visible, SingleFile: true}, nil
	}}
	source, err := inspectSource(ctx, target, opts)
	if err != nil || source.File != "/host/config.yaml" || sourceReloadPath(source) != "/core/config.yaml" || sourceOwnerIdentity(source) != "identity:image" {
		t.Fatal(source, err)
	}
	if err = validateOwnerCandidate(ctx, target, source, []byte("rules: [MATCH,DIRECT]\n"), "version", opts); err != nil {
		t.Fatal(err)
	}
	ready, restarted, err := activateOwnerSource(ctx, target, source, "after", opts)
	if ready || restarted || err != nil {
		t.Fatal("stale unbound single-file mount reloaded", ready, restarted, err)
	}
	visible = "after"
	ready, restarted, err = activateOwnerSource(ctx, target, source, "after", opts)
	if !ready || restarted || err != nil {
		t.Fatal(ready, restarted, err)
	}
	opts.Docker = func(context.Context, config.Target, DockerRequest) (DockerInfo, error) {
		return DockerInfo{ContainerID: "replacement", Image: "image", SourceSHA256: "after"}, nil
	}
	if _, _, err = activateOwnerSource(ctx, target, source, "after", opts); err == nil {
		t.Fatal("replaced owner accepted")
	}
}

func TestSourceUnavailableDoesNotHideInvalidSource(t *testing.T) {
	if _, err := readHost(context.Background(), "", filepath.Join(t.TempDir(), "absent.yaml")); !errors.Is(err, ErrSourceUnavailable) {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := readHost(context.Background(), "", dir); !errors.Is(err, ErrSourceUnavailable) {
		t.Fatal("directory OS read failure should be unavailable", err)
	}
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte("rules: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := inspectSource(context.Background(), config.Target{RuleSource: &config.RuleSource{Kind: "invalid"}}, Options{})
	if err == nil || errors.Is(err, ErrSourceUnavailable) {
		t.Fatal("invalid binding hidden", err)
	}
}
