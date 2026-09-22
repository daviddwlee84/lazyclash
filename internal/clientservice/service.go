package clientservice

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
)

//go:embed host.py
var hostScript string

func digest(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func call(ctx context.Context, t config.Target, r Request, o Options) (Status, error) {
	if o.Host != nil {
		return o.Host(ctx, t, r)
	}
	raw, _ := json.Marshal(r)
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	out, err := connection.ExecutePython(ctx, t.SSHHost, hostScript, raw, 1<<20)
	if err != nil {
		return Status{}, err
	}
	var s Status
	if json.Unmarshal(out, &s) != nil {
		return s, errors.New("invalid client service response")
	}
	if s.Error != "" {
		return s, errors.New(s.Error)
	}
	return s, nil
}
func validTarget(t config.Target) error {
	if t.Transient || t.TransportOverride || t.ID == "" {
		return errors.New("existing service operations require a saved target endpoint and SSH host")
	}
	if t.ManagedCoreID != "" {
		return errors.New("this target has a managed installation; use cores lifecycle commands")
	}
	return nil
}
func Inspect(ctx context.Context, t config.Target, o Options) (Status, error) {
	if err := validTarget(t); err != nil {
		return Status{}, err
	}
	if t.Service == nil {
		return Status{}, errors.New("bind the existing service with targets service bind first")
	}
	if err := config.ValidateClientService(t.Service); err != nil {
		return Status{}, err
	}
	return call(ctx, t, Request{Op: "status", Service: *t.Service}, o)
}

// PrepareBind inspects a named candidate and returns a pinned identity for review.
func PrepareBind(ctx context.Context, t config.Target, candidate config.ClientService, o Options) (Plan, error) {
	if err := validTarget(t); err != nil {
		return Plan{}, err
	}
	if candidate.Kind == "docker" && !config.ValidDockerHost(candidate.DockerHost) {
		return Plan{}, errors.New("--docker-host requires an explicit unix:///absolute/socket on the selected host")
	}
	s, err := call(ctx, t, Request{Op: "bind", Service: candidate}, o)
	if err != nil {
		return Plan{}, err
	}
	if err = config.ValidateClientService(&s.Binding); err != nil {
		return Plan{}, err
	}
	p := Plan{TargetID: t.ID, Action: "bind", Before: s, Changes: []string{"Record the inspected existing service identity; no service or files are changed."}}
	p.Digest = planDigest(t, p)
	return p, nil
}
func planDigest(t config.Target, p Plan) string {
	return digest(struct {
		Target     string
		Controller string
		SSH        string
		Existing   *config.ClientService
		Plan       Plan
	}{t.ID, t.Controller, t.SSHHost, t.Service, p})
}
func Preview(ctx context.Context, t config.Target, action string, disableAutostart bool, o Options) (Plan, error) {
	switch action {
	case "start", "stop", "restart", "enable", "disable":
	default:
		return Plan{}, errors.New("unknown existing service action")
	}
	if disableAutostart && action != "stop" {
		return Plan{}, errors.New("--disable-autostart only applies to stop")
	}
	s, err := Inspect(ctx, t, o)
	if err != nil {
		return Plan{}, err
	}
	p := Plan{TargetID: t.ID, Action: action, DisableAutostart: disableAutostart, Before: s}
	if action == "enable" || action == "disable" || disableAutostart {
		if s.Binding.Kind == "docker" && s.Binding.ComposeFile != "" && !s.ComposeEditable {
			return Plan{}, errors.New("Compose restart source is not a simple editable service field; inspect it before changing autostart")
		}
		if action == "enable" {
			p.Changes = append(p.Changes, "Enable this bound service's autostart (Docker: unless-stopped).")
		} else {
			p.Changes = append(p.Changes, "Disable this bound service's autostart; update both Compose source and live Docker policy when applicable.")
		}
	}
	if action == "start" || action == "stop" || action == "restart" {
		p.Changes = append(p.Changes, fmt.Sprintf("%s only the bound %s service; preserve its installation and shared resources.", action, s.Binding.Kind))
	}
	if action == "restart" || action == "start" {
		p.Changes = append(p.Changes, "Startup source settings take effect; inspect routing settings and test traffic after activation.")
	}
	p.Digest = planDigest(t, p)
	return p, nil
}
func Apply(ctx context.Context, t config.Target, action string, disableAutostart bool, expected string, o Options) (Receipt, error) {
	return apply(ctx, t, action, disableAutostart, expected, o, nil)
}
func apply(ctx context.Context, t config.Target, action string, disableAutostart bool, expected string, o Options, source *Request) (Receipt, error) {
	if o.ReadOnly {
		return Receipt{}, errors.New("read-only mode forbids existing service changes")
	}
	if expected == "" {
		return Receipt{}, errors.New("service action requires the reviewed preview digest")
	}
	p, err := Preview(ctx, t, action, disableAutostart, o)
	if err != nil {
		return Receipt{}, err
	}
	if p.Digest != expected {
		return Receipt{}, errors.New("service state changed; review a fresh preview")
	}
	id := make([]byte, 16)
	if _, err = rand.Read(id); err != nil {
		return Receipt{}, err
	}
	receipt := Receipt{ID: hex.EncodeToString(id), TargetID: t.ID, Action: action, Status: "pending", Digest: p.Digest, Before: p.Before, CreatedAt: time.Now().UTC()}
	if source != nil {
		receipt.SourcePath, receipt.SourceSHA256 = source.SourcePath, source.SourceSHA256
	}
	path, err := newReceipt(o, receipt)
	if err != nil {
		return Receipt{}, err
	}
	request := Request{Op: action, Service: *t.Service, Expected: p.Before.StateDigest, DisableAutostart: disableAutostart}
	if source != nil {
		request.SourcePath, request.CorePath, request.SourceSHA256, request.SourceContainer = source.SourcePath, source.CorePath, source.SourceSHA256, source.SourceContainer
	}
	after, err := call(ctx, t, request, o)
	receipt.After = &after
	if err != nil {
		receipt.Status = "unconfirmed"
		receipt.Error = err.Error()
	} else {
		receipt.Status = "observed"
	}
	if writeErr := saveReceipt(path, receipt); writeErr != nil {
		return receipt, writeErr
	}
	return receipt, err
}

// VerifySource proves the source mount and compares host/container bytes without
// mutating either. It requires a service binding matching the source container.
func VerifySource(ctx context.Context, t config.Target, sha string, o Options) (Status, error) {
	if t.ConfigSource == nil || t.ConfigSource.Kind != "docker" {
		return Status{}, errors.New("source activation requires a Docker source")
	}
	if t.Service == nil || t.Service.Kind != "docker" || t.ConfigSource.DockerHost != t.Service.DockerHost {
		return Status{}, errors.New("source activation requires the same explicitly bound Docker daemon")
	}
	if err := config.ValidateClientService(t.Service); err != nil {
		return Status{}, err
	}
	s, err := call(ctx, t, Request{Op: "source-status", Service: *t.Service, SourceContainer: t.ConfigSource.Container, SourcePath: t.ConfigSource.HostPath, CorePath: t.ConfigSource.CorePath, SourceSHA256: sha}, o)
	return s, err
}

// RestartForSource performs one guarded owner restart after a reviewed source
// write. It creates its own durable lifecycle receipt before changing the service.
func RestartForSource(ctx context.Context, t config.Target, sha string, o Options) (Receipt, error) {
	s, err := VerifySource(ctx, t, sha, o)
	if err != nil {
		return Receipt{}, err
	}
	if s.SourceMatches {
		return Receipt{TargetID: t.ID, Status: "already_visible"}, nil
	}
	if !s.SourceSingleFile {
		return Receipt{}, errors.New("container source differs unexpectedly; automatic owner restart requires a proved single-file bind")
	}
	p, err := Preview(ctx, t, "restart", false, o)
	if err != nil {
		return Receipt{}, err
	}
	guard := Request{SourcePath: t.ConfigSource.HostPath, CorePath: t.ConfigSource.CorePath, SourceSHA256: sha, SourceContainer: t.ConfigSource.Container}
	r, err := apply(ctx, t, "restart", false, p.Digest, o, &guard)
	if err != nil {
		return r, err
	}
	s, err = VerifySource(ctx, t, sha, o)
	if err != nil {
		return r, err
	}
	if !s.SourceMatches {
		return r, errors.New("restarted owner does not see the saved source; verify the receipt before retrying")
	}
	return r, nil
}
func newReceipt(o Options, r Receipt) (string, error) {
	root := o.StateDir
	if root == "" {
		root = os.Getenv("XDG_STATE_HOME")
		if !filepath.IsAbs(root) {
			h, e := os.UserHomeDir()
			if e != nil {
				return "", e
			}
			root = filepath.Join(h, ".local", "state")
		}
		root = filepath.Join(root, "lazyclash", "service-receipts")
	}
	if !filepath.IsAbs(root) {
		return "", errors.New("service receipt directory must be absolute")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("service receipt directory must be private and not a symlink")
	}
	path := filepath.Join(root, r.ID+".json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	raw, _ := json.MarshalIndent(r, "", "  ")
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	return path, err
}
func saveReceipt(path string, r Receipt) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("service receipt is absent or unsafe")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".service-receipt-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	raw, _ := json.MarshalIndent(r, "", "  ")
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	return os.Rename(f.Name(), path)
}

// ReviewedBind checks a fresh read-only plan against the explicitly reviewed digest.
func ReviewedBind(p Plan, expected string) error {
	if p.Action != "bind" || expected == "" || !strings.EqualFold(p.Digest, expected) {
		return errors.New("binding changed; review the current service bind preview")
	}
	return nil
}
