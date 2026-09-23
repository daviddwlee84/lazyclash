package rulework

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/hostpath"
)

type windowsRuleFixture struct {
	*fixture
	files          map[string]HostFile
	calls          []HostRequest
	activations    int
	failActivation bool
}

func newWindowsRuleFixture(t *testing.T) *windowsRuleFixture {
	t.Helper()
	f := &windowsRuleFixture{fixture: newFixture(t, true), files: map[string]HostFile{}}
	f.target.HostOS = "windows"
	f.target.ManagedCoreID = "owned-windows"
	f.target.SSHHost = "windows-fixture-must-not-contact"
	f.target.RuleSource.DataDir = `C:\Owned Verge`
	f.put(`C:/Owned Verge/profiles.yaml`, []byte("current: chosen\nitems:\n  - uid: chosen\n    type: local\n    option: {rules: owned-rules}\n  - uid: owned-rules\n    type: rules\n    file: owned.yaml\n  - uid: Merge\n    type: merge\n    file: merge.yaml\n"))
	f.put(`C:/Owned Verge/profiles/owned.yaml`, f.source)
	f.put(`C:/Owned Verge/profiles/merge.yaml`, []byte("# Native empty Merge\n"))
	f.opts.Open = func(_ context.Context, target config.Target, readOnly bool) (*core.Client, io.Closer, error) {
		c, err := core.New(core.Options{Endpoint: target.Controller, ReadOnly: readOnly})
		return c, nil, err
	}
	f.opts.Host = func(_ context.Context, target config.Target, request HostRequest) (HostFile, error) {
		if target.HostOS != "windows" || target.SSHHost != f.target.SSHHost {
			return HostFile{}, errors.New("fixture host identity changed")
		}
		f.calls = append(f.calls, request)
		guard := func() error {
			for _, g := range request.Guards {
				file, found := f.files[windowsRuleKey(g.Path)]
				if !found || file.Fingerprint != g.Fingerprint {
					return errors.New("fixture source guard changed")
				}
			}
			return nil
		}
		switch request.Op {
		case "read":
			file, found := f.files[windowsRuleKey(request.Path)]
			if !found {
				return HostFile{}, fmt.Errorf("unexpected fixture read: %s", request.Path)
			}
			file.Data = append([]byte(nil), file.Data...)
			return file, nil
		case "check":
			return HostFile{}, guard()
		case "write":
			if len(request.Guards) == 0 {
				return HostFile{}, errors.New("unguarded fixture write")
			}
			if err := guard(); err != nil {
				return HostFile{}, err
			}
			f.put(request.Path, request.Data)
			return f.files[windowsRuleKey(request.Path)], nil
		case "validate":
			if request.Binary != `C:\Apps\mihomo.exe` || request.Home != `C:\Apps\home` || request.Version != "v1.19.29" || request.Document == nil {
				return HostFile{}, errors.New("Windows validation lost bound binary/home/version/document")
			}
			return HostFile{}, nil
		}
		return HostFile{}, errors.New("unexpected fixture host operation")
	}
	f.opts.ActivateOwner = func(_ context.Context, target config.Target) error {
		f.activations++
		if target.ManagedCoreID != "owned-windows" {
			return errors.New("unowned fixture activation")
		}
		entries, err := os.ReadDir(f.opts.StateDir)
		if err != nil || len(entries) != 1 {
			return errors.New("activation ran before its durable receipt")
		}
		r, err := loadReceipt(f.opts, entries[0].Name())
		if err != nil {
			return err
		}
		want := "persisted_pending_owner_reload"
		if r.Restored {
			want = "restored_pending_owner_reload"
		}
		if r.Status != want {
			return fmt.Errorf("activation preceded pending state: %s", r.Status)
		}
		if f.failActivation {
			return errors.New("fixture owner activation failed")
		}
		file := f.files[windowsRuleKey(`C:/Owned Verge/profiles/owned.yaml`)]
		doc, err := decodeYAML(file.Data)
		if err != nil {
			return err
		}
		var rules []map[string]any
		for _, item := range mappingValue(doc.Content[0], "prepend").Content {
			parts := strings.Split(item.Value, ",")
			kind := "Domain"
			if parts[0] == "IP-CIDR" || parts[0] == "IP-CIDR6" {
				kind = "IPCIDR"
			}
			rules = append(rules, map[string]any{"type": kind, "payload": parts[1], "proxy": parts[2]})
		}
		rules = append(rules, map[string]any{"type": "Match", "payload": "", "proxy": "DIRECT"})
		f.mu.Lock()
		f.rules = rules
		f.mu.Unlock()
		return nil
	}
	return f
}

func windowsRuleKey(path string) string { return strings.ToLower(hostpath.Clean("windows", path)) }
func (f *windowsRuleFixture) put(path string, data []byte) {
	path = hostpath.Clean("windows", path)
	f.files[windowsRuleKey(path)] = HostFile{Path: path, Resolved: path, Data: append([]byte(nil), data...), SHA256: sha(data), Fingerprint: sha(append([]byte(windowsRuleKey(path)), data...)), Mode: 0600}
}

func TestOwnedWindowsRuleHooksApplyActivateVerifyAndRestore(t *testing.T) {
	f := newWindowsRuleFixture(t)
	ctx := context.Background()
	source, err := InspectSourceWithOptions(ctx, f.target, f.opts)
	if err != nil || source.File != "C:/Owned Verge/profiles/owned.yaml" {
		t.Fatalf("Windows source paths: %+v %v", source, err)
	}
	plan, err := PreviewIP(ctx, f.target, "192.0.2.1", "DIRECT", f.opts)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ApplyIP(ctx, f.target, "192.0.2.1", "DIRECT", plan.Digest, f.opts)
	if err != nil || r.Status != "applied_verified" || !r.RuntimeVerified || f.activations != 1 || f.writes != 0 {
		t.Fatalf("owned activation: %+v %v, activations=%d API writes=%d", r, err, f.activations, f.writes)
	}
	read, check, write := false, false, false
	for _, call := range f.calls {
		switch call.Op {
		case "read":
			read = true
		case "check":
			check = true
		case "write":
			write = true
		}
		if call.Path != "" && !hostpath.IsAbs("windows", call.Path) {
			t.Fatal("core host path interpreted on controller OS", call.Path)
		}
	}
	if !read || !check || !write {
		t.Fatal("host hook did not own every source operation", f.calls)
	}
	r, err = Restore(ctx, f.target, r.ID, f.opts)
	if err != nil || r.Status != "restored_verified" || !r.RuntimeVerified || f.activations != 2 || f.writes != 0 {
		t.Fatalf("owned restore activation: %+v %v", r, err)
	}
	if string(f.files[windowsRuleKey(r.File)].Data) != string(f.source) {
		t.Fatal("Windows restore lost exact original bytes")
	}
}

func TestWindowsRuleActivationFailureRetainsDurablePendingReceipt(t *testing.T) {
	f := newWindowsRuleFixture(t)
	f.failActivation = true
	ctx := context.Background()
	plan, err := Preview(ctx, f.target, "example.com", "PROXY", f.opts)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Apply(ctx, f.target, "example.com", "PROXY", plan.Digest, f.opts)
	if err == nil || r.ID == "" || r.Status != "persisted_pending_owner_reload" || f.activations != 1 {
		t.Fatalf("activation failure lost saved state: %+v %v", r, err)
	}
	saved, err := loadReceipt(f.opts, r.ID)
	if err != nil || saved.Status != r.Status || saved.AfterFingerprint == "" {
		t.Fatal("pending apply receipt missing", saved, err)
	}
	if !strings.Contains(string(f.files[windowsRuleKey(r.File)].Data), "DOMAIN,example.com,PROXY") {
		t.Fatal("activation failure hid persistent source write")
	}
	if _, err = Verify(ctx, f.target, r.ID, f.opts); err != nil || f.activations != 1 {
		t.Fatal("verify retried owner activation", err)
	}
	r, err = Restore(ctx, f.target, r.ID, f.opts)
	if err == nil || !r.Restored || r.Status != "restored_pending_owner_reload" || f.activations != 2 {
		t.Fatalf("activation failure lost restored state: %+v %v", r, err)
	}
	saved, err = loadReceipt(f.opts, r.ID)
	if err != nil || !saved.Restored || saved.RestoredFingerprint == "" {
		t.Fatal("pending restore receipt missing", saved, err)
	}
	if string(f.files[windowsRuleKey(r.File)].Data) != string(f.source) {
		t.Fatal("restore failed to preserve original bytes before activation")
	}
}

func TestForeignWindowsRuleOwnerRemainsPendingWithoutAutomaticActivation(t *testing.T) {
	f := newWindowsRuleFixture(t)
	f.target.ManagedCoreID = ""
	ctx := context.Background()
	plan, err := Preview(ctx, f.target, "example.com", "PROXY", f.opts)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Apply(ctx, f.target, "example.com", "PROXY", plan.Digest, f.opts)
	if err != nil || r.Status != "persisted_pending_owner_reload" || f.activations != 0 {
		t.Fatal("foreign owner was activated", r, err)
	}
	if _, err = Restore(ctx, f.target, r.ID, f.opts); err != nil || f.activations != 0 {
		t.Fatal("foreign restore activated owner", err)
	}
}

func TestWindowsNativeValidationUsesOwnerProtocolInsteadOfLocalPython(t *testing.T) {
	f := newWindowsRuleFixture(t)
	f.target.RuleSource = &config.RuleSource{Kind: "mihomo", ConfigID: "main", Binary: `C:\Apps\mihomo.exe`, Home: `C:\Apps\home`}
	f.target.Configs = []config.CoreConfig{{ID: "main", Path: `C:\Apps\home\config.yaml`}}
	f.put(`C:\Apps\home\config.yaml`, []byte("rules: [MATCH,DIRECT]\n"))
	f.opts.Validate = func(context.Context, config.Target, []byte, string) error {
		t.Fatal("fixture validator bypassed the supplied owner protocol")
		return nil
	}
	if _, err := InspectSourceWithOptions(context.Background(), f.target, f.opts); err != nil {
		t.Fatal(err)
	}
	if err := validateCandidate(context.Background(), f.target, []byte("rules: [MATCH,DIRECT]\n"), "v1.19.29", f.opts); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 || f.calls[0].Op != "read" || f.calls[1].Op != "validate" {
		t.Fatal("native Windows source escaped the host callback", f.calls)
	}
	if _, err := InspectSource(context.Background(), f.target); err == nil || !strings.Contains(err.Error(), "owner host adapter") {
		t.Fatal("Windows source silently fell back to POSIX Python", err)
	}
}

func TestWindowsCompanionPathsRejectEscapesAndAcceptResolvedCaseVariants(t *testing.T) {
	for _, file := range []string{`..\outside.yaml`, `C:\outside.yaml`, `C:outside.yaml`, `\outside.yaml`, `/outside.yaml`, `\\server\share\outside.yaml`, `rules.yaml:stream`} {
		if path, err := companionPathForOS("windows", `C:\Owned Verge`, file); err == nil {
			t.Fatalf("unsafe companion %q became %q", file, path)
		}
	}
	path, err := companionPathForOS("windows", `C:\Owned Verge`, `nested\rules.yaml`)
	if err != nil || path != "C:/Owned Verge/profiles/nested/rules.yaml" {
		t.Fatal("safe Windows companion rejected", path, err)
	}
	f := newWindowsRuleFixture(t)
	key := windowsRuleKey(`C:/Owned Verge/profiles/owned.yaml`)
	file := f.files[key]
	file.Resolved = `c:\OWNED VERGE\PROFILES\OWNED.YAML`
	f.files[key] = file
	if _, err := InspectSourceWithOptions(context.Background(), f.target, f.opts); err != nil {
		t.Fatal("Windows path case was compared using POSIX rules", err)
	}
	file.Resolved = `D:\Outside\owned.yaml`
	f.files[key] = file
	if _, err := InspectSourceWithOptions(context.Background(), f.target, f.opts); err == nil {
		t.Fatal("resolved companion outside its owner volume accepted")
	}
}

func TestRuleBindingHostOSPreservesLegacyEmptyBinding(t *testing.T) {
	f := newFixture(t, false)
	legacy, _ := json.Marshal(struct {
		ID, Controller, SSH string
		ManagedRPi          *config.ManagedRPi `json:",omitempty"`
		Source              *config.RuleSource
		ConfigPath          string
	}{f.target.ID, f.target.Controller, f.target.SSHHost, f.target.ManagedRPi, f.target.RuleSource, f.target.Configs[0].Path})
	if binding(f.target) != sha(legacy) {
		t.Fatal("empty host OS invalidated existing receipt bindings")
	}
	f.target.HostOS = "linux"
	if binding(f.target) == sha(legacy) {
		t.Fatal("explicit host OS was not bound into the receipt digest")
	}
}

func TestWindowsRulePreviewPinsManagedOwnerWithoutChangingUnixBindings(t *testing.T) {
	f := newWindowsRuleFixture(t)
	ctx := context.Background()
	plan, err := Preview(ctx, f.target, "example.com", "PROXY", f.opts)
	if err != nil {
		t.Fatal(err)
	}
	f.target.ManagedCoreID = "different-windows-owner"
	if _, err = Apply(ctx, f.target, "example.com", "PROXY", plan.Digest, f.opts); err == nil || !strings.Contains(err.Error(), "preview changed") {
		t.Fatal("owner change replayed a reviewed write", err)
	}
	if f.activations != 0 || string(f.files[windowsRuleKey(plan.Owner.File)].Data) != string(f.source) {
		t.Fatal("owner mismatch changed source or activated a GUI")
	}
	unix := newFixture(t, false)
	before := binding(unix.target)
	unix.target.ManagedCoreID = "existing-unix-owner"
	if binding(unix.target) != before {
		t.Fatal("Windows ownership extension changed a pre-existing Unix receipt binding")
	}
}
