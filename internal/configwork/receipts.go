package configwork

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/daviddwlee84/lazyclash/internal/privatefs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/clientservice"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"go.yaml.in/yaml/v3"
)

func hashJSON(v any) string { b, _ := json.Marshal(v); return hash(b) }
func receiptDir(opts Options, id string, create bool) (string, error) {
	if len(id) != 32 {
		return "", errors.New("invalid config receipt ID")
	}
	if _, e := hex.DecodeString(id); e != nil {
		return "", errors.New("invalid config receipt ID")
	}
	root := opts.StateDir
	if root == "" {
		root = os.Getenv("XDG_STATE_HOME")
		if root == "" {
			home, e := os.UserHomeDir()
			if e != nil {
				return "", e
			}
			root = filepath.Join(home, ".local", "state")
		}
		root = filepath.Join(root, "lazyclash", "config-receipts")
	}
	if !filepath.IsAbs(root) {
		return "", errors.New("config receipt directory must be absolute")
	}
	dir := filepath.Join(root, id)
	if create {
		if e := os.MkdirAll(root, 0700); e != nil {
			return "", e
		}
		info, e := os.Lstat(root)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("receipt root is not an ordinary directory")
		}
		if e = os.Chmod(root, 0700); e != nil {
			return "", e
		}
		if e = os.Mkdir(dir, 0700); e != nil {
			return "", e
		}
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !privatefs.Private(dir) {
		return "", errors.New("receipt directory is absent or unsafe")
	}
	return dir, nil
}
func privateWrite(path string, data []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".config-receipt-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(f.Name(), path)
}
func saveReceipt(opts Options, r Receipt) error {
	dir, e := receiptDir(opts, r.ID, false)
	if e != nil {
		return e
	}
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	return privateWrite(filepath.Join(dir, "receipt.json"), b)
}
func loadReceipt(opts Options, id string) (Receipt, error) {
	var r Receipt
	dir, e := receiptDir(opts, id, false)
	if e != nil {
		return r, e
	}
	b, e := privateRead(filepath.Join(dir, "receipt.json"), 1<<20)
	if e != nil {
		return r, e
	}
	if json.Unmarshal(b, &r) != nil || r.ID != id {
		return r, errors.New("invalid config receipt")
	}
	return r, nil
}
func privateRead(path string, limit int64) ([]byte, error) {
	i, e := os.Lstat(path)
	if e != nil || !i.Mode().IsRegular() || !privatefs.Private(path) || i.Size() > limit {
		return nil, errors.New("private receipt file is absent or unsafe")
	}
	return os.ReadFile(path)
}
func Apply(ctx context.Context, t config.Target, req Request, expected string, opts Options) (Receipt, error) {
	if opts.ReadOnly {
		return Receipt{}, errors.New("source edits are disabled in read-only mode")
	}
	if len(expected) != 64 {
		return Receipt{}, errors.New("apply needs the digest from a fresh preview")
	}
	p, e := Preview(ctx, t, req, opts)
	if e != nil {
		return Receipt{}, e
	}
	if p.Digest != expected {
		return Receipt{}, errors.New("source/context changed; review a new preview")
	}
	if e = checkSourceFiles(ctx, t, p.source.guards, opts); e != nil {
		return Receipt{}, e
	}
	var id [16]byte
	if _, e = rand.Read(id[:]); e != nil {
		return Receipt{}, e
	}
	now := time.Now().UTC()
	r := Receipt{ID: hex.EncodeToString(id[:]), TargetID: t.ID, Binding: Binding(t), Owner: p.Owner, Kind: p.Kind, Name: p.Name, Status: "prepared", Changes: p.Changes, CreatedAt: now, UpdatedAt: now, Definitions: map[string]string{}, GroupSHA256: map[string]string{}}
	if p.source.dockerID != "" {
		r.OwnerIdentity = p.source.dockerID + ":" + p.source.dockerImage
	}
	for _, d := range p.expected {
		r.Definitions[d.Kind+"/"+d.Name] = semantic(d.Node)
	}
	if len(p.expected) == 1 {
		r.DefinitionSHA256 = semantic(p.expected[0].Node)
	}
	for _, g := range p.expectedGroups {
		r.GroupSHA256[g.Name] = semantic(g.Node)
	}
	dir, e := receiptDir(opts, r.ID, true)
	if e != nil {
		return Receipt{}, e
	}
	for i, ch := range p.Changes {
		if e = privateWrite(filepath.Join(dir, fmt.Sprintf("%d.before.yaml", i)), ch.before); e != nil {
			return Receipt{}, e
		}
		if e = privateWrite(filepath.Join(dir, fmt.Sprintf("%d.after.yaml", i)), ch.after); e != nil {
			return Receipt{}, e
		}
		r.Changes[i].Status = "unattempted"
	}
	if e = saveReceipt(opts, r); e != nil {
		return Receipt{}, e
	}
	guards := p.source.guards
	for i, ch := range p.Changes {
		f, err := writeSourceFile(ctx, t, ch.Path, ch.after, guards, opts)
		if err != nil {
			r.Changes[i].Status = "unknown"
			r.Status = "write_result_unknown"
			r.Message = "A source write was not confirmed; verify or restore this receipt before retrying."
			r.UpdatedAt = time.Now().UTC()
			_ = saveReceipt(opts, r)
			return r, fmt.Errorf("%w: %w", &core.Error{Kind: core.KindUnknownWrite, Operation: "write configuration source"}, err)
		}
		r.Changes[i].Status = "written"
		r.Changes[i].Fingerprint = f.Fingerprint
		guards = refreshGuard(guards, ch.Path, f.Fingerprint)
		if e = saveReceipt(opts, r); e != nil {
			return r, e
		}
	}
	r.SourceVerified = true
	if len(p.Changes) == 0 {
		return Verify(ctx, t, r.ID, opts)
	}
	if p.Owner == "verge" {
		r.Status = "persisted_pending_owner_reload"
		r.Message = "Reactivate this profile in Clash Verge, then verify. Local group overrides remain after subscription updates."
		r.UpdatedAt = time.Now().UTC()
		if e = saveReceipt(opts, r); e != nil {
			return r, e
		}
		if t.ManagedCoreID != "" && opts.ActivateOwner != nil {
			if e = opts.ActivateOwner(ctx, t); e != nil {
				return r, e
			}
			return Verify(ctx, t, r.ID, opts)
		}
		return r, nil
	}
	r.Status = "persisted_pending_apply"
	if e = saveReceipt(opts, r); e != nil {
		return r, e
	}
	restarted := false
	if p.Owner == "docker" {
		var sha string
		for _, change := range p.Changes {
			if change.Path == p.source.base {
				sha = change.AfterSHA256
			}
		}
		if sha != "" {
			restarted, e = activateDockerSource(ctx, t, p.source, sha, opts)
			if e != nil {
				r.Status = "persisted_pending_owner_reload"
				r.Message = "Source saved; container activation is pending or unconfirmed. Inspect the service and receipt before retrying."
				_ = saveReceipt(opts, r)
				if errors.Is(e, errDockerOwnerReload) {
					return r, nil
				}
				return r, e
			}
		}
	}
	e = applySourceOnce(ctx, t, p.source.applyPath, restarted, opts)
	if e != nil {
		r.Status = "runtime_result_unknown"
		r.Message = "Source saved; runtime apply is unknown. Do not retry before verification."
		_ = saveReceipt(opts, r)
		return r, e
	}
	return Verify(ctx, t, r.ID, opts)
}
func Verify(ctx context.Context, t config.Target, id string, opts Options) (Receipt, error) {
	r, e := loadReceipt(opts, id)
	if e != nil {
		return r, e
	}
	if r.Composite != nil {
		return verifyChangeSetReceipt(ctx, t, r, opts)
	}
	if r.Binding != Binding(t) {
		return r, errors.New("receipt belongs to a different source binding")
	}
	s, e := inspectWithOptions(ctx, t, opts)
	if e != nil {
		return r, e
	}
	if r.OwnerIdentity != "" && r.OwnerIdentity != s.dockerID+":"+s.dockerImage {
		return r, errors.New("Docker owner identity changed; receipt is not applicable")
	}
	r.SourceVerified = true
	for i, ch := range r.Changes {
		f, ok := s.files[ch.Path]
		if !ok {
			return r, errors.New("receipt file no longer belongs to source")
		}
		want := ch.AfterSHA256
		if r.Restored {
			want = ch.BeforeSHA256
		}
		if f.SHA256 != want {
			r.SourceVerified = false
		}
		if f.SHA256 == ch.AfterSHA256 {
			r.Changes[i].Status = "written"
		} else if f.SHA256 == ch.BeforeSHA256 {
			r.Changes[i].Status = "original"
		} else {
			r.Changes[i].Status = "changed"
		}
	}
	r.UpdatedAt = time.Now().UTC()
	r.GeneratedVerified = false
	r.RuntimeObserved = false
	if !r.SourceVerified {
		r.Status = "source_changed"
		r.Message = "Not all current source bytes match this receipt; inspect before applying or restoring."
		_ = saveReceipt(opts, r)
		return r, nil
	}
	if r.Owner == "docker" && s.dockerSourceSHA != s.files[s.base].SHA256 {
		r.GeneratedVerified = false
		r.RuntimeObserved = false
		r.Status = "persisted_pending_owner_reload"
		r.Message = "Container-visible source differs from the saved host source; reactivate its owner before verification."
		return r, saveReceipt(opts, r)
	}
	if r.Owner == "docker" && t.Service != nil {
		status, err := clientservice.VerifySource(ctx, t, s.files[s.base].SHA256, opts.ClientServices)
		if err != nil {
			return r, err
		}
		if !status.SourceMatches {
			r.SourceVerified = true
			r.GeneratedVerified = false
			r.RuntimeObserved = false
			r.Status = "persisted_pending_owner_reload"
			r.Message = "Host source and container-visible bytes differ; activate the bound owner before verification."
			return r, saveReceipt(opts, r)
		}
	}
	if r.Restored {
		if len(r.Changes) == 0 {
			markNoChangeRestore(&r)
			return r, saveReceipt(opts, r)
		}
		r.Status = "restored_pending_verification"
		r.Message = "Original source bytes restored. Check the owner/runtime and test traffic."
		return r, saveReceipt(opts, r)
	}
	generated := s.effective()
	if r.Owner == "verge" {
		file, err := readSourceFile(ctx, t, s.runtime, opts)
		if err != nil {
			r.Status = "persisted_pending_owner_reload"
			r.Message = "Generated Verge runtime is not readable yet."
			_ = saveReceipt(opts, r)
			return r, nil
		}
		generated, e = decode(file.Data)
		if e != nil {
			return r, e
		}
	}
	ps, e := proxyDefinitions(generated, "")
	if e != nil {
		return r, e
	}
	gs, e := definitions(generated, "proxy-groups", "group", "")
	if e != nil {
		return r, e
	}
	r.GeneratedVerified = true
	for key, want := range r.Definitions {
		found := false
		for _, d := range append(ps, gs...) {
			if key == d.Kind+"/"+d.Name {
				found = true
				if semantic(d.Node) != want {
					r.GeneratedVerified = false
				}
			}
		}
		if !found {
			r.GeneratedVerified = false
		}
	}
	for name, want := range r.GroupSHA256 {
		g, ok := find(gs, name)
		if !ok || semantic(g.Node) != want {
			r.GeneratedVerified = false
		}
	}
	if !r.GeneratedVerified {
		r.Status = "owner_result_not_observed"
		r.Message = "Persisted edit is absent or overridden in the owner-generated configuration."
		return r, saveReceipt(opts, r)
	}
	c, close, e := open(ctx, t, true, opts)
	if e != nil {
		r.Status = "runtime_unavailable"
		_ = saveReceipt(opts, r)
		return r, e
	}
	defer close()
	runtime, e := c.Proxies(ctx)
	if e != nil {
		return r, e
	}
	r.RuntimeObserved = true
	for _, d := range append(ps, gs...) {
		if _, needed := r.Definitions[d.Kind+"/"+d.Name]; needed {
			p, ok := runtime[d.Name]
			if !ok || runtimeType(p.Type) != runtimeType(d.Type) {
				r.RuntimeObserved = false
			}
			if d.Kind == "group" {
				members := get(d.Node, "proxies")
				for _, member := range membersContent(members) {
					found := false
					for _, v := range p.All {
						if v == member.Value {
							found = true
						}
					}
					if !found {
						r.RuntimeObserved = false
					}
				}
			}
		}
	}
	for _, g := range gs {
		if _, needed := r.GroupSHA256[g.Name]; !needed {
			continue
		}
		observed, exists := runtime[g.Name]
		if !exists || runtimeType(observed.Type) != runtimeType(g.Type) {
			r.RuntimeObserved = false
			continue
		}
		for _, member := range membersContent(get(g.Node, "proxies")) {
			found := false
			for _, name := range observed.All {
				if member.Value == name {
					found = true
				}
			}
			if !found {
				r.RuntimeObserved = false
			}
		}
	}
	r.Status = "source_and_structure_verified"
	r.Message = "Source/generated definitions and runtime names were observed. The API does not expose credentials; test actual traffic separately."
	if !r.RuntimeObserved {
		r.Status = "runtime_structure_not_observed"
		r.Message = "Persisted/generated definitions match, but runtime structure has not been observed."
	}
	return r, saveReceipt(opts, r)
}
func runtimeType(value string) string {
	value = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(value, "-", ""), "_", ""))
	switch value {
	case "ss":
		return "shadowsocks"
	case "ssr":
		return "shadowsocksr"
	case "selector":
		return "select"
	}
	return value
}
func membersContent(n *yaml.Node) []*yaml.Node {
	if n != nil {
		return n.Content
	}
	return nil
}
func Restore(ctx context.Context, t config.Target, id string, opts Options) (Receipt, error) {
	if opts.ReadOnly {
		return Receipt{}, errors.New("restore is disabled in read-only mode")
	}
	r, e := loadReceipt(opts, id)
	if e != nil {
		return r, e
	}
	if r.Composite != nil {
		return restoreChangeSetReceipt(ctx, t, r, opts)
	}
	if r.Binding != Binding(t) {
		return r, errors.New("receipt belongs to a different source binding")
	}
	if r.Restored {
		return Verify(ctx, t, id, opts)
	}
	s, e := inspectWithOptions(ctx, t, opts)
	if e != nil {
		return r, e
	}
	if r.OwnerIdentity != "" && r.OwnerIdentity != s.dockerID+":"+s.dockerImage {
		return r, errors.New("Docker owner identity changed; receipt is not applicable")
	}
	if len(r.Changes) == 0 {
		r.Restored = true
		markNoChangeRestore(&r)
		return r, saveReceipt(opts, r)
	}
	dir, e := receiptDir(opts, id, false)
	if e != nil {
		return r, e
	}
	before := map[string][]byte{}
	for i, ch := range r.Changes {
		f, ok := s.files[ch.Path]
		if !ok {
			return r, errors.New("receipt file is no longer owned")
		}
		if f.SHA256 != ch.AfterSHA256 && f.SHA256 != ch.BeforeSHA256 {
			return r, errors.New("source was edited after this receipt; restore refused")
		}
		raw, err := privateRead(filepath.Join(dir, fmt.Sprintf("%d.before.yaml", i)), MaxDocument)
		if err != nil {
			return r, err
		}
		if hash(raw) != ch.BeforeSHA256 {
			return r, errors.New("backup hash mismatch")
		}
		before[ch.Path] = raw
	}
	if r.Owner != "verge" && len(r.Changes) > 0 {
		n, e := decode(before[s.base])
		if e != nil {
			return r, e
		}
		s.docs[s.base] = n
		c, close, e := open(ctx, t, true, opts)
		if e != nil {
			return r, e
		}
		v, e := c.Version(ctx)
		close()
		if e != nil {
			return r, e
		}
		version, _ := v["version"].(string)
		if e = validate(ctx, t, Plan{source: s, CoreVersion: version}, opts); e != nil {
			return r, e
		}
	}
	r.Status = "restore_prepared"
	if e = saveReceipt(opts, r); e != nil {
		return r, e
	}
	guards := s.guards
	for i := len(r.Changes) - 1; i >= 0; i-- {
		ch := r.Changes[i]
		if s.files[ch.Path].SHA256 == ch.BeforeSHA256 {
			continue
		}
		f, err := writeSourceFile(ctx, t, ch.Path, before[ch.Path], guards, opts)
		if err != nil {
			r.Status = "restore_result_unknown"
			r.Message = "Restore result is unknown; inspect this receipt."
			_ = saveReceipt(opts, r)
			return r, err
		}
		guards = refreshGuard(guards, ch.Path, f.Fingerprint)
		r.Changes[i].Status = "restored"
		if e = saveReceipt(opts, r); e != nil {
			return r, e
		}
	}
	r.Restored = true
	r.SourceVerified = true
	r.GeneratedVerified = false
	r.RuntimeObserved = false
	r.UpdatedAt = time.Now().UTC()
	r.Status = "restored_pending_owner_reload"
	r.Message = "Source backups restored; reactivate the owner and verify actual traffic."
	if e = saveReceipt(opts, r); e != nil {
		return r, e
	}
	if r.Owner == "verge" && t.ManagedCoreID != "" && opts.ActivateOwner != nil {
		if e = opts.ActivateOwner(ctx, t); e != nil {
			return r, e
		}
		return Verify(ctx, t, r.ID, opts)
	}
	if r.Owner != "verge" {
		restarted := false
		if r.Owner == "docker" {
			sha := s.files[s.base].SHA256
			for _, change := range r.Changes {
				if change.Path == s.base {
					sha = change.BeforeSHA256
				}
			}
			restarted, e = activateDockerSource(ctx, t, s, sha, opts)
			if e != nil {
				_ = saveReceipt(opts, r)
				if errors.Is(e, errDockerOwnerReload) {
					return r, nil
				}
				return r, e
			}
		}
		if e = applySourceOnce(ctx, t, s.applyPath, restarted, opts); e != nil {
			r.Status = "restore_runtime_result_unknown"
			_ = saveReceipt(opts, r)
			return r, e
		}
		r.Status = "restored_runtime_apply_confirmed"
	}
	return r, saveReceipt(opts, r)
}

var errDockerOwnerReload = errors.New("container-visible configuration needs owner reactivation")

// activateDockerSource never sends an API reload against a stale single-file
// mount. Without a separately bound service, it leaves activation to the owner.
func activateDockerSource(ctx context.Context, t config.Target, s *source, sha string, opts Options) (bool, error) {
	if opts.ReadOnly {
		return false, errors.New("owner activation is disabled in read-only mode")
	}
	if t.Service != nil {
		receipt, err := clientservice.RestartForSource(ctx, t, sha, opts.ClientServices)
		return receipt.ID != "", err
	}
	visible, err := dockerSourceOperation(ctx, t, "inspect", nil, "", opts)
	if err != nil {
		return false, err
	}
	if visible.ContainerID != s.dockerID || visible.Image != s.dockerImage {
		return false, errors.New("Docker owner changed before runtime activation")
	}
	if visible.SourceSHA256 != sha {
		return false, errDockerOwnerReload
	}
	return false, nil
}

// Readiness is retried only for a service that was just restarted. The PUT is
// issued once: a failed or timed-out write has an unknown result, never a retry.
func applySourceOnce(ctx context.Context, t config.Target, path string, waitReady bool, opts Options) error {
	if waitReady {
		readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		for {
			c, close, err := open(readyCtx, t, true, opts)
			if err == nil {
				_, err = c.Version(readyCtx)
				close()
			}
			if err == nil {
				break
			}
			select {
			case <-readyCtx.Done():
				return fmt.Errorf("restarted controller readiness was not observed: %w", readyCtx.Err())
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	c, close, err := open(ctx, t, false, opts)
	if err != nil {
		return err
	}
	defer close()
	_, err = c.ApplyConfig(ctx, path)
	return err
}

// Adoption receipts establish provenance without owning a source edit. Undoing
// that bookkeeping must not reload startup settings or remove an existing node.
func markNoChangeRestore(r *Receipt) {
	r.SourceVerified = false
	r.GeneratedVerified = false
	r.RuntimeObserved = false
	r.Status = "restored_no_changes"
	r.Message = "This receipt only linked existing definitions; no source bytes or runtime settings were changed."
	r.UpdatedAt = time.Now().UTC()
}
