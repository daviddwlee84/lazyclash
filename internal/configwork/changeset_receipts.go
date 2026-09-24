package configwork

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/hostpath"
	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"go.yaml.in/yaml/v3"
)

func ApplyChangeSet(ctx context.Context, from, to config.Target, selection StructuralSelection, expected string, opts Options) (ChangeSetReceipt, error) {
	if opts.ReadOnly {
		return Receipt{}, errors.New("configuration synchronization is disabled in read-only mode")
	}
	if len(expected) != 64 {
		return Receipt{}, errors.New("configuration synchronization requires a fresh preview digest")
	}
	p, err := PreviewChangeSet(ctx, from, to, selection, opts)
	if err != nil {
		return Receipt{}, err
	}
	if p.Digest != expected {
		return Receipt{}, errors.New("source, destination, resources or selection changed; review a new preview")
	}
	if p.Status == "no_changes" {
		return Receipt{TargetID: to.ID, Status: "no_changes"}, nil
	}
	t, err := changeSetTarget(to)
	if err != nil {
		return Receipt{}, err
	}
	if err = checkSourceFiles(ctx, t, p.source.guards, opts); err != nil {
		return Receipt{}, err
	}
	fromOwner, err := changeSetTarget(from)
	if err != nil {
		return Receipt{}, err
	}
	if err = checkSourceFiles(ctx, fromOwner, p.Composition.SourceSnapshot.source.guards, opts); err != nil {
		return Receipt{}, fmt.Errorf("source changed during validation: %w", err)
	}
	for _, resource := range p.Resources {
		file, e := ReadProviderResource(ctx, fromOwner, p.Composition.SourceSnapshot.source, resource.sourceObject, opts)
		if e != nil {
			return Receipt{}, e
		}
		if file.SHA256 != resource.sourceSHA256 {
			return Receipt{}, errors.New("source provider snapshot changed during validation; review a new plan")
		}
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return Receipt{}, err
	}
	now := time.Now().UTC()
	record := &ChangeSetRecord{Version: 1, RuleBinding: p.ruleBinding, Resources: p.Resources, ExpectedSections: changeSetDocumentSections(p.Composition.Root, changeSetSections(p.Composition)), SourceTargetID: from.ID}
	r := Receipt{ID: hex.EncodeToString(id[:]), TargetID: to.ID, Binding: Binding(to), Owner: p.Owner, Kind: "changeset", Name: "selected configuration objects", Status: "prepared", Changes: p.Changes, CreatedAt: now, UpdatedAt: now, Composite: record, Definitions: map[string]string{}}
	if p.source.dockerID != "" {
		r.OwnerIdentity = p.source.dockerID + ":" + p.source.dockerImage
	}
	for _, d := range p.Composition.Definitions {
		r.Definitions[d.Kind+"/"+d.Name] = semantic(d.Node)
	}
	dir, err := receiptDir(opts, r.ID, true)
	if err != nil {
		return Receipt{}, err
	}
	for i, ch := range p.Changes {
		if err = privateWrite(filepath.Join(dir, fmt.Sprintf("%d.before.yaml", i)), ch.before); err != nil {
			return Receipt{}, err
		}
		if err = privateWrite(filepath.Join(dir, fmt.Sprintf("%d.after.yaml", i)), ch.after); err != nil {
			return Receipt{}, err
		}
		r.Changes[i].Status = "unattempted"
	}
	if err = privateWrite(filepath.Join(dir, "effective.after.yaml"), p.effective); err != nil {
		return Receipt{}, err
	}
	beforeRoot, err := changeSetEffective(p.Composition.DestinationSnapshot.source)
	if err != nil {
		return Receipt{}, err
	}
	before, err := encode(beforeRoot)
	if err != nil {
		return Receipt{}, err
	}
	if err = privateWrite(filepath.Join(dir, "effective.before.yaml"), before); err != nil {
		return Receipt{}, err
	}
	for i, res := range p.Resources {
		if err = privateWrite(filepath.Join(dir, fmt.Sprintf("resource.%d.seed", i)), res.data); err != nil {
			return Receipt{}, err
		}
	}
	if err = saveReceipt(opts, r); err != nil {
		return Receipt{}, err
	}
	for i, res := range p.Resources {
		written, e := hostOperation(ctx, t, HostRequest{Op: "resource-write", Path: res.Path, ResourceRoot: res.root, ExpectedSHA256: res.SHA256, Data: res.data}, opts)
		if e != nil {
			r.Composite.Resources[i].Status = "unknown"
			r.Status = "resource_result_unknown"
			r.Message = "Provider resource creation was not confirmed; inspect the receipt before retrying."
			_ = saveReceipt(opts, r)
			return r, fmt.Errorf("%w: %w", &core.Error{Kind: core.KindUnknownWrite, Operation: "create provider resource"}, e)
		}
		r.Composite.Resources[i].Created = written.Created
		r.Composite.Resources[i].Status = "written"
		if err = saveReceipt(opts, r); err != nil {
			return r, err
		}
	}
	guards := p.source.guards
	for i, ch := range p.Changes {
		f, e := writeSourceFile(ctx, t, ch.Path, ch.after, guards, opts)
		if e != nil {
			r.Changes[i].Status = "unknown"
			r.Status = "write_result_unknown"
			r.Message = "A configuration write was not confirmed; inspect or restore this receipt before retrying."
			_ = saveReceipt(opts, r)
			return r, fmt.Errorf("%w: %w", &core.Error{Kind: core.KindUnknownWrite, Operation: "write composed configuration"}, e)
		}
		r.Changes[i].Status = "written"
		r.Changes[i].Fingerprint = f.Fingerprint
		guards = refreshGuard(guards, ch.Path, f.Fingerprint)
		if err = saveReceipt(opts, r); err != nil {
			return r, err
		}
	}
	r.SourceVerified = true
	r.Status = "persisted_pending_owner_reload"
	if err = saveReceipt(opts, r); err != nil {
		return r, err
	}
	if p.Owner == "verge" {
		r.Message = "Selected profile companions saved; activate the profile in its native owner, then configs verify this receipt."
		if err = saveReceipt(opts, r); err != nil {
			return r, err
		}
		if t.ManagedCoreID == "" || opts.ActivateOwner == nil {
			return r, nil
		}
		if err = opts.ActivateOwner(ctx, t); err != nil {
			return r, err
		}
	} else {
		restarted := false
		if p.Owner == "docker" {
			sum := p.source.files[p.source.base].SHA256
			for _, ch := range p.Changes {
				if ch.Path == p.source.base {
					sum = ch.AfterSHA256
				}
			}
			restarted, err = activateDockerSource(ctx, t, p.source, sum, opts)
			if errors.Is(err, errDockerOwnerReload) {
				r.Message = "Host source saved; container owner must remount the configuration before verification."
				_ = saveReceipt(opts, r)
				return r, nil
			}
		}
		if err == nil {
			err = applySourceOnce(ctx, t, p.source.applyPath, restarted, opts)
		}
		if err != nil {
			r.Status = "runtime_result_unknown"
			r.Message = "Source saved; owner activation or reload was not confirmed. Inspect before retrying."
			_ = saveReceipt(opts, r)
			return r, err
		}
	}
	return verifyChangeSetReceipt(ctx, to, r, opts)
}

func VerifyChangeSet(ctx context.Context, t config.Target, id string, opts Options) (ChangeSetReceipt, error) {
	r, err := loadReceipt(opts, id)
	if err != nil {
		return r, err
	}
	if r.Composite == nil {
		return r, errors.New("receipt is not a configuration changeset")
	}
	return verifyChangeSetReceipt(ctx, t, r, opts)
}

func verifyChangeSetReceipt(ctx context.Context, original config.Target, r Receipt, opts Options) (Receipt, error) {
	if r.Binding != Binding(original) || r.TargetID != original.ID {
		return r, errors.New("changeset receipt belongs to a different target or configuration binding")
	}
	if r.Composite.RuleBinding != "" && r.Composite.RuleBinding != hashJSON(original.RuleSource) {
		return r, errors.New("changeset rule owner binding changed")
	}
	t, err := changeSetTarget(original)
	if err != nil {
		return r, err
	}
	s, err := inspectWithOptions(ctx, t, opts)
	if err != nil {
		return r, err
	}
	if r.OwnerIdentity != "" && r.OwnerIdentity != s.dockerID+":"+s.dockerImage {
		return r, errors.New("changeset Docker owner identity changed")
	}
	r.SourceVerified = true
	r.GeneratedVerified = false
	r.RuntimeObserved = false
	r.UpdatedAt = time.Now().UTC()
	for i, ch := range r.Changes {
		f, ok := s.files[ch.Path]
		want := ch.AfterSHA256
		if r.Restored {
			want = ch.BeforeSHA256
		}
		if !ok || f.SHA256 != want {
			r.SourceVerified = false
		}
		if ok && f.SHA256 == ch.AfterSHA256 {
			r.Changes[i].Status = "written"
		} else if ok && f.SHA256 == ch.BeforeSHA256 {
			r.Changes[i].Status = "original"
		} else {
			r.Changes[i].Status = "changed"
		}
	}
	for i, res := range r.Composite.Resources {
		if r.Restored && res.Created {
			continue
		}
		observed, e := hostOperation(ctx, t, HostRequest{Op: "resource-inspect", Path: res.Path, ResourceRoot: hostpath.Dir(t.HostOS, res.Path)}, opts)
		if e != nil || !observed.Exists {
			r.SourceVerified = false
			r.Composite.Resources[i].Status = "unavailable"
			continue
		}
		if !res.Mutable && observed.File.SHA256 != res.SHA256 {
			r.SourceVerified = false
			r.Composite.Resources[i].Status = "changed"
		} else if res.Mutable && observed.File.SHA256 != res.SHA256 {
			r.Composite.Resources[i].Status = "cache_evolved"
		}
	}
	if !r.SourceVerified {
		r.Status = "source_changed"
		r.Message = "Not every guarded configuration/resource matches the receipt; inspect before retrying."
		_ = saveReceipt(opts, r)
		return r, nil
	}
	if s.Kind == "docker" && s.dockerSourceSHA != s.files[s.base].SHA256 {
		r.Status = "persisted_pending_owner_reload"
		return r, saveReceipt(opts, r)
	}
	generated, err := changeSetEffective(s)
	if err != nil {
		return r, err
	}
	if s.Kind == "verge" {
		file, e := readSourceFile(ctx, t, s.runtime, opts)
		if e != nil {
			r.Status = "persisted_pending_owner_reload"
			return r, saveReceipt(opts, r)
		}
		generated, err = decode(file.Data)
		if err != nil {
			return r, err
		}
	}
	dir, err := receiptDir(opts, r.ID, false)
	if err != nil {
		return r, err
	}
	name := "effective.after.yaml"
	if r.Restored {
		name = "effective.before.yaml"
	}
	raw, err := privateRead(filepath.Join(dir, name), MaxDocument)
	if err != nil {
		return r, err
	}
	expected, err := decode(raw)
	if err != nil {
		return r, err
	}
	r.GeneratedVerified = true
	for section := range r.Composite.ExpectedSections {
		if semantic(get(expected, section)) != semantic(get(generated, section)) {
			r.GeneratedVerified = false
		}
	}
	if !r.GeneratedVerified {
		r.Status = "owner_result_not_observed"
		r.Message = "Owner-generated sections differ from the reviewed candidate."
		return r, saveReceipt(opts, r)
	}
	r.RuntimeObserved = true
	client, close, err := open(ctx, t, true, opts)
	if err != nil {
		r.Status = "runtime_unavailable"
		_ = saveReceipt(opts, r)
		return r, err
	}
	defer close()
	if _, needed := r.Composite.ExpectedSections["proxies"]; needed || r.Composite.ExpectedSections["proxy-groups"] != "" {
		proxies, e := client.Proxies(ctx)
		if e != nil {
			return r, e
		}
		for _, spec := range []struct{ section, kind string }{{"proxies", "proxy"}, {"proxy-groups", "group"}} {
			defs, e := definitions(expected, spec.section, spec.kind, "")
			if e != nil {
				return r, e
			}
			for _, d := range defs {
				observed, ok := proxies[d.Name]
				if !ok || runtimeType(observed.Type) != runtimeType(d.Type) {
					r.RuntimeObserved = false
					continue
				}
				if spec.kind == "group" && !runtimeGroupMembersMatch(d.Node, observed.All) {
					r.RuntimeObserved = false
				}
			}
		}
	}
	for _, spec := range []struct{ section, kind string }{{"proxy-providers", "proxies"}, {"rule-providers", "rules"}} {
		if _, needed := r.Composite.ExpectedSections[spec.section]; !needed {
			continue
		}
		object, e := client.Providers(ctx, spec.kind)
		if e != nil {
			return r, e
		}
		providers, _ := object["providers"].(map[string]any)
		if node := get(expected, spec.section); node != nil {
			for i := 0; i+1 < len(node.Content); i += 2 {
				if _, ok := providers[node.Content[i].Value]; !ok {
					r.RuntimeObserved = false
				}
			}
		}
	}
	if _, needed := r.Composite.ExpectedSections["rules"]; needed {
		snapshot, e := rulework.ReadRulesSnapshot(ctx, t, "runtime", rulework.Options{ReadOnly: true, Open: opts.Open})
		if e != nil {
			return r, e
		}
		entries := []rulecheck.Entry{}
		if rules := get(expected, "rules"); rules != nil {
			for i, n := range rules.Content {
				entries = append(entries, rulecheck.Entry{Section: "rules", Rule: rulecheck.ParseExisting(n.Value, i)})
			}
		}
		if snapshot.Runtime == nil || snapshot.Runtime.Status != "available" || !rulecheck.CompareEntries(entries, snapshot.Runtime.Entries, true).Equal {
			r.RuntimeObserved = false
		}
	}
	r.Status = "source_and_structure_verified"
	r.Message = "Selected source/generated sections and reported runtime structure were verified; credentials and live traffic are not exposed by the controller."
	if !r.RuntimeObserved {
		r.Status = "runtime_structure_not_observed"
	}
	if r.Restored && r.RuntimeObserved {
		r.Status = "restored_runtime_apply_confirmed"
	}
	return r, saveReceipt(opts, r)
}

func RestoreChangeSet(ctx context.Context, t config.Target, id string, opts Options) (ChangeSetReceipt, error) {
	r, err := loadReceipt(opts, id)
	if err != nil {
		return r, err
	}
	if r.Composite == nil {
		return r, errors.New("receipt is not a configuration changeset")
	}
	return restoreChangeSetReceipt(ctx, t, r, opts)
}

func restoreChangeSetReceipt(ctx context.Context, original config.Target, r Receipt, opts Options) (Receipt, error) {
	if opts.ReadOnly {
		return r, errors.New("restore is disabled in read-only mode")
	}
	if r.Binding != Binding(original) || r.TargetID != original.ID {
		return r, errors.New("changeset receipt belongs to a different target or configuration binding")
	}
	if r.Composite.RuleBinding != "" && r.Composite.RuleBinding != hashJSON(original.RuleSource) {
		return r, errors.New("changeset rule owner binding changed")
	}
	t, err := changeSetTarget(original)
	if err != nil {
		return r, err
	}
	if r.Restored {
		verified, e := verifyChangeSetReceipt(ctx, original, r, opts)
		if e == nil && verified.RuntimeObserved {
			return cleanupChangeSetResources(ctx, t, verified, opts)
		}
		return verified, e
	}
	s, err := inspectWithOptions(ctx, t, opts)
	if err != nil {
		return r, err
	}
	if r.OwnerIdentity != "" && r.OwnerIdentity != s.dockerID+":"+s.dockerImage {
		return r, errors.New("changeset Docker owner identity changed")
	}
	dir, err := receiptDir(opts, r.ID, false)
	if err != nil {
		return r, err
	}
	before := map[string][]byte{}
	candidate := cloneOwnerSource(s)
	for i, ch := range r.Changes {
		file, ok := s.files[ch.Path]
		if !ok || (file.SHA256 != ch.BeforeSHA256 && file.SHA256 != ch.AfterSHA256) {
			return r, errors.New("configuration changed after the receipt; restore refused")
		}
		data, e := privateRead(filepath.Join(dir, fmt.Sprintf("%d.before.yaml", i)), MaxDocument)
		if e != nil {
			return r, e
		}
		if hash(data) != ch.BeforeSHA256 {
			return r, errors.New("changeset backup hash mismatch")
		}
		before[ch.Path] = data
		node, e := decodeChangeSetFile(s, ch.Path, data)
		if e != nil {
			return r, e
		}
		candidate.docs[ch.Path] = node
	}
	root, err := changeSetEffective(candidate)
	if err != nil {
		return r, err
	}
	raw, err := encode(root)
	if err != nil {
		return r, err
	}
	client, close, err := open(ctx, t, true, opts)
	if err != nil {
		return r, err
	}
	version, e := client.Version(ctx)
	close()
	if e != nil {
		return r, e
	}
	v, _ := version["version"].(string)
	// Receipt-guarded rollback is allowed while a single-file mount still sees
	// the old bytes. Owner identity remains guarded by inspect/validation.
	candidate.dockerSourceSHA = candidate.files[candidate.base].SHA256
	if err = validateChangeSet(ctx, t, candidate, raw, v, nil, opts); err != nil {
		return r, err
	}
	r.Status = "restore_prepared"
	if err = saveReceipt(opts, r); err != nil {
		return r, err
	}
	guards := s.guards
	for i := len(r.Changes) - 1; i >= 0; i-- {
		ch := r.Changes[i]
		if s.files[ch.Path].SHA256 == ch.BeforeSHA256 {
			continue
		}
		file, e := writeSourceFile(ctx, t, ch.Path, before[ch.Path], guards, opts)
		if e != nil {
			r.Status = "restore_result_unknown"
			r.Message = "Configuration restore was not confirmed; inspect before retrying."
			_ = saveReceipt(opts, r)
			return r, e
		}
		guards = refreshGuard(guards, ch.Path, file.Fingerprint)
		r.Changes[i].Status = "restored"
		if err = saveReceipt(opts, r); err != nil {
			return r, err
		}
	}
	r.Restored = true
	r.Status = "restored_pending_owner_reload"
	r.SourceVerified = true
	r.GeneratedVerified = false
	r.RuntimeObserved = false
	if err = saveReceipt(opts, r); err != nil {
		return r, err
	}
	if s.Kind == "verge" {
		if t.ManagedCoreID == "" || opts.ActivateOwner == nil {
			return r, nil
		}
		err = opts.ActivateOwner(ctx, t)
	} else {
		restarted := false
		if s.Kind == "docker" {
			sum := s.files[s.base].SHA256
			for _, ch := range r.Changes {
				if ch.Path == s.base {
					sum = ch.BeforeSHA256
				}
			}
			restarted, err = activateDockerSource(ctx, t, s, sum, opts)
			if errors.Is(err, errDockerOwnerReload) {
				return r, nil
			}
		}
		if err == nil {
			err = applySourceOnce(ctx, t, s.applyPath, restarted, opts)
		}
	}
	if err != nil {
		r.Status = "restore_runtime_result_unknown"
		_ = saveReceipt(opts, r)
		return r, err
	}
	r, err = verifyChangeSetReceipt(ctx, original, r, opts)
	if err == nil && r.RuntimeObserved {
		return cleanupChangeSetResources(ctx, t, r, opts)
	}
	return r, err
}

func cleanupChangeSetResources(ctx context.Context, t config.Target, r Receipt, opts Options) (Receipt, error) {
	for i, res := range r.Composite.Resources {
		if !res.Created || res.Status == "removed" {
			continue
		}
		if res.Mutable {
			r.Composite.Resources[i].Status = "retained_cache"
			continue
		}
		if res.Status == "unknown" {
			r.Composite.Resources[i].Status = "retained_unknown"
			continue
		}
		observed, err := hostOperation(ctx, t, HostRequest{Op: "resource-inspect", Path: res.Path, ResourceRoot: hostpath.Dir(t.HostOS, res.Path)}, opts)
		if err != nil {
			return r, err
		}
		if !observed.Exists {
			r.Composite.Resources[i].Status = "removed"
			continue
		}
		if observed.File.SHA256 != res.SHA256 {
			r.Composite.Resources[i].Status = "retained_changed"
			continue
		}
		if _, err = hostOperation(ctx, t, HostRequest{Op: "resource-remove", Path: res.Path, ResourceRoot: hostpath.Dir(t.HostOS, res.Path), ExpectedSHA256: res.SHA256}, opts); err != nil {
			r.Composite.Resources[i].Status = "remove_result_unknown"
			_ = saveReceipt(opts, r)
			return r, err
		}
		r.Composite.Resources[i].Status = "removed"
		if err = saveReceipt(opts, r); err != nil {
			return r, err
		}
	}
	return r, saveReceipt(opts, r)
}

func runtimeGroupMembersMatch(node *yaml.Node, observed []string) bool {
	expected := []string{}
	for _, n := range membersContent(get(node, "proxies")) {
		expected = append(expected, n.Value)
	}
	dynamic := false
	if use := get(node, "use"); use != nil && len(use.Content) > 0 {
		dynamic = true
	}
	for _, key := range []string{"include-all", "include-all-proxies", "include-all-providers"} {
		if scalar(node, key) == "true" {
			dynamic = true
		}
	}
	if !dynamic {
		return slices.Equal(expected, observed)
	}
	at := 0
	for _, name := range observed {
		if at < len(expected) && name == expected[at] {
			at++
		}
	}
	return at == len(expected)
}
