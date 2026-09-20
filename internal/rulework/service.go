package rulework

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

func binding(target config.Target) string {
	configPath := ""
	if target.RuleSource != nil {
		for _, item := range target.Configs {
			if item.ID == target.RuleSource.ConfigID {
				configPath = item.Path
			}
		}
	}
	data, _ := json.Marshal(struct {
		ID, Controller, SSH string
		Source              *config.RuleSource
		ConfigPath          string
	}{target.ID, target.Controller, target.SSHHost, target.RuleSource, configPath})
	return sha(data)
}

func Preview(ctx context.Context, target config.Target, domain, policy string, opts Options) (Plan, error) {
	var plan Plan
	domain, err := NormalizeDomain(domain)
	if err != nil {
		return plan, err
	}
	if policy == "" || len(policy) > 4096 || strings.Contains(policy, ",") || strings.IndexFunc(policy, unicode.IsControl) >= 0 {
		return plan, errors.New("policy must be an existing proxy or group name without commas or control characters")
	}
	source, err := InspectSource(ctx, target)
	if err != nil {
		return plan, err
	}
	client, cleanup, err := openCore(ctx, target, true, opts)
	if err != nil {
		return plan, err
	}
	defer cleanup()
	proxies, err := client.Proxies(ctx)
	if err != nil {
		return plan, err
	}
	if _, ok := proxies[policy]; !ok {
		return plan, errors.New("the selected policy does not exist on this target")
	}
	version, err := client.Version(ctx)
	if err != nil {
		return plan, err
	}
	coreVersion, _ := version["version"].(string)
	runtimeRules, err := client.Rules(ctx)
	if err != nil {
		return plan, err
	}
	beforeRuntimeDigest, err := rulesDigest(runtimeRules)
	if err != nil {
		return plan, err
	}
	rule := "DOMAIN," + domain + "," + policy
	after, noChange, err := addRule(source.file.Data, source.Kind, rule)
	if err != nil {
		return plan, err
	}
	if len(after) > 8<<20 {
		return plan, errors.New("candidate exceeds 8 MiB")
	}
	plan = Plan{TargetID: target.ID, Owner: source, Domain: domain, Policy: policy, Rule: rule, NoChange: noChange, CoreVersion: coreVersion, after: after, beforeRuntimeDigest: beforeRuntimeDigest, Diff: ruleDiff(source.file.Data, source.Kind, rule, domain, noChange)}
	data, _ := json.Marshal(struct {
		Binding, Domain, Policy, Version, After, Runtime string
		Guards                                           []fileGuard
	}{binding(target), domain, policy, coreVersion, sha(after), beforeRuntimeDigest, source.guards})
	plan.Digest = sha(data)
	return plan, nil
}

// Apply recomputes the preview and requires its digest. No write is retried;
// an uncertain SSH/API result always has a durable receipt for verification.
func Apply(ctx context.Context, target config.Target, domain, policy, expected string, opts Options) (Receipt, error) {
	if opts.ReadOnly {
		return Receipt{}, errors.New("rule repair is disabled in read-only mode")
	}
	if len(expected) != 64 {
		return Receipt{}, errors.New("apply requires the digest from a fresh preview")
	}
	plan, err := Preview(ctx, target, domain, policy, opts)
	if err != nil {
		return Receipt{}, err
	}
	if plan.Digest != expected {
		return Receipt{}, errors.New("rule preview changed; review a new preview before applying")
	}
	if target.RuleSource.Kind == "mihomo" {
		if err = validateCandidate(ctx, target, plan.after, plan.CoreVersion, opts); err != nil {
			return Receipt{}, err
		}
	}
	if _, err = hostCall(ctx, target.SSHHost, hostRequest{Op: "check", Guards: plan.Owner.guards}); err != nil {
		return Receipt{}, err
	}
	now := time.Now().UTC()
	idBytes := make([]byte, 16)
	if _, err = rand.Read(idBytes); err != nil {
		return Receipt{}, err
	}
	receipt := Receipt{ID: hex.EncodeToString(idBytes), TargetID: target.ID, Owner: plan.Owner.Kind, File: plan.Owner.File, Rule: plan.Rule, Domain: plan.Domain, Policy: plan.Policy, Status: "prepared", CreatedAt: now, UpdatedAt: now, Digest: plan.Digest, BeforeSHA256: plan.Owner.file.SHA256, AfterSHA256: sha(plan.after), Binding: binding(target), ProfileUID: plan.Owner.ProfileUID}
	receipt.BeforeRuntimeDigest = plan.beforeRuntimeDigest
	if plan.NoChange {
		receipt.AfterFingerprint = plan.Owner.file.Fingerprint
	}
	if err = prepareReceipt(opts, receipt, plan.Owner.file.Data); err != nil {
		return Receipt{}, err
	}
	if !plan.NoChange {
		var written hostFile
		written, err = hostCall(ctx, target.SSHHost, hostRequest{Op: "write", Path: plan.Owner.File, Data: plan.after, Guards: plan.Owner.guards})
		if err != nil {
			receipt.Status = "write_result_unknown"
			receipt.Message = "The file write was not confirmed. Verify this receipt before retrying."
			_ = saveReceipt(opts, receipt)
			return receipt, fmt.Errorf("%w: %w", &core.Error{Kind: core.KindUnknownWrite, Operation: "write persistent rule source"}, err)
		}
		receipt.AfterFingerprint = written.Fingerprint
	}
	if receipt.Owner == "verge" {
		receipt.Status = "persisted_pending_owner_reload"
		receipt.Message = "Rule saved to the current profile Rules companion. Reactivate Profiles in Clash Verge, then verify this receipt. Later Merge or Script rules can override it."
		err = saveReceipt(opts, receipt)
		return receipt, err
	}
	receipt.Status = "persisted_pending_apply"
	if err = saveReceipt(opts, receipt); err != nil {
		return receipt, err
	}
	client, cleanup, err := openCore(ctx, target, false, opts)
	if err == nil {
		_, err = client.ApplyConfig(ctx, receipt.File)
		cleanup()
	}
	if err != nil {
		receipt.Status = "runtime_result_unknown"
		receipt.Message = "Persistent rule saved; runtime apply was not confirmed. Verify before retrying."
		_ = saveReceipt(opts, receipt)
		return receipt, err
	}
	return Verify(ctx, target, receipt.ID, opts)
}

func runtimeFirstRule(ctx context.Context, target config.Target, domain, policy string, opts Options) (bool, error) {
	client, cleanup, err := openCore(ctx, target, true, opts)
	if err != nil {
		return false, err
	}
	defer cleanup()
	object, err := client.Rules(ctx)
	if err != nil {
		return false, err
	}
	rules, ok := object["rules"].([]any)
	if !ok || len(rules) == 0 {
		return false, nil
	}
	first, ok := rules[0].(map[string]any)
	if !ok {
		return false, nil
	}
	return strings.EqualFold(fmt.Sprint(first["type"]), "Domain") && strings.EqualFold(fmt.Sprint(first["payload"]), domain) && first["proxy"] == policy, nil
}

func Verify(ctx context.Context, target config.Target, id string, opts Options) (Receipt, error) {
	r, err := loadReceipt(opts, id)
	if err != nil {
		return r, err
	}
	if r.Binding != binding(target) {
		return r, errors.New("receipt belongs to a different target or source binding")
	}
	source, err := InspectSource(ctx, target)
	if err != nil {
		return r, err
	}
	if source.File != r.File {
		return r, errors.New("the persistent owner changed since this receipt")
	}
	f := source.file
	expectedSHA := r.AfterSHA256
	expectedFingerprint := r.AfterFingerprint
	if r.Restored {
		expectedSHA = r.BeforeSHA256
		expectedFingerprint = r.RestoredFingerprint
	}
	if f.SHA256 != expectedSHA || expectedFingerprint != "" && f.Fingerprint != expectedFingerprint {
		r.Status = "source_changed"
		r.RuntimeVerified = false
		r.Message = "Current source no longer matches the applied candidate."
		_ = saveReceipt(opts, r)
		return r, errors.New(r.Message)
	}
	if r.Restored {
		r.RestoredFingerprint = f.Fingerprint
	} else {
		r.AfterFingerprint = f.Fingerprint
	}
	if r.Restored {
		client, cleanup, e := openCore(ctx, target, true, opts)
		var current string
		if e == nil {
			var rules core.Object
			rules, e = client.Rules(ctx)
			if e == nil {
				current, e = rulesDigest(rules)
			}
			cleanup()
		}
		r.RuntimeVerified = e == nil && current == r.BeforeRuntimeDigest
		r.UpdatedAt = time.Now().UTC()
		if r.RuntimeVerified {
			r.Status = "restored_verified"
			r.Message = "Original bytes and the ordered runtime rule snapshot were restored."
		} else {
			r.Status = "restored_pending_owner_reload"
			r.Message = "Original file restored; runtime rules do not yet match the pre-edit snapshot. Reload the owner and verify again."
		}
		if saveErr := saveReceipt(opts, r); saveErr != nil {
			return r, saveErr
		}
		return r, e
	}
	verified, err := runtimeFirstRule(ctx, target, r.Domain, r.Policy, opts)
	r.RuntimeVerified = verified
	r.UpdatedAt = time.Now().UTC()
	if verified {
		r.Status = "applied_verified"
		r.Message = "Persistent source matches; the exact DOMAIN rule is first in the current runtime rules."
	} else if r.Owner == "verge" {
		r.Status = "persisted_pending_owner_reload"
		r.Message = "Reactivate Profiles in Clash Verge, then verify. The rule may also be overridden by a later Merge or Script."
	} else {
		r.Status = "persisted_not_verified"
		r.Message = "Persistent source matches, but the first runtime rule does not match the repair."
	}
	if saveErr := saveReceipt(opts, r); saveErr != nil {
		return r, saveErr
	}
	return r, err
}

// Restore refuses to overwrite intervening edits. Standalone owners reload the
// original YAML; Verge owners require native reactivation and later verification.
func Restore(ctx context.Context, target config.Target, id string, opts Options) (Receipt, error) {
	if opts.ReadOnly {
		return Receipt{}, errors.New("rule restore is disabled in read-only mode")
	}
	r, err := loadReceipt(opts, id)
	if err != nil {
		return r, err
	}
	if r.Binding != binding(target) {
		return r, errors.New("receipt belongs to a different target or source binding")
	}
	source, err := InspectSource(ctx, target)
	if err != nil {
		return r, err
	}
	if r.Restored && source.File == r.File && source.file.SHA256 == r.BeforeSHA256 {
		if r.RestoredFingerprint != "" && source.file.Fingerprint != r.RestoredFingerprint {
			return r, errors.New("restored source changed; refusing to overwrite intervening edits")
		}
		return Verify(ctx, target, r.ID, opts)
	}
	if source.File != r.File || source.file.SHA256 != r.AfterSHA256 || r.AfterFingerprint != "" && source.file.Fingerprint != r.AfterFingerprint {
		return r, errors.New("source changed since apply; restore will not overwrite intervening edits")
	}
	directory, err := receiptDirectory(opts, id, false)
	if err != nil {
		return r, err
	}
	backupPath := filepath.Join(directory, "before.yaml")
	backupInfo, statErr := os.Lstat(backupPath)
	if statErr != nil || !backupInfo.Mode().IsRegular() || backupInfo.Mode().Perm()&0077 != 0 || backupInfo.Size() > 8<<20 {
		return r, errors.New("receipt backup is absent or unsafe")
	}
	backup, err := os.ReadFile(backupPath)
	if err != nil || sha(backup) != r.BeforeSHA256 {
		return r, errors.New("receipt backup is missing or changed")
	}
	if r.Owner == "mihomo" {
		version, e := receiptCoreVersion(ctx, target, opts)
		if e != nil {
			return r, e
		}
		if e = validateCandidate(ctx, target, backup, version, opts); e != nil {
			return r, e
		}
	}
	r.Restored = true
	r.Status = "restore_prepared"
	if err = saveReceipt(opts, r); err != nil {
		return r, err
	}
	written, err := hostCall(ctx, target.SSHHost, hostRequest{Op: "write", Path: r.File, Data: backup, Guards: source.guards})
	if err != nil {
		r.Status = "restore_result_unknown"
		_ = saveReceipt(opts, r)
		return r, fmt.Errorf("%w: %w", &core.Error{Kind: core.KindUnknownWrite, Operation: "restore persistent rule source"}, err)
	}
	r.RestoredFingerprint = written.Fingerprint
	r.Status = "restored_pending_owner_reload"
	r.RuntimeVerified = false
	r.UpdatedAt = time.Now().UTC()
	r.Message = "Original file restored. Reload the persistent owner before testing traffic."
	if r.Owner == "mihomo" {
		client, cleanup, e := openCore(ctx, target, false, opts)
		if e == nil {
			_, e = client.ApplyConfig(ctx, r.File)
			cleanup()
		}
		if e != nil {
			err = e
			r.Status = "restore_runtime_result_unknown"
		}
	}
	if e := saveReceipt(opts, r); e != nil {
		return r, e
	}
	if err == nil && r.Owner == "mihomo" {
		return Verify(ctx, target, r.ID, opts)
	}
	return r, err
}

func rulesDigest(object core.Object) (string, error) {
	rows, ok := object["rules"].([]any)
	if !ok {
		return "", errors.New("controller did not return ordered runtime rules")
	}
	stable := make([][]any, 0, len(rows))
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return "", errors.New("invalid runtime rule")
		}
		kind, k := row["type"].(string)
		payload, p := row["payload"].(string)
		policy, a := row["proxy"].(string)
		if !k || !p || !a {
			return "", errors.New("incomplete runtime rule")
		}
		var disabled any
		if extra, ok := row["extra"].(map[string]any); ok {
			disabled = extra["disabled"]
		}
		stable = append(stable, []any{kind, payload, policy, disabled})
	}
	data, _ := json.Marshal(stable)
	return sha(data), nil
}

func receiptCoreVersion(ctx context.Context, t config.Target, opts Options) (string, error) {
	c, cleanup, err := openCore(ctx, t, true, opts)
	if err != nil {
		return "", err
	}
	defer cleanup()
	v, err := c.Version(ctx)
	if err != nil {
		return "", err
	}
	s, _ := v["version"].(string)
	return s, nil
}

func validateCandidate(ctx context.Context, target config.Target, data []byte, version string, opts Options) error {
	if opts.Validate != nil {
		return opts.Validate(ctx, target, data, version)
	}
	node, err := decodeYAML(data)
	if err != nil {
		return err
	}
	var document map[string]any
	if node.Decode(&document) != nil {
		return errors.New("cannot prepare isolated validation document")
	}
	_, err = hostCall(ctx, target.SSHHost, hostRequest{Op: "validate", Binary: target.RuleSource.Binary, Home: target.RuleSource.Home, Version: version, Document: document})
	return err
}
