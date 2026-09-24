package configwork

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"go.yaml.in/yaml/v3"
)

func PreviewChangeSet(ctx context.Context, from, to config.Target, selection StructuralSelection, opts Options) (ChangeSetPlan, error) {
	p := ChangeSetPlan{TargetID: to.ID, SourceTargetID: from.ID, Status: "blocked", Changes: []Change{}, Resources: []ResourceChange{}}
	left, err := SnapshotConfig(ctx, from, opts)
	if err != nil {
		return p, err
	}
	right, err := SnapshotConfig(ctx, to, opts)
	if err != nil {
		return p, err
	}
	if len(selection.Objects) == 0 {
		p.Owner = right.Owner
		p.Status = "no_changes"
		p.Composition = StructuralComposition{SourceSnapshot: &left, DestinationSnapshot: &right, Root: clone(right.Root), Diff: CompareConfig(left, right), Selected: []string{}, AutoSelected: []string{}, Reused: []string{}, Blockers: []StructuralBlocker{}}
		p.Digest = hashJSON([]any{Binding(from), Binding(to), left.Digest, right.Digest, selection})
		return p, nil
	}
	c, err := composeChangeSetWithCaches(ctx, from, left, right, selection, opts)
	p.Composition = c
	p.Owner = right.Owner
	if err != nil {
		return p, err
	}
	p.Warnings = append(p.Warnings, c.Warnings...)
	blocked := func(err error) (ChangeSetPlan, error) {
		p.Status = "blocked"
		p.Composition.Blockers = append(p.Composition.Blockers, StructuralBlocker{Code: "owner_preflight", Message: core.Sanitize(err.Error())})
		return p, err
	}
	if err = objectCopyBlockers(c); err != nil {
		return blocked(err)
	}
	rules, named := false, false
	ids := map[string]bool{}
	for _, id := range append(append([]string{}, c.Selected...), c.AutoSelected...) {
		ids[id] = true
	}
	for _, object := range left.Objects {
		if ids[object.ID] {
			if object.Kind == "rule" {
				rules = true
			} else {
				named = true
			}
		}
	}
	if named && (from.ConfigSource == nil || to.ConfigSource == nil) {
		return blocked(errors.New("selected named objects require explicit configuration source bindings on both targets"))
	}
	effectiveTo, err := changeSetTarget(to)
	if err != nil {
		return blocked(err)
	}
	if rules {
		if err = sameChangeSetRuleOwner(effectiveTo); err != nil {
			return blocked(err)
		}
		p.ruleBinding = hashJSON(to.RuleSource)
	}
	owner := cloneOwnerSource(right.source)
	p.source = owner
	p.Resources, err = prepareChangeSetResources(ctx, from, effectiveTo, &c, opts)
	if err != nil {
		return blocked(err)
	}
	paths, err := adaptChangeSetOwner(effectiveTo, owner, c.Root, selection)
	if err != nil {
		return blocked(err)
	}
	actual, err := changeSetEffective(owner)
	if err != nil {
		return blocked(err)
	}
	if err = validateGraph(actual); err != nil {
		return blocked(err)
	}
	seen := map[string]bool{}
	for _, file := range paths {
		if seen[file] {
			continue
		}
		seen[file] = true
		before := owner.files[file]
		after, e := encode(owner.docs[file])
		if e != nil {
			return blocked(e)
		}
		if len(after) > MaxDocument {
			return blocked(errors.New("candidate exceeds 8 MiB"))
		}
		if semantic(owner.docs[file]) == semanticMust(before.Data) {
			continue
		}
		p.Changes = append(p.Changes, Change{Path: file, BeforeSHA256: before.SHA256, AfterSHA256: hash(after), Status: "planned", Fingerprint: before.Fingerprint, before: before.Data, after: after})
	}
	p.effective, err = encode(actual)
	if err != nil {
		return blocked(err)
	}
	p.Composition = c
	p.Composition.Root = actual
	afterSnapshot := right
	afterSnapshot.TargetID = from.ID
	afterSnapshot.Root = actual
	afterSnapshot.Objects, err = structuralObjects(actual, owner)
	if err != nil {
		return blocked(err)
	}
	priorObjects := map[string]ConfigObject{}
	for _, object := range right.Objects {
		priorObjects[object.ID] = object
	}
	for i := range afterSnapshot.Objects {
		if previous, ok := priorObjects[afterSnapshot.Objects[i].ID]; ok {
			afterSnapshot.Objects[i].ResourceSHA256 = previous.ResourceSHA256
			afterSnapshot.Objects[i].ResourceStatus = previous.ResourceStatus
			afterSnapshot.Objects[i].ResourceMessage = previous.ResourceMessage
		}
	}
	for i := range afterSnapshot.Objects {
		for _, res := range p.Resources {
			if afterSnapshot.Objects[i].Section == res.Section && afterSnapshot.Objects[i].Name == res.Provider && !res.Mutable {
				afterSnapshot.Objects[i].ResourceSHA256 = res.SHA256
				afterSnapshot.Objects[i].ResourceStatus = "available"
			}
		}
	}
	p.Composition.Diff = CompareConfig(afterSnapshot, right)
	p.Status = "no_changes"
	if len(p.Changes) > 0 || newChangeSetResources(p.Resources) {
		client, close, e := open(ctx, effectiveTo, true, opts)
		if e != nil {
			return blocked(changeSetAvailability(e))
		}
		version, e := client.Version(ctx)
		close()
		if e != nil {
			return blocked(changeSetAvailability(e))
		}
		p.version, _ = version["version"].(string)
		if p.version == "" {
			return blocked(errors.New("destination core version is unavailable"))
		}
		if e = checkCompatibility(version, c.Definitions); e != nil {
			return blocked(e)
		}
		if e = validateChangeSet(ctx, effectiveTo, owner, p.effective, p.version, p.Resources, opts); e != nil {
			return blocked(e)
		}
		p.Status = "ready"
	}
	if owner.Kind == "verge" && len(p.Changes) > 0 {
		p.Warnings = append(p.Warnings, "Selected definitions become persistent profile overrides; owner-generated ordering can differ and later subscription changes to overridden definitions are masked.")
		if rules && owner.profileMerge != "" && get(owner.docs[owner.profileMerge], "rules") != nil {
			p.Warnings = append(p.Warnings, "The full active-profile Merge.rules override masks subsequent subscription rule updates.")
		}
	}
	p.Digest = hashJSON([]any{Binding(from), Binding(to), left.Digest, right.Digest, selection, p.Changes, p.Resources, p.ruleBinding, p.version, hash(p.effective), owner.dockerID, owner.dockerImage})
	return p, nil
}

// HTTP cache bytes are captured only for providers selected by the current
// dependency closure. They inform execution dependencies but never become
// configuration-diff identity or trigger network downloads.
func composeChangeSetWithCaches(ctx context.Context, from config.Target, left, right ConfigSnapshot, selection StructuralSelection, opts Options) (StructuralComposition, error) {
	for pass := 0; pass <= len(left.Objects); pass++ {
		c, err := ComposeConfig(left, right, selection)
		if from.ConfigSource == nil {
			return c, err
		}
		ids := map[string]bool{}
		for _, id := range append(append([]string{}, c.Selected...), c.AutoSelected...) {
			ids[id] = true
		}
		loaded := false
		for i := range left.Objects {
			object := &left.Objects[i]
			if !ids[object.ID] || object.Kind != "proxy-provider" || scalar(object.Node, "type") != "http" || object.resource != nil {
				continue
			}
			file, e := ReadProviderResource(ctx, from, left.source, *object, opts)
			if e != nil || len(file.Data) == 0 || file.SHA256 != hash(file.Data) {
				if e == nil {
					e = errors.New("HTTP provider cache could not be verified")
				}
				c.Blockers = append(c.Blockers, StructuralBlocker{Code: "provider_cache_unavailable", ObjectID: object.ID, Message: cleanChangeSetMessage(e)})
				return c, e
			}
			object.resource = &file
			loaded = true
		}
		if !loaded {
			return c, err
		}
	}
	return StructuralComposition{}, errors.New("HTTP provider dependency closure did not stabilize")
}

func newChangeSetResources(resources []ResourceChange) bool {
	for _, r := range resources {
		if r.Created {
			return true
		}
	}
	return false
}

func validateChangeSet(ctx context.Context, t config.Target, s *source, raw []byte, version string, resources []ResourceChange, opts Options) error {
	if s.Kind == "docker" && s.dockerSourceSHA != s.files[s.base].SHA256 {
		return errors.New("destination container does not see the current host source; recover owner activation first")
	}
	if opts.Validate != nil {
		return opts.Validate(ctx, t, raw, version)
	}
	if s.Kind == "verge" && t.ConfigSource.Binary == "" {
		if len(resources) > 0 {
			return errors.New("Verge provider migration requires a bound validator binary/home; configure these before transferring provider snapshots")
		}
		return nil
	}
	node, err := decode(raw)
	if err != nil {
		return err
	}
	var document any
	if node.Decode(&document) != nil {
		return errors.New("candidate validation document is invalid")
	}
	c := t.ConfigSource
	op := "validate"
	if c.Kind == "docker" {
		op = "docker-validate"
	}
	r, err := hostOperation(ctx, t, HostRequest{Op: op, Binary: c.Binary, Home: c.Home, Version: version, Document: document, Container: c.Container, HostPath: c.HostPath, CorePath: c.CorePath, ValidationDockerHost: c.ValidationDockerHost, ValidationImage: c.ValidationImage, Resources: resourceBytes(resources)}, opts)
	if err == nil && s.Kind == "docker" && (r.ContainerID != s.dockerID || r.Image != s.dockerImage) {
		return errors.New("Docker owner changed during candidate validation")
	}
	return err
}

func changeSetSections(c StructuralComposition) []string {
	sections := []string{}
	seen := map[string]bool{}
	ids := map[string]bool{}
	for _, id := range append(append([]string{}, c.Selected...), c.AutoSelected...) {
		ids[id] = true
	}
	for _, o := range c.SourceSnapshot.Objects {
		if !ids[o.ID] {
			continue
		}
		section := o.Section
		if o.Kind == "rule" {
			section = "rules"
		}
		if !seen[section] {
			sections = append(sections, section)
			seen[section] = true
		}
		if o.Kind == "proxy" && !seen["proxy-groups"] {
			sections = append(sections, "proxy-groups")
			seen["proxy-groups"] = true
		}
	}
	return sections
}

func objectCopyBlockers(c StructuralComposition) error {
	for _, d := range c.Definitions {
		if d.Kind != "proxy" {
			continue
		}
		if err := transferDefinitionCheck(d.Map()); err != nil {
			return fmt.Errorf("node %q: %w", d.Name, err)
		}
	}
	ids := map[string]bool{}
	for _, id := range append(append([]string{}, c.Selected...), c.AutoSelected...) {
		ids[id] = true
	}
	for _, o := range c.SourceSnapshot.Objects {
		if ids[o.ID] && o.Kind == "proxy-provider" {
			if err := transferDefinitionCheck(o.Node); err != nil {
				return err
			}
		}
	}
	return nil
}

func transferDefinitionCheck(value any) error {
	if n, ok := value.(*yaml.Node); ok {
		var decoded any
		if n.Decode(&decoded) != nil {
			return errors.New("provider definition cannot be decoded")
		}
		value = decoded
	}
	if hasFileDependency(value) {
		return errors.New("host-local certificate/key references require explicit adaptation before transfer")
	}
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			if key == "interface-name" || key == "routing-mark" {
				return errors.New("host-specific routing fields require explicit adaptation before transfer")
			}
			if err := transferDefinitionCheck(item); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range v {
			if err := transferDefinitionCheck(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func changeSetAvailability(err error) error {
	var api *core.Error
	var ssh *connection.SSHTransportError
	var auth *connection.AuthRequiredError
	if errors.As(err, &ssh) || errors.As(err, &auth) || errors.As(err, &api) && (api.Kind == core.KindUnreachable || api.Kind == core.KindAuth || api.Kind == core.KindTLS) {
		return fmt.Errorf("%w: %w", ErrConfigUnavailable, err)
	}
	return err
}

func cleanChangeSetMessage(err error) string { return core.Sanitize(strings.TrimSpace(err.Error())) }

func changeSetDocumentSections(root *yaml.Node, sections []string) map[string]string {
	out := map[string]string{}
	for _, section := range sections {
		out[section] = semantic(get(root, section))
	}
	return out
}
