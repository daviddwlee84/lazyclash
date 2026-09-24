package configwork

import (
	"errors"
	"fmt"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
	"go.yaml.in/yaml/v3"
)

type structuralReference struct{ kind, name string }

// ComposeConfig produces one private desired destination root. It does not
// adapt owner files, stage resources, validate a running core, or perform I/O.
func ComposeConfig(source, destination ConfigSnapshot, selection StructuralSelection) (StructuralComposition, error) {
	c := StructuralComposition{Selected: []string{}, AutoSelected: []string{}, Reused: []string{}, RequiredBy: map[string][]string{}, Blockers: []StructuralBlocker{}, SourceSnapshot: &source, DestinationSnapshot: &destination, source: destination.source, baseline: source.source}
	block := func(code, object, dependency, message string) {
		c.Blockers = append(c.Blockers, StructuralBlocker{Code: code, ObjectID: object, DependencyID: dependency, Message: message})
	}
	if source.Root == nil || destination.Root == nil {
		return c, errors.New("composition requires private source and destination snapshots")
	}
	if selection.RulePlacement == "" {
		selection.RulePlacement = "anchored"
	}
	if selection.RulePlacement != "anchored" && selection.RulePlacement != "prepend" {
		return c, errors.New("rule placement must be anchored or prepend")
	}
	if len(selection.Objects) == 0 {
		return c, errors.New("select at least one source object")
	}
	root, err := standalone(destination.Root, map[*yaml.Node]bool{})
	if err != nil {
		return c, err
	}
	c.Root = root
	from, to := structuralByID(source.Objects), structuralByID(destination.Objects)
	explicit, planned, replacements := map[string]bool{}, map[string]bool{}, map[string]bool{}
	decisions := map[string]string{}
	for _, d := range selection.Dependencies {
		if d.ID == "" || (d.Action != "reuse" && d.Action != "replace") || decisions[d.ID] != "" {
			return c, errors.New("dependency decisions need unique IDs and reuse or replace actions")
		}
		decisions[d.ID] = d.Action
	}
	pairs := structuralObjectPairs(source.Objects, destination.Objects)
	pairByID := map[string]ConfigObject{}
	for i, j := range pairs {
		pairByID[source.Objects[i].ID] = destination.Objects[j]
	}
	for _, selected := range selection.Objects {
		object, ok := from[selected.ID]
		if !ok || explicit[selected.ID] {
			block("invalid_selection", selected.ID, "", "Select a unique source object ID from the current comparison.")
			continue
		}
		explicit[selected.ID] = true
		if !object.Selectable {
			block("read_only_object", object.ID, "", object.ReadOnlyReason)
			continue
		}
		if previous, exists := pairByID[object.ID]; exists && !structuralObjectsEqual(object, previous) && !selected.Replace {
			block("replacement_required", object.ID, "", "An existing destination object differs; explicitly select replacement.")
			continue
		}
		replacements[object.ID] = selected.Replace
		c.Selected = append(c.Selected, object.ID)
	}
	visiting, visited := map[string]bool{}, map[string]bool{}
	var include func(ConfigObject, string)
	include = func(object ConfigObject, requiring string) {
		if visiting[object.ID] {
			block("dependency_cycle", requiring, object.ID, "Selected definitions contain a dependency cycle.")
			return
		}
		if visited[object.ID] {
			return
		}
		if !object.Selectable {
			block("unavailable_dependency", requiring, object.ID, object.ReadOnlyReason)
			return
		}
		visiting[object.ID] = true
		planned[object.ID] = true
		if object.Kind == "group" {
			for _, field := range []string{"include-all", "include-all-proxies", "include-all-providers"} {
				if strings.EqualFold(scalar(object.Node, field), "true") {
					c.Warnings = append(c.Warnings, "Group "+object.Name+" keeps "+field+"; membership is evaluated from destination nodes/providers, and this selection does not copy the whole source inventory.")
				}
			}
		}
		refs, refErr := structuralReferences(object)
		if refErr != nil {
			block("unsupported_dependency", object.ID, "", refErr.Error())
		}
		for _, ref := range refs {
			if ref.kind == "outbound" && structuralBuiltin(ref.name) {
				continue
			}
			wanted, sourceOK, sourceAmbiguous := structuralResolve(source.Objects, ref)
			existing, destinationOK, destinationAmbiguous := structuralResolve(destination.Objects, ref)
			destinationSatisfies := destinationOK
			if sourceOK && !destinationOK && !destinationAmbiguous {
				if sameName, exists := to[wanted.ID]; exists {
					existing, destinationOK = sameName, true
				}
			}
			dependencyID := ""
			if sourceOK {
				dependencyID = wanted.ID
			} else if destinationOK {
				dependencyID = existing.ID
			}
			if dependencyID != "" {
				required := c.RequiredBy[dependencyID]
				appendUnique(&required, object.ID)
				c.RequiredBy[dependencyID] = required
			}
			if sourceAmbiguous || destinationAmbiguous {
				block("ambiguous_dependency", object.ID, "", "Dependency name is ambiguous: "+ref.name)
				continue
			}
			if sourceOK && explicit[wanted.ID] {
				if !containsString(c.Selected, wanted.ID) {
					block("dependency_conflict", object.ID, wanted.ID, "An explicitly selected dependency is blocked.")
					continue
				}
				include(wanted, object.ID)
				continue
			}
			if destinationOK {
				id := existing.ID
				if sourceOK {
					id = wanted.ID
				}
				if sourceOK && structuralObjectsEqual(wanted, existing) {
					appendUnique(&c.Reused, id)
					continue
				}
				switch decisions[id] {
				case "reuse":
					if !destinationSatisfies {
						block("missing_dependency", object.ID, id, "The reused provider does not declare the referenced node "+ref.name+".")
						continue
					}
					appendUnique(&c.Reused, id)
				case "replace":
					if !sourceOK {
						block("missing_dependency", object.ID, id, "No transferable source definition exists for replacement.")
						continue
					}
					if wanted.Kind != existing.Kind || wanted.ID != existing.ID {
						block("name_collision", object.ID, id, "Replacing this dependency would require deleting a differently owned definition.")
						continue
					}
					replacements[wanted.ID] = true
					appendUnique(&c.AutoSelected, wanted.ID)
					include(wanted, object.ID)
				default:
					block("dependency_conflict", object.ID, id, "Destination dependency "+ref.name+" differs or has no comparable source definition; explicitly reuse or replace it.")
				}
			} else if sourceOK {
				if decisions[wanted.ID] == "reuse" {
					block("missing_dependency", object.ID, wanted.ID, "The requested reused dependency does not exist on the destination.")
					continue
				}
				appendUnique(&c.AutoSelected, wanted.ID)
				include(wanted, object.ID)
			} else {
				block("missing_dependency", object.ID, "", "No transferable definition was found for "+ref.kind+" "+ref.name+".")
			}
		}
		visiting[object.ID] = false
		visited[object.ID] = true
	}
	for _, id := range c.Selected {
		include(from[id], id)
	}
	if len(c.Blockers) > 0 {
		return c, errors.New("configuration selection has unresolved blockers")
	}
	for _, object := range source.Objects {
		if !planned[object.ID] || object.Kind == "rule" {
			continue
		}
		if object.Kind == "proxy" || object.Kind == "group" {
			if other, exists, _ := structuralResolve(destination.Objects, structuralReference{"outbound", object.Name}); exists && other.ID != object.ID {
				block("name_collision", object.ID, other.ID, "The destination outbound name belongs to another definition kind or provider.")
				continue
			}
		}
		portable, e := standalone(object.Node, map[*yaml.Node]bool{})
		if e != nil {
			block("source_alias", object.ID, "", e.Error())
			continue
		}
		switch object.Kind {
		case "proxy", "group":
			_, exists := to[object.ID]
			if exists && !replacements[object.ID] && !structuralObjectsEqual(object, to[object.ID]) {
				block("replacement_required", object.ID, "", "Existing destination definition needs explicit replacement.")
				continue
			}
			if e = replaceSeq(root, object.Section, object.Name, portable, !exists); e != nil {
				block("composition_failed", object.ID, "", e.Error())
			}
		case "proxy-provider", "rule-provider":
			if prior, exists := to[object.ID]; exists && !replacements[object.ID] && !structuralObjectsEqual(object, prior) {
				block("replacement_required", object.ID, "", "Existing destination provider needs explicit replacement.")
				continue
			}
			mapping := get(root, object.Section)
			if mapping == nil {
				mapping = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
				set(root, object.Section, mapping)
			}
			if mapping.Kind != yaml.MappingNode {
				block("composition_failed", object.ID, "", "Provider section is not a mapping.")
				continue
			}
			set(mapping, object.Name, portable)
		default:
			block("read_only_object", object.ID, "", "This object is compare-only.")
		}
	}
	if err = structuralComposeRules(root, source, destination, planned, selection.RulePlacement); err != nil {
		block("rule_placement_ambiguous", "", "", err.Error())
	}
	for _, attachment := range selection.AttachGroups {
		proxy, ok := from[attachment.ProxyID]
		if !ok || proxy.Kind != "proxy" || !planned[proxy.ID] {
			block("invalid_attachment", attachment.ProxyID, "", "Attachments require a selected source proxy.")
			continue
		}
		for _, name := range attachment.Groups {
			id := "/proxy-groups/" + structuralPointer(name)
			if planned[id] {
				block("attachment_conflict", proxy.ID, id, "A group cannot be both replaced and changed by an attachment in the same selection.")
				continue
			}
			group, exists := to[id]
			if !exists {
				block("missing_dependency", proxy.ID, id, "Attachment group must already exist on the destination.")
				continue
			}
			list := get(root, "proxy-groups")
			for _, n := range membersContent(list) {
				if scalar(n, "name") != group.Name {
					continue
				}
				members := sequence(n, "proxies")
				if members.Kind != yaml.SequenceNode {
					block("attachment_conflict", proxy.ID, id, "Group members are not an ordered sequence.")
					continue
				}
				found := false
				for _, member := range members.Content {
					found = found || member.Value == proxy.Name
				}
				if !found {
					members.Content = append(members.Content, str(proxy.Name))
				}
			}
		}
	}
	if len(c.Blockers) > 0 {
		return c, errors.New("configuration composition is blocked")
	}
	if err = validateGraph(root); err != nil {
		block("invalid_graph", "", "", err.Error())
	}
	dependencyMetadata := structuralByID(destination.Objects)
	for id := range planned {
		dependencyMetadata[id] = from[id]
	}
	if err = structuralValidateCycles(root, dependencyMetadata); err != nil {
		block("dependency_cycle", "", "", err.Error())
	}
	if len(c.Blockers) > 0 {
		return c, errors.New("configuration dependency graph is invalid")
	}
	// Read-only top-level data must retain its effective values after alias
	// materialization and selected object replacement.
	for i := 0; i+1 < len(destination.Root.Content); i += 2 {
		key := destination.Root.Content[i].Value
		if key == "proxies" || key == "proxy-groups" || key == "proxy-providers" || key == "rule-providers" || key == "rules" {
			continue
		}
		if typedFingerprint(get(root, key)) != typedFingerprint(destination.Root.Content[i+1]) {
			block("unselected_value_changed", "/"+structuralPointer(key), "", "An unselected top-level value changed while resolving aliases.")
		}
	}
	objects, e := structuralObjects(root, destination.source)
	if e != nil {
		return c, e
	}
	for i := range objects {
		original, exists := to[objects[i].ID]
		if planned[objects[i].ID] {
			original, exists = from[objects[i].ID]
		}
		if exists {
			objects[i].ResourceSHA256, objects[i].ResourceStatus, objects[i].ResourceMessage, objects[i].resource = original.ResourceSHA256, original.ResourceStatus, original.ResourceMessage, original.resource
		}
	}
	afterByID := structuralByID(objects)
	attached := map[string]bool{}
	for _, attachment := range selection.AttachGroups {
		for _, name := range attachment.Groups {
			attached["/proxy-groups/"+structuralPointer(name)] = true
		}
	}
	for _, prior := range destination.Objects {
		if prior.Kind == "section" || prior.Kind == "rule" || planned[prior.ID] || attached[prior.ID] {
			continue
		}
		actual, exists := afterByID[prior.ID]
		if !exists || typedFingerprint(prior.Node) != typedFingerprint(actual.Node) {
			block("unselected_value_changed", prior.ID, "", "An unselected named object's effective value changed while resolving aliases.")
		}
	}
	after := destination
	after.Root = root
	after.Objects = objects
	c.Diff = CompareConfig(after, destination)
	c.Diff.SourceTargetID = source.TargetID
	for _, object := range objects {
		if object.Kind == "rule" {
			c.Rules = append(c.Rules, object.Node.Value)
		}
		if object.Kind == "proxy" || object.Kind == "group" {
			if planned[object.ID] {
				d, e := definition(object.Node, object.Kind, "candidate")
				if e != nil {
					return c, e
				}
				c.Definitions = append(c.Definitions, d)
			}
		}
	}
	c.expected, c.expectedRules = c.Definitions, c.Rules
	if len(c.Blockers) > 0 {
		return c, errors.New("unselected configuration values were not preserved")
	}
	return c, nil
}

func structuralByID(objects []ConfigObject) map[string]ConfigObject {
	result := map[string]ConfigObject{}
	for _, o := range objects {
		result[o.ID] = o
	}
	return result
}
func structuralObjectsEqual(a, b ConfigObject) bool {
	if a.Kind != b.Kind {
		return false
	}
	if a.Kind == "rule" {
		return structuralRuleKey(a, true) == structuralRuleKey(b, true)
	}
	if typedFingerprint(a.Node) != typedFingerprint(b.Node) {
		return false
	}
	if structuralFileProvider(a) || structuralFileProvider(b) {
		return a.ResourceStatus == "available" && b.ResourceStatus == "available" && a.ResourceSHA256 == b.ResourceSHA256
	}
	return true
}
func appendUnique(values *[]string, value string) {
	if !containsString(*values, value) {
		*values = append(*values, value)
	}
}
func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
func structuralBuiltin(name string) bool {
	switch name {
	case "DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE", "GLOBAL":
		return true
	}
	return false
}

func structuralResolve(objects []ConfigObject, ref structuralReference) (ConfigObject, bool, bool) {
	var found ConfigObject
	count := 0
	for _, object := range objects {
		match := object.Name == ref.name && (object.Kind == ref.kind || ref.kind == "outbound" && (object.Kind == "proxy" || object.Kind == "group"))
		if ref.kind == "outbound" && object.Kind == "proxy-provider" {
			if nodes, err := structuralProviderPayloadNodes(object); err == nil {
				for _, entry := range nodes {
					if scalar(entry, "name") == ref.name {
						match = true
					}
				}
			}
		}
		if match {
			found = object
			count++
		}
	}
	return found, count == 1, count > 1
}

func structuralReferences(object ConfigObject) ([]structuralReference, error) {
	refs := []structuralReference{}
	add := func(kind, name string) {
		if name != "" {
			refs = append(refs, structuralReference{kind, name})
		}
	}
	switch object.Kind {
	case "proxy":
		add("outbound", scalar(object.Node, "dialer-proxy"))
	case "group":
		for _, n := range membersContent(get(object.Node, "proxies")) {
			if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
				return nil, errors.New("group members must be names")
			}
			add("outbound", n.Value)
		}
		for _, n := range membersContent(get(object.Node, "use")) {
			if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
				return nil, errors.New("group providers must be names")
			}
			add("proxy-provider", n.Value)
		}
	case "proxy-provider", "rule-provider":
		add("outbound", scalar(object.Node, "proxy"))
		add("outbound", scalar(get(object.Node, "override"), "dialer-proxy"))
		if object.Kind == "proxy-provider" {
			nodes, err := structuralProviderPayloadNodes(object)
			if err != nil {
				return nil, err
			}
			for _, n := range nodes {
				add("outbound", scalar(n, "dialer-proxy"))
			}
		}
	case "rule":
		r, err := rulecheck.ParseQuery(object.Node.Value)
		if err != nil {
			return nil, errors.New("selected rule has invalid outer syntax")
		}
		if r.LiteralOnly || r.Policy == "" {
			return nil, errors.New("selected rule grammar has unknown dependencies")
		}
		switch r.Type {
		case "AND", "OR", "NOT", "SUB-RULE":
			return nil, errors.New("logical/sub-rule transfer requires dependency analysis not available in this sync version")
		}
		add("outbound", r.Policy)
		if r.Type == "RULE-SET" {
			add("rule-provider", r.Payload)
		}
	}
	return refs, nil
}

// Private captured bytes may come from an authoritative file or a selected
// HTTP cache seed. HTTP bytes remain excluded from configuration equality.
func structuralProviderPayloadNodes(object ConfigObject) ([]*yaml.Node, error) {
	if object.Kind != "proxy-provider" {
		return nil, nil
	}
	var payload *yaml.Node
	switch scalar(object.Node, "type") {
	case "inline":
		payload = get(object.Node, "payload")
	case "file", "http":
		if object.resource == nil {
			return nil, nil
		}
		document, err := decode(object.resource.Data)
		if err != nil {
			return nil, errors.New("captured proxy-provider data cannot be parsed for dependency closure")
		}
		if document.Kind != yaml.MappingNode {
			return nil, errors.New("captured proxy-provider data must contain a proxies mapping")
		}
		payload = get(document, "proxies")
		if payload == nil {
			payload = get(document, "payload")
		}
	default:
		return nil, nil
	}
	if payload == nil {
		return nil, nil
	}
	if payload.Kind != yaml.SequenceNode {
		return nil, errors.New("proxy-provider payload must be a sequence for dependency closure")
	}
	for _, node := range payload.Content {
		resolved := node
		if resolved.Kind == yaml.AliasNode {
			resolved = resolved.Alias
		}
		if resolved == nil || resolved.Kind != yaml.MappingNode {
			return nil, errors.New("proxy-provider payload entries must be mappings for dependency closure")
		}
	}
	return payload.Content, nil
}

func structuralValidateCycles(root *yaml.Node, metadata map[string]ConfigObject) error {
	objects, err := structuralObjects(root, nil)
	if err != nil {
		return err
	}
	for i := range objects {
		if original, ok := metadata[objects[i].ID]; ok {
			objects[i].resource = original.resource
		}
	}
	edges := map[string][]string{}
	for _, object := range objects {
		if object.Kind == "section" || object.Kind == "rule" {
			continue
		}
		refs, e := structuralReferences(object)
		if e != nil {
			return e
		}
		for _, ref := range refs {
			if ref.kind == "outbound" && structuralBuiltin(ref.name) {
				continue
			}
			dep, ok, ambiguous := structuralResolve(objects, ref)
			if ambiguous {
				return errors.New("ambiguous candidate dependency")
			}
			if ok {
				edges[object.ID] = append(edges[object.ID], dep.ID)
			}
		}
	}
	state := map[string]int{}
	var visit func(string) error
	visit = func(id string) error {
		if state[id] == 1 {
			return fmt.Errorf("dependency cycle includes %s", id)
		}
		if state[id] == 2 {
			return nil
		}
		state[id] = 1
		for _, dep := range edges[id] {
			if e := visit(dep); e != nil {
				return e
			}
		}
		state[id] = 2
		return nil
	}
	for _, object := range objects {
		if err := visit(object.ID); err != nil {
			return err
		}
	}
	return nil
}

func structuralComposeRules(root *yaml.Node, source, destination ConfigSnapshot, selected map[string]bool, placement string) error {
	sourceRules, destRules := []ConfigObject{}, []ConfigObject{}
	for _, o := range source.Objects {
		if o.Kind == "rule" {
			sourceRules = append(sourceRules, o)
		}
	}
	for _, o := range destination.Objects {
		if o.Kind == "rule" {
			destRules = append(destRules, o)
		}
	}
	chosen := []ConfigObject{}
	for _, o := range sourceRules {
		if selected[o.ID] {
			chosen = append(chosen, o)
		}
	}
	if len(chosen) == 0 {
		return nil
	}
	pairs := structuralObjectPairs(sourceRules, destRules)
	remove := map[int]bool{}
	for i, j := range pairs {
		if selected[sourceRules[i].ID] {
			remove[j] = true
		}
	}
	remaining := []ConfigObject{}
	for i, o := range destRules {
		if !remove[i] {
			remaining = append(remaining, o)
		}
	}
	slots := map[int][]ConfigObject{}
	if placement == "prepend" {
		slots[0] = chosen
	} else {
		counts := map[string]int{}
		for _, o := range sourceRules {
			counts[structuralRuleKey(o, true)]++
		}
		destPositions := map[string][]int{}
		for i, o := range remaining {
			key := structuralRuleKey(o, true)
			destPositions[key] = append(destPositions[key], i)
		}
		anchor := func(o ConfigObject) (int, bool) {
			key := structuralRuleKey(o, true)
			p := destPositions[key]
			returnValue := -1
			if len(p) == 1 {
				returnValue = p[0]
			}
			return returnValue, counts[key] == 1 && len(p) == 1 && !selected[o.ID]
		}
		lastSlot := -1
		for i := 0; i < len(sourceRules); {
			if !selected[sourceRules[i].ID] {
				i++
				continue
			}
			start := i
			block := []ConfigObject{}
			for i < len(sourceRules) && selected[sourceRules[i].ID] {
				block = append(block, sourceRules[i])
				i++
			}
			left, right := -1, len(remaining)
			leftFound, rightFound := false, false
			for j := start - 1; j >= 0; j-- {
				if pos, ok := anchor(sourceRules[j]); ok {
					left, leftFound = pos, true
					break
				}
			}
			for j := i; j < len(sourceRules); j++ {
				if pos, ok := anchor(sourceRules[j]); ok {
					right, rightFound = pos, true
					break
				}
			}
			if (!leftFound && !rightFound && len(remaining) > 0) || left >= right || right-left != 1 {
				return errors.New("rule insertion has no unique gap between unchanged common anchors; choose explicit prepend")
			}
			slot := right
			if slot < lastSlot {
				return errors.New("common rule anchors disagree with source order; choose explicit prepend")
			}
			lastSlot = slot
			slots[slot] = append(slots[slot], block...)
		}
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for i := 0; i <= len(remaining); i++ {
		for _, o := range slots[i] {
			seq.Content = append(seq.Content, clone(o.Node))
		}
		if i < len(remaining) {
			seq.Content = append(seq.Content, clone(remaining[i].Node))
		}
	}
	set(root, "rules", seq)
	return nil
}
