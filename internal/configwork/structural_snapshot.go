package configwork

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"github.com/daviddwlee84/lazyclash/internal/sourceowner"
	"go.yaml.in/yaml/v3"
)

// SnapshotConfig reads declared owner data, never runtime proxy reconstructions.
// Raw documents remain private; public objects contain masked display values.
func SnapshotConfig(ctx context.Context, target config.Target, opts Options) (ConfigSnapshot, error) {
	result := ConfigSnapshot{TargetID: target.ID, Target: target, target: target, Objects: []ConfigObject{}, Files: []string{}, Complete: false}
	effectiveTarget, err := changeSetTarget(target)
	if err != nil {
		return result, err
	}
	s, err := inspectWithOptions(ctx, effectiveTarget, opts)
	if err != nil {
		var transport *connection.SSHTransportError
		var auth *connection.AuthRequiredError
		if errors.Is(err, rulework.ErrSourceUnavailable) || errors.Is(err, sourceowner.ErrUnavailable) || os.IsNotExist(err) || errors.As(err, &transport) || errors.As(err, &auth) {
			return result, fmt.Errorf("%w: %w", ErrConfigUnavailable, err)
		}
		return result, err
	}
	root, err := changeSetEffective(s)
	if err != nil {
		return result, err
	}
	result.Owner, result.Shape, result.Root, result.source = s.Kind, "complete-yaml", root, s
	result.Files = append(result.Files, s.Files...)
	result.Warnings = append([]string{}, s.Warnings...)
	if s.Kind == "verge" {
		result.Shape = "verge-declared"
		result.Warnings = append(result.Warnings, "Verge comparison covers declarative source stages; Scripts are not executed and generated/runtime behavior can differ.")
	}
	result.Objects, err = structuralObjects(root, s)
	if err != nil {
		return result, err
	}
	result.Complete = true
	resources := []any{}
	for i := range result.Objects {
		object := &result.Objects[i]
		if !structuralFileProvider(*object) {
			continue
		}
		file, readErr := ReadProviderResource(ctx, target, s, *object, opts)
		if readErr == nil && (len(file.Data) == 0 || len(file.Data) > MaxDocument || file.SHA256 != hash(file.Data)) {
			readErr = errors.New("provider resource returned incomplete or inconsistent bytes")
		}
		if readErr != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			object.ResourceStatus, object.ResourceMessage = "unavailable", core.Sanitize(readErr.Error())
			object.Selectable = false
			object.ReadOnlyReason = "Authoritative file-provider data is unavailable: " + object.ResourceMessage
			result.Complete = false
			result.Warnings = append(result.Warnings, "Provider "+object.Name+" contents could not be compared; its declaration alone does not establish equality.")
			resources = append(resources, []any{object.ID, "unavailable"})
			continue
		}
		object.ResourceStatus, object.ResourceSHA256 = "available", file.SHA256
		object.resource = &file
		resources = append(resources, []any{object.ID, file.SHA256, file.Fingerprint})
	}
	result.Digest = hashJSON([]any{Binding(effectiveTarget), typedFingerprint(root), s.guards, s.dockerID, s.dockerImage, resources})
	return result, nil
}

func structuralFileProvider(object ConfigObject) bool {
	return (object.Kind == "proxy-provider" || object.Kind == "rule-provider") && scalar(object.Node, "type") == "file"
}

func structuralObjects(root *yaml.Node, owner *source) ([]ConfigObject, error) {
	if root == nil || root.Kind != yaml.MappingNode {
		return nil, errors.New("structural configuration must be a YAML mapping")
	}
	objects := []ConfigObject{}
	base := ""
	if owner != nil {
		base = owner.base
	}
	for _, section := range []string{"proxies", "proxy-groups", "proxy-providers", "rule-providers", "rules"} {
		shape := structuralNodeType(get(root, section))
		object := makeStructuralObject("section", section, "(container shape)", base, -1, str(shape), false)
		object.ID = "/_shape/" + section
		object.Value = shape
		object.ReadOnlyReason = "Container presence/type is compared, not independently applied."
		objects = append(objects, object)
	}
	for _, spec := range []struct{ section, kind string }{{"proxies", "proxy"}, {"proxy-groups", "group"}} {
		defs, err := definitions(root, spec.section, spec.kind, base)
		if err != nil {
			return nil, err
		}
		for i, def := range defs {
			origin := base
			if owner != nil {
				origin = owner.origin(spec.kind, def.Name)
			}
			objects = append(objects, makeStructuralObject(spec.kind, spec.section, def.Name, origin, i, def.Node, true))
		}
		order := []string{}
		for _, def := range defs {
			order = append(order, def.Name)
		}
		object := makeStructuralObject("section", spec.section, "(definition order)", base, -1, mapNode(order), false)
		object.ID = "/_order/" + spec.section
		object.ReadOnlyReason = "Definition order is compared separately; selected named objects retain destination positions. Member order inside a group is copied with that group."
		objects = append(objects, object)
	}
	for _, spec := range []struct{ section, kind string }{{"proxy-providers", "proxy-provider"}, {"rule-providers", "rule-provider"}} {
		node := get(root, spec.section)
		if node == nil {
			continue
		}
		if node.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s must be a mapping", spec.section)
		}
		seen := map[string]bool{}
		for i := 0; i+1 < len(node.Content); i += 2 {
			name, value := node.Content[i].Value, node.Content[i+1]
			if !validName(name) || seen[name] || value.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("%s contains an invalid or duplicate provider", spec.section)
			}
			seen[name] = true
			objects = append(objects, makeStructuralObject(spec.kind, spec.section, name, base, i/2, value, true))
		}
	}
	if rules := get(root, "rules"); rules != nil {
		if rules.Kind != yaml.SequenceNode {
			return nil, errors.New("rules must be an ordered sequence")
		}
		for i, rule := range rules.Content {
			if rule.Kind != yaml.ScalarNode || rule.Tag != "!!str" {
				return nil, errors.New("rules must contain string expressions")
			}
			object := makeStructuralObject("rule", "rules", rule.Value, base, i, rule, true)
			object.ID = "/rules/" + strconv.Itoa(i) + "@" + typedFingerprint(rule)[:16]
			objects = append(objects, object)
		}
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return nil, errors.New("top-level configuration keys must be strings")
		}
		switch key.Value {
		case "proxies", "proxy-groups", "proxy-providers", "rule-providers", "rules":
			continue
		}
		object := makeStructuralObject("section", key.Value, key.Value, base, i/2, value, false)
		object.ReadOnlyReason = "This top-level section is compare-only in configuration sync."
		objects = append(objects, object)
	}
	return objects, nil
}

func makeStructuralObject(kind, section, name, origin string, index int, node *yaml.Node, selectable bool) ConfigObject {
	value, _ := structuralDisplay(node, kind, section)
	id := "/" + structuralPointer(section) + "/" + structuralPointer(name)
	if kind == "section" {
		id = "/" + structuralPointer(section)
	}
	return ConfigObject{ID: id, Kind: kind, Name: name, Section: section, Origin: origin, Index: index, Selectable: selectable, Value: value, Node: clone(node)}
}

func structuralPointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func structuralNormalized(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	var value any
	if node.Decode(&value) != nil {
		return clone(node)
	}
	return mapNode(value)
}

// Tags remain part of identity, so absent/null and strings/numbers are distinct.
// Comments, mapping order, scalar style and anchor spelling are not identity.
func typedFingerprint(node *yaml.Node) string {
	return hashJSON(typedStructuralValue(structuralNormalized(node)))
}

func typedStructuralValue(node *yaml.Node) any {
	if node == nil {
		return []any{"absent"}
	}
	switch node.Kind {
	case yaml.MappingNode:
		type pair struct {
			key   string
			value any
		}
		pairs := []pair{}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			pairs = append(pairs, pair{key.Tag + ":" + key.Value, typedStructuralValue(node.Content[i+1])})
		}
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].key < pairs[j].key })
		values := []any{}
		for _, pair := range pairs {
			values = append(values, []any{pair.key, pair.value})
		}
		return []any{"mapping", values}
	case yaml.SequenceNode:
		values := []any{}
		for _, item := range node.Content {
			values = append(values, typedStructuralValue(item))
		}
		return []any{"sequence", values}
	default:
		return []any{node.Tag, node.Value}
	}
}

func structuralDisplay(node *yaml.Node, kind, section string) (any, bool) {
	if kind == "rule" && node != nil {
		return core.Sanitize(node.Value), false
	}
	allowed := kind != "section" || structuralSafeScalar(section) || structuralSafeContainer(section)
	return structuralMask(structuralNormalized(node), section, allowed, kind == "rule-provider")
}

func structuralMask(node *yaml.Node, key string, allowed, rulePayload bool) (any, bool) {
	if node == nil {
		return nil, false
	}
	if node.Kind == yaml.MappingNode {
		result, masked := map[string]any{}, false
		for i := 0; i+1 < len(node.Content); i += 2 {
			name := node.Content[i].Value
			childAllowed := allowed && (structuralSafeScalar(name) || structuralSafeContainer(name))
			value, hidden := structuralMask(node.Content[i+1], name, childAllowed, rulePayload)
			result[core.Sanitize(name)], masked = value, masked || hidden
		}
		return result, masked
	}
	if node.Kind == yaml.SequenceNode {
		result, masked := []any{}, false
		for _, item := range node.Content {
			childAllowed := allowed
			if key == "payload" && item.Kind == yaml.ScalarNode && !rulePayload {
				childAllowed = false
			}
			value, hidden := structuralMask(item, key, childAllowed, rulePayload)
			result, masked = append(result, value), masked || hidden
		}
		return result, masked
	}
	if !allowed {
		return "[redacted]", true
	}
	var value any
	if node.Decode(&value) != nil {
		return "[redacted]", true
	}
	if key == "url" {
		return displayField("url", value)
	}
	if text, ok := value.(string); ok {
		if strings.Contains(text, "://") {
			return displayField("url", text)
		}
		return core.Sanitize(text), false
	}
	return value, false
}

func structuralSafeContainer(key string) bool {
	switch key {
	case "dns", "tun", "profile", "health-check", "override", "payload", "ws-opts", "grpc-opts", "reality-opts", "smux", "http-opts", "h2-opts", "http-upgrade-opts":
		return true
	}
	return false
}

func structuralSafeScalar(key string) bool {
	switch key {
	case "name", "type", "server", "port", "cipher", "alterId", "network", "tls", "udp", "tfo", "mptcp", "servername", "sni", "alpn", "client-fingerprint", "flow", "skip-cert-verify", "proxies", "use", "filter", "exclude-filter", "exclude-type", "interval", "timeout", "tolerance", "lazy", "strategy", "hidden", "include-all", "include-all-providers", "include-all-proxies", "url", "behavior", "format", "size-limit", "dialer-proxy", "proxy", "udp-over-tcp", "up", "down", "version":
		return true
	case "mode", "log-level", "ipv6", "mixed-port", "socks-port", "redir-port", "tproxy-port", "allow-lan", "bind-address", "external-controller", "external-controller-unix", "external-controller-pipe", "store-selected", "store-fake-ip", "find-process-mode", "tcp-concurrent", "unified-delay", "global-client-fingerprint":
		return true
	case "enable", "listen", "stack", "auto-route", "strict-route", "auto-detect-interface", "dns-hijack", "device", "mtu", "gso", "exclude-interface", "enhanced-mode", "fake-ip-range", "fake-ip-filter", "nameserver", "default-nameserver", "fallback", "proxy-server-nameserver", "direct-nameserver", "respect-rules", "use-hosts", "use-system-hosts":
		return true
	}
	return false
}
