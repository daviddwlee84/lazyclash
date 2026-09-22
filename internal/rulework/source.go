package rulework

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"go.yaml.in/yaml/v3"
)

func options(opts Options) Options {
	if opts.Open == nil {
		opts.Open = connection.Open
	}
	return opts
}

func openCore(ctx context.Context, target config.Target, readOnly bool, opts Options) (*core.Client, func(), error) {
	opts = options(opts)
	client, closer, err := opts.Open(ctx, target, readOnly)
	cleanup := func() {
		if closer != nil {
			_ = closer.Close()
		}
		if client != nil {
			_ = client.Close()
		}
	}
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	if client == nil {
		cleanup()
		return nil, func() {}, errors.New("controller opener returned no client")
	}
	return client, cleanup, nil
}

func NormalizeDomain(value string) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if value == "" || len(value) > 253 || net.ParseIP(value) != nil {
		return "", errors.New("supply a DNS hostname, not an IP address or URL")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS hostname")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("use an ASCII DNS hostname (punycode for international names)")
			}
		}
	}
	return value, nil
}

// NormalizeIPPrefix uses a host prefix for a bare address and canonicalizes
// explicit networks. Mapped IPv4 and interface-scoped IPv6 are rejected so the
// rule family cannot silently differ from the address supplied by the caller.
func NormalizeIPPrefix(value string) (string, error) {
	var prefix netip.Prefix
	var err error
	if strings.Contains(value, "/") {
		prefix, err = netip.ParsePrefix(value)
	} else {
		var address netip.Addr
		address, err = netip.ParseAddr(value)
		if err == nil {
			prefix = netip.PrefixFrom(address, address.BitLen())
			if address.Zone() != "" {
				return "", errors.New("IPv6 interface zones are not supported in IP rules")
			}
		}
	}
	if err != nil || !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
		return "", errors.New("supply an IPv4/IPv6 address or CIDR, without a URL, DNS name, zone or mapped address family")
	}
	return prefix.Masked().String(), nil
}

func ipRuleKind(prefix string) string {
	parsed, err := netip.ParsePrefix(prefix)
	if err == nil && parsed.Addr().Is4() {
		return "IP-CIDR"
	}
	return "IP-CIDR6"
}

// InspectSource reads only the explicit binding; it never infers write ownership
// from credential SourceConfig or the controller's general runtime settings.
func InspectSource(ctx context.Context, target config.Target) (Source, error) {
	if target.TransportOverride {
		return Source{}, errors.New("persistent rule repair requires a saved endpoint and SSH host; save the target and explicitly rebind its rule source first")
	}
	s := target.RuleSource
	if s == nil {
		return Source{}, errors.New("bind a persistent rule owner with rules source set first")
	}
	if err := config.ValidateRuleSource(target); err != nil {
		return Source{}, err
	}
	source := Source{Kind: s.Kind, ProfileUID: s.ProfileUID}
	if s.Kind == "mihomo" {
		source.Warnings = append(source.Warnings, "Applying the registered YAML reloads all its settings; other runtime-only changes may be replaced by the persisted source.")
		for _, item := range target.Configs {
			if item.ID == s.ConfigID {
				source.File = item.Path
			}
		}
	} else {
		manifest, err := readHost(ctx, target.SSHHost, filepath.Join(s.DataDir, "profiles.yaml"))
		if err != nil {
			return source, err
		}
		var index struct {
			Current string `yaml:"current"`
			Items   []struct {
				UID    string `yaml:"uid"`
				Type   string `yaml:"type"`
				File   string `yaml:"file"`
				Option struct {
					Rules  string `yaml:"rules"`
					Merge  string `yaml:"merge"`
					Script string `yaml:"script"`
				} `yaml:"option"`
			} `yaml:"items"`
		}
		if yaml.Unmarshal(manifest.Data, &index) != nil {
			return source, errors.New("Verge profile index is invalid")
		}
		seenUID := map[string]bool{}
		for _, item := range index.Items {
			if item.UID == "" || seenUID[item.UID] {
				return source, errors.New("Verge profile index contains missing or duplicate UIDs")
			}
			seenUID[item.UID] = true
		}
		if index.Current != s.ProfileUID {
			return source, errors.New("the bound Verge profile is no longer current; select or rebind it before editing")
		}
		rulesUID, mergeUID, scriptUID := "", "", ""
		for _, item := range index.Items {
			if item.UID == s.ProfileUID {
				if item.Type != "remote" && item.Type != "local" {
					return source, errors.New("bound Verge owner is not a local or remote profile")
				}
				rulesUID, mergeUID, scriptUID = item.Option.Rules, item.Option.Merge, item.Option.Script
			}
		}
		if rulesUID == "" {
			return source, errors.New("create and bind a profile Rules companion in Clash Verge first; lazyclash does not rewrite its live profile index")
		}
		source.guards = append(source.guards, fileGuard{manifest.Path, manifest.Fingerprint})
		for _, item := range index.Items {
			if item.UID != rulesUID && item.UID != mergeUID && item.UID != scriptUID && item.UID != "Merge" && item.UID != "Script" {
				continue
			}
			path, err := companionPath(s.DataDir, item.File)
			if err != nil {
				return source, err
			}
			f, err := readHost(ctx, target.SSHHost, path)
			if err != nil {
				return source, err
			}
			if !within(filepath.Join(filepath.Dir(manifest.Resolved), "profiles"), f.Resolved) {
				return source, errors.New("Verge companion resolves outside its profiles directory")
			}
			if item.UID == rulesUID {
				if item.Type != "rules" {
					return source, errors.New("bound companion is not a Verge Rules item")
				}
				source.File = path
			}
			source.guards = append(source.guards, fileGuard{path, f.Fingerprint})
			if item.Type == "merge" {
				doc, e := decodeMergeContext(f.Data)
				if e != nil {
					return source, errors.New("Verge Merge companion is invalid")
				}
				if mappingValue(doc.Content[0], "rules") != nil {
					source.Warnings = append(source.Warnings, "A later Verge Merge defines rules and may replace this Rules companion; verify after native reactivation.")
				}
			}
			if item.Type == "script" {
				source.Warnings = append(source.Warnings, "Verge Scripts run after Rules; final rule order must be verified after native reactivation.")
			}
		}
		if source.File == "" {
			return source, errors.New("the current profile Rules companion is absent from the Verge index")
		}
	}
	f, err := readHost(ctx, target.SSHHost, source.File)
	if err != nil {
		return source, err
	}
	source.file = f
	source.guards = append(source.guards, fileGuard{source.File, f.Fingerprint})
	return source, nil
}

func companionPath(dataDir, file string) (string, error) {
	if file == "" || filepath.IsAbs(file) || strings.IndexFunc(file, unicode.IsControl) >= 0 {
		return "", errors.New("invalid Verge companion filename")
	}
	path := filepath.Join(dataDir, "profiles", file)
	if !within(filepath.Join(dataDir, "profiles"), path) {
		return "", errors.New("Verge companion escapes its profiles directory")
	}
	return path, nil
}
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func decodeYAML(data []byte) (*yaml.Node, error) {
	var node yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&node); err != nil {
		return nil, errors.New("rule source is not valid YAML")
	}
	if len(node.Content) != 1 || node.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("rule source must be a YAML mapping")
	}
	var object map[string]any
	if node.Decode(&object) != nil {
		return nil, errors.New("rule source contains invalid or duplicate YAML keys")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("rule source must contain one valid YAML document")
	}
	return &node, nil
}

// Only an inspected Verge Merge companion may be empty/null. Other source
// documents still require a mapping, and malformed tagged nulls must fail.
func decodeMergeContext(data []byte) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	err := decoder.Decode(&document)
	empty := err == io.EOF
	if err == nil && len(document.Content) == 1 && document.Content[0].Tag == "!!null" {
		var value any
		var next yaml.Node
		empty = document.Decode(&value) == nil && value == nil && decoder.Decode(&next) == io.EOF
	}
	if empty {
		return &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}, nil
	}
	return decodeYAML(data)
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func addRule(data []byte, kind, rule string) ([]byte, bool, error) {
	node, err := decodeYAML(data)
	if err != nil {
		return nil, false, err
	}
	key := "rules"
	if kind == "verge" {
		key = "prepend"
	}
	mapping := node.Content[0]
	sequence := mappingValue(mapping, key)
	if sequence == nil {
		sequence = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, sequence)
	}
	if sequence.Kind != yaml.SequenceNode {
		return nil, false, fmt.Errorf("%s must be a YAML sequence", key)
	}
	parts := strings.Split(rule, ",")
	if len(parts) < 3 || (parts[0] != "DOMAIN" && parts[0] != "IP-CIDR" && parts[0] != "IP-CIDR6") {
		return nil, false, errors.New("unsupported rule repair type")
	}
	ruleKind, payload := parts[0], parts[1]
	matching := 0
	for _, item := range sequence.Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return nil, false, errors.New("rule sequence must contain strings")
		}
		if sameRuleTarget(item.Value, ruleKind, payload) {
			matching++
		}
	}
	if len(sequence.Content) > 0 && sequence.Content[0].Kind == yaml.ScalarNode && sequence.Content[0].Value == rule && matching == 1 {
		return data, true, nil
	}
	newRule := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: rule}
	items := []*yaml.Node{newRule}
	for _, item := range sequence.Content {
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			return nil, false, errors.New("rule sequence must contain strings")
		}
		if !sameRuleTarget(item.Value, ruleKind, payload) {
			items = append(items, item)
		} else {
			for _, comment := range []string{item.HeadComment, item.LineComment, item.FootComment} {
				if comment != "" {
					if newRule.HeadComment != "" {
						newRule.HeadComment += "\n"
					}
					newRule.HeadComment += comment
				}
			}
		}
	}
	sequence.Content = items
	sequence.Style = 0
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(node); err != nil {
		return nil, false, err
	}
	_ = encoder.Close()
	return out.Bytes(), false, nil
}

func sameDomainRule(rule, domain string) bool {
	return sameRuleTarget(rule, "DOMAIN", domain)
}

func sameRuleTarget(rule, kind, payload string) bool {
	parts := strings.Split(rule, ",")
	if len(parts) < 3 || !strings.EqualFold(strings.TrimSpace(parts[0]), kind) {
		return false
	}
	if kind == "DOMAIN" {
		host, err := NormalizeDomain(strings.TrimSpace(parts[1]))
		return err == nil && host == payload
	}
	prefix, err := NormalizeIPPrefix(strings.TrimSpace(parts[1]))
	return err == nil && ipRuleKind(prefix) == kind && prefix == payload
}

func ruleDiff(before []byte, kind, rule, payload string, noChange bool) string {
	ruleKind := strings.Split(rule, ",")[0]
	if noChange {
		return "No file change: this exact " + ruleKind + " rule is already first and has no duplicate entries."
	}
	key := "rules"
	if kind == "verge" {
		key = "prepend"
	}
	var lines []string
	lines = append(lines, "@@ "+key+" (zero-based order) @@")
	if doc, err := decodeYAML(before); err == nil {
		if seq := mappingValue(doc.Content[0], key); seq != nil {
			for index, node := range seq.Content {
				if sameRuleTarget(node.Value, ruleKind, payload) {
					lines = append(lines, fmt.Sprintf("- [%d] %s", index, core.Sanitize(node.Value)))
				}
			}
		}
	}
	lines = append(lines, "+ [0] "+rule, "All other entries retain their relative order.")
	return strings.Join(lines, "\n")
}
func sha(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
