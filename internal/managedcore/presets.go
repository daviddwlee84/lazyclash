package managedcore

import (
	"bufio"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"sort"
	"strings"
)

//go:embed assets/rules
var ruleAssets embed.FS

type Preset struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
	Categories  []string `json:"categories"`
	Licenses    []string `json:"licenses"`
}
type rulesManifest struct {
	Version string            `json:"version"`
	Files   map[string]string `json:"files"`
}

func Presets() ([]Preset, error) {
	m, err := verifiedRuleManifest()
	if err != nil {
		return nil, err
	}
	return []Preset{{Name: "cn-split", Description: "Local/VPN bypass; reject, direct and proxy categories; China domains/IPs direct; remaining traffic PROXY", Version: m.Version, Categories: []string{"reject", "direct", "proxy", "ai", "apple", "media-global", "media-hkmt"}, Licenses: []string{"Handmade rules: MIT", "MetaCubeX mirrored data: GPL-3.0 (original source and notices retained)"}}, {Name: "simple", Description: "Local/VPN bypass; remaining traffic PROXY", Version: m.Version, Licenses: []string{"Handmade rules: MIT", "MetaCubeX mirrored data: GPL-3.0 (original source and notices retained)"}}}, nil
}

func verifiedRuleManifest() (rulesManifest, error) {
	var manifest rulesManifest
	data, err := ruleAssets.ReadFile("assets/rules/manifest.json")
	if err != nil || json.Unmarshal(data, &manifest) != nil || !digestPattern.MatchString(manifest.Version) {
		return manifest, errors.New("embedded rules manifest is invalid")
	}
	err = fs.WalkDir(ruleAssets, "assets/rules", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative := strings.TrimPrefix(path, "assets/rules/")
		if relative == "manifest.json" || relative == "origin.json" {
			return nil
		}
		data, err := ruleAssets.ReadFile(path)
		if err != nil {
			return err
		}
		if manifest.Files[relative] != hashBytes(data) {
			return fmt.Errorf("embedded rules checksum mismatch: %s", relative)
		}
		if strings.Contains(relative, "/geoip/") {
			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if _, err := netip.ParsePrefix(line); err != nil {
					return errors.New("embedded IP rules contain an invalid prefix")
				}
			}
			return scanner.Err()
		}
		return nil
	})
	return manifest, err
}

func presetRules(preset string, categories []string, roles map[string]string) (map[string]any, []any, map[string][]byte, string, error) {
	manifest, err := verifiedRuleManifest()
	if err != nil {
		return nil, nil, nil, "", err
	}
	if preset != "cn-split" && preset != "simple" {
		return nil, nil, nil, "", errors.New("preset must be cn-split or simple")
	}
	providers := map[string]any{}
	resources := map[string][]byte{}
	rules := []any{}
	add := func(id, path, behavior, policy string) error {
		data, err := ruleAssets.ReadFile("assets/rules/" + path)
		if err != nil {
			return err
		}
		name := "lazyclash-" + id
		relative := "rules/" + name + ".list"
		resources[relative] = data
		providers[name] = map[string]any{"type": "file", "behavior": behavior, "format": "text", "path": "./" + relative}
		rules = append(rules, "RULE-SET,"+name+","+policy)
		return nil
	}
	if err := add("private-domain", "vendor/metacubex/geo/geosite/private.list", "domain", "DIRECT"); err != nil {
		return nil, nil, nil, "", err
	}
	if err := add("private-ip", "vendor/metacubex/geo/geoip/private.list", "ipcidr", "DIRECT"); err != nil {
		return nil, nil, nil, "", err
	}
	if preset == "cn-split" {
		selected := map[string]bool{"reject": true, "direct": true, "proxy": true}
		for _, category := range categories {
			switch category {
			case "reject", "direct", "proxy", "ai", "apple", "media-global", "media-hkmt":
				selected[category] = true
			default:
				return nil, nil, nil, "", errors.New("unknown rule category")
			}
		}
		for _, category := range []string{"reject", "ai", "apple", "media-hkmt", "media-global", "direct", "proxy"} {
			if !selected[category] {
				continue
			}
			policy := roles[category]
			if policy == "" {
				switch category {
				case "reject":
					policy = "REJECT"
				case "direct":
					policy = "DIRECT"
				default:
					policy = "PROXY"
				}
			}
			if strings.ContainsAny(policy, ",\r\n") {
				return nil, nil, nil, "", errors.New("rule category policy contains unsupported separators")
			}
			if err := add(category, "clash/"+category+".list", "classical", policy); err != nil {
				return nil, nil, nil, "", err
			}
		}
		if err := add("cn-domain", "vendor/metacubex/geo/geosite/cn.list", "domain", "DIRECT"); err != nil {
			return nil, nil, nil, "", err
		}
		if err := add("cn-ip", "vendor/metacubex/geo/geoip/cn.list", "ipcidr", "DIRECT"); err != nil {
			return nil, nil, nil, "", err
		}
	}
	rules = append(rules, "MATCH,PROXY")
	for _, path := range []string{"LICENSE", "THIRD_PARTY.md", "upstreams.lock.json", "vendor/metacubex/LICENSE", "vendor/metacubex/README.md", "manifest.json", "origin.json"} {
		data, err := ruleAssets.ReadFile("assets/rules/" + path)
		if err != nil {
			return nil, nil, nil, "", err
		}
		resources["rules/provenance/"+path] = data
	}
	return providers, rules, resources, manifest.Version, nil
}

func sortedResourceNames(resources map[string][]byte) []string {
	names := make([]string, 0, len(resources))
	for name := range resources {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
