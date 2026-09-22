package managedcore

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"go.yaml.in/yaml/v3"
)

func windowsVergeFiles(r Request, profile []byte, secret, uid string, before *WindowsProxyState) (map[string][]byte, error) {
	files := map[string][]byte{}
	prefix := uid
	profileName := prefix + ".yaml"
	options := map[string]string{"merge": prefix + "_merge", "script": prefix + "_script", "rules": prefix + "_rules", "proxies": prefix + "_proxies", "groups": prefix + "_groups"}
	selected := []map[string]string{}
	names := make([]string, 0, len(r.CloneSelections))
	for name := range r.CloneSelections {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		selected = append(selected, map[string]string{"name": name, "now": r.CloneSelections[name]})
	}
	items := []any{map[string]any{"uid": uid, "type": "local", "name": r.Name, "file": profileName, "desc": "Owned lazyclash profile", "updated": time.Now().Unix(), "option": options, "selected": selected}}
	files["profiles/"+profileName] = profile
	for _, kind := range []string{"merge", "script", "rules", "proxies", "groups"} {
		file := options[kind] + ".yaml"
		var data []byte
		switch kind {
		case "merge":
			data = []byte("{}\n")
		case "script":
			file = options[kind] + ".js"
			data = []byte("function main(config) { return config; }\n")
		default:
			data = []byte("prepend: []\nappend: []\ndelete: []\n")
		}
		files["profiles/"+file] = data
		items = append(items, map[string]any{"uid": options[kind], "type": kind, "file": file})
	}
	manifest, err := yaml.Marshal(map[string]any{"current": uid, "items": items})
	if err != nil {
		return nil, err
	}
	files["profiles.yaml"] = manifest
	clash, err := yaml.Marshal(map[string]any{"mixed-port": r.MixedPort, "allow-lan": false, "bind-address": "127.0.0.1", "mode": "rule", "external-controller": fmt.Sprintf("127.0.0.1:%d", r.ControllerPort), "secret": secret, "tun": map[string]any{"enable": false}})
	if err != nil {
		return nil, err
	}
	files["config.yaml"] = clash
	files["verge.yaml"], err = yaml.Marshal(map[string]any{
		"clash_core": "verge-mihomo", "verge_mixed_port": r.MixedPort,
		"verge_socks_enabled": false, "verge_http_enabled": false,
		"enable_external_controller": true, "enable_auto_launch": false,
		"enable_silent_start": true, "enable_system_proxy": false, "enable_tun_mode": false,
		"auto_check_update": false, "enable_builtin_enhanced": false,
		"enable_dns_settings": false, "enable_proxy_guard": false,
		"proxy_host": "127.0.0.1", "proxy_auto_config": false,
		"use_default_bypass": false, "enable_bypass_check": false,
		"system_proxy_bypass": windowsAppliedBypass("verge", before),
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}
func windowsTarget(instance Instance, p Plan, secretPath string) config.Target {
	target := config.Target{ID: instance.ID, Name: instance.Name, SSHHost: instance.SSHHost, Controller: p.Controller, ProbeProxy: p.ProbeProxy, SecretFile: secretPath, ManagedCoreID: instance.ID, HostOS: "windows", Checks: append([]config.DiagnosticCheck(nil), p.Request.CloneChecks...)}
	if instance.Client == "verge" {
		data := strings.TrimRight(strings.ReplaceAll(p.Host.VergeDataDir, `\`, "/"), "/")
		source := winJoin(data, "profiles", instance.ProfileUID+".yaml")
		binary := winJoin(instance.AppRoot, "verge-mihomo.exe")
		target.Configs = []config.CoreConfig{{ID: "managed", Name: "Owned native Verge profile", Path: source}}
		target.ConfigSource = &config.ConfigSource{Kind: "verge", Version: "2.5.2", DataDir: data, ProfileUID: instance.ProfileUID, Binary: binary, Home: data}
		target.RuleSource = &config.RuleSource{Kind: "verge", Version: "2.5.2", DataDir: data, ProfileUID: instance.ProfileUID}
	} else {
		home := winJoin(instance.Root, "home")
		binary := winJoin(instance.Root, "bin", "mihomo.exe")
		source := winJoin(home, "config.yaml")
		target.Configs = []config.CoreConfig{{ID: "managed", Name: "Owned Windows profile", Path: source}}
		target.ConfigSource = &config.ConfigSource{Kind: "native", ConfigID: "managed", Binary: binary, Home: home}
		target.RuleSource = &config.RuleSource{Kind: "mihomo", ConfigID: "managed", Binary: binary, Home: home}
	}
	return target
}
func validateWindowsProfile(profile []byte) error {
	var doc map[string]any
	if yaml.Unmarshal(profile, &doc) != nil {
		return errors.New("invalid Windows profile")
	}
	// Foreground core validation has no Windows OS sandbox. Block executable
	// hooks and injected OS routing before any owned binary receives this YAML.
	for _, key := range []string{"post-up", "post-down", "interface-name", "routing-mark"} {
		if v, ok := doc[key]; ok && v != nil && fmt.Sprint(v) != "" && fmt.Sprint(v) != "0" {
			return fmt.Errorf("Windows clone requires explicit removal of host-specific %s", key)
		}
	}
	if tun, ok := doc["tun"].(map[string]any); ok && tun["enable"] == true {
		return errors.New("Windows initial deployment requires TUN disabled")
	}
	if mode, _ := doc["mode"].(string); strings.ToLower(mode) != "rule" {
		return errors.New("Windows initial deployment requires Rule mode")
	}
	return nil
}
