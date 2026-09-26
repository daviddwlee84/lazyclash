package managedcore

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/hostpath"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"go.yaml.in/yaml/v3"
)

// NativeMirror is a guarded copy of one bound Verge data directory: its
// profile index, every profile/companion, owner settings and geodata. Review
// output carries only hashes; bytes stay in private memory.
type NativeMirror struct {
	SourceID   string            `json:"source_id"`
	ProfileUID string            `json:"profile_uid"`
	SHA256     map[string]string `json:"sha256"`
	Warnings   []string          `json:"warnings"`
	Files      map[string][]byte `json:"-"`
}

type nativeMirrorKey struct{}

// WithNativeMirror carries a mirror privately into Preview/Apply.
func WithNativeMirror(ctx context.Context, mirror NativeMirror) context.Context {
	return context.WithValue(ctx, nativeMirrorKey{}, mirror)
}

func nativeMirrorFrom(ctx context.Context) (NativeMirror, bool) {
	mirror, ok := ctx.Value(nativeMirrorKey{}).(NativeMirror)
	return mirror, ok
}

// Runtime, cache and host-local state is never mirrored: Verge regenerates
// clash-verge.yaml, cache.db holds host-specific fake-IP mappings, and
// selections are applied through the controller instead.
var nativeMirrorSettings = []string{"profiles.yaml", "config.yaml", "verge.yaml"}
var nativeMirrorOptional = []string{"dns_config.yaml", "geoip.dat", "geosite.dat", "Country.mmdb", "ASN.mmdb"}

// SnapshotVergeNative reads the bound Verge data directory twice and fails if
// anything changed between the passes. It never executes Merge/Script code.
func SnapshotVergeNative(ctx context.Context, target config.Target, opts Options) (NativeMirror, error) {
	reader := func(ctx context.Context, p string) (rulework.HostFile, error) {
		if target.SSHHost == "" {
			return cloneReadLocal(p)
		}
		return cloneReadRemote(ctx, target, p, false)
	}
	return snapshotVergeNative(ctx, target, reader)
}

func snapshotVergeNative(ctx context.Context, target config.Target, reader cloneReadFunc) (NativeMirror, error) {
	c := target.ConfigSource
	if c == nil || c.Kind != "verge" || target.HostOS == "windows" {
		return NativeMirror{}, errors.New("native mirror requires a saved macOS/Linux target bound to a Verge data directory")
	}
	if err := config.ValidateConfigSource(target); err != nil {
		return NativeMirror{}, err
	}
	pathOS := "darwin"
	root := c.DataDir
	pass := func() (map[string]rulework.HostFile, string, []string, error) {
		files := map[string]rulework.HostFile{}
		warnings := []string{}
		total := 0
		read := func(name string, optional bool) error {
			file, err := reader(ctx, hostpath.Join(pathOS, root, name))
			if err != nil {
				if optional {
					return nil
				}
				return fmt.Errorf("Verge data file %s is unavailable: %w", name, err)
			}
			if len(file.Data) > cloneFileLimit || file.SHA256 != hashBytes(file.Data) {
				return fmt.Errorf("Verge data file %s is oversized or inconsistent", name)
			}
			if file.Resolved != "" && !hostpath.Within(pathOS, root, file.Resolved) && !strings.HasPrefix(file.Resolved, "/private"+root) {
				return fmt.Errorf("Verge data file %s resolves outside its data directory", name)
			}
			total += len(file.Data)
			if total > cloneBundleLimit {
				return errors.New("Verge data mirror exceeds the 128 MiB private-memory limit")
			}
			files[name] = file
			return nil
		}
		for _, name := range nativeMirrorSettings {
			if err := read(name, false); err != nil {
				return nil, "", nil, err
			}
		}
		var index struct {
			Current string `yaml:"current"`
			Items   []struct {
				UID  string `yaml:"uid"`
				Type string `yaml:"type"`
				File string `yaml:"file"`
			} `yaml:"items"`
		}
		if err := cloneDecode(files["profiles.yaml"].Data, &index); err != nil {
			return nil, "", nil, errors.New("Verge profile index is invalid")
		}
		if index.Current == "" || index.Current != c.ProfileUID {
			return nil, "", nil, errors.New("the bound Verge profile is no longer current; rebind before mirroring")
		}
		for _, item := range index.Items {
			if item.File == "" {
				continue
			}
			clean := path.Clean(item.File)
			if strings.Contains(item.File, "/") || strings.Contains(item.File, `\`) || strings.HasPrefix(clean, ".") || clean != item.File {
				return nil, "", nil, errors.New("Verge profile index names a file outside profiles/")
			}
			if err := read("profiles/"+clean, true); err != nil {
				return nil, "", nil, err
			}
			if _, ok := files["profiles/"+clean]; !ok {
				if item.UID == index.Current {
					return nil, "", nil, errors.New("the active Verge profile file is missing")
				}
				warnings = append(warnings, "Skipped a profile index entry whose file is missing: "+item.UID)
			}
		}
		for _, name := range nativeMirrorOptional {
			if err := read(name, true); err != nil {
				return nil, "", nil, err
			}
		}
		return files, index.Current, warnings, nil
	}
	first, current, warnings, err := pass()
	if err != nil {
		return NativeMirror{}, err
	}
	second, _, _, err := pass()
	if err != nil {
		return NativeMirror{}, err
	}
	if len(first) != len(second) {
		return NativeMirror{}, errors.New("Verge data changed while mirroring; retry")
	}
	mirror := NativeMirror{SourceID: target.ID, ProfileUID: current, SHA256: map[string]string{}, Files: map[string][]byte{}, Warnings: append(warnings, "Verge Merge/Script companions are copied as data; Verge on the destination runs them exactly as the source does.")}
	for name, file := range first {
		if again, ok := second[name]; !ok || again.SHA256 != file.SHA256 {
			return NativeMirror{}, errors.New("Verge data changed while mirroring; retry")
		}
		mirror.SHA256[name] = file.SHA256
		mirror.Files[name] = append([]byte(nil), file.Data...)
	}
	return mirror, nil
}

var tailnetRoutes = []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"}

// darwinVergeFiles renders the destination data directory privately. Owner
// settings are rewritten here because the host helper deliberately has no YAML
// parser: a new controller secret, reviewed loopback ports, Tailnet exclusions
// from TUN, and a staged (TUN/system proxy/autostart off) plus final verge.yaml.
func darwinVergeFiles(r Request, files map[string][]byte, secret string) (map[string][]byte, []byte, []byte, []string, error) {
	out := map[string][]byte{}
	for name, data := range files {
		out[name] = append([]byte(nil), data...)
	}
	warnings := []string{}
	var clash map[string]any
	if err := yaml.Unmarshal(out["config.yaml"], &clash); err != nil || clash == nil {
		return nil, nil, nil, nil, errors.New("Verge config.yaml must be one YAML mapping")
	}
	if allow, _ := clash["allow-lan"].(bool); allow {
		warnings = append(warnings, "The source allowed LAN connections; the destination keeps allow-lan off.")
	}
	clash["secret"] = secret
	clash["external-controller"] = fmt.Sprintf("127.0.0.1:%d", r.ControllerPort)
	clash["mixed-port"] = r.MixedPort
	clash["allow-lan"] = false
	tun, _ := clash["tun"].(map[string]any)
	if tun == nil {
		tun = map[string]any{}
	}
	tun["enable"] = false
	excluded := []string{}
	if existing, ok := tun["route-exclude-address"].([]any); ok {
		for _, value := range existing {
			if s, ok := value.(string); ok {
				excluded = append(excluded, s)
			}
		}
	}
	excluded = uniqueStrings(append(append(excluded, tailnetRoutes...), r.Network.ExcludedRoutes...))
	tun["route-exclude-address"] = excluded
	if strict, _ := tun["strict-route"].(bool); strict {
		warnings = append(warnings, "The source TUN uses strict-route; SSH over Tailscale relies on the rollback watchdog if routing breaks.")
	}
	clash["tun"] = tun
	rendered, err := yaml.Marshal(clash)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	out["config.yaml"] = rendered
	var settings map[string]any
	if err = yaml.Unmarshal(out["verge.yaml"], &settings); err != nil || settings == nil {
		return nil, nil, nil, nil, errors.New("Verge verge.yaml must be one YAML mapping")
	}
	delete(out, "verge.yaml")
	for key := range settings {
		if key == "startup_script" || strings.HasPrefix(key, "webdav_") {
			if settings[key] != nil && settings[key] != "" {
				warnings = append(warnings, "Dropped host-executed or credential Verge setting "+key+".")
			}
			delete(settings, key)
		}
	}
	if bypass, _ := settings["system_proxy_bypass"].(string); strings.Contains(bypass, ";") {
		delete(settings, "system_proxy_bypass") // Windows-format cold-seed default
	}
	settings["verge_mixed_port"] = r.MixedPort
	settings["enable_external_controller"] = true
	final := map[string]any{}
	for k, v := range settings {
		final[k] = v
	}
	final["enable_tun_mode"] = r.Network.TUN
	final["enable_system_proxy"] = r.Network.SystemProxy
	final["enable_auto_launch"] = r.Boot
	settings["enable_tun_mode"] = false
	settings["enable_system_proxy"] = false
	settings["enable_auto_launch"] = false
	settings["enable_silent_start"] = true
	settings["auto_check_update"] = false
	staged, err := yaml.Marshal(settings)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	finalRaw, err := yaml.Marshal(final)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return out, staged, finalRaw, warnings, nil
}
