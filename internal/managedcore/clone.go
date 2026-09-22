package managedcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/hostpath"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"go.yaml.in/yaml/v3"
)

const cloneFileLimit = (24 << 20) - 4096 // base64 response remains below the 32 MiB SSH helper bound
const cloneBundleLimit = 128 << 20

type CloneGuard struct {
	Path        string `json:"path"`
	Resolved    string `json:"resolved"`
	SHA256      string `json:"sha256"`
	Fingerprint string `json:"fingerprint"`
	Size        int    `json:"size"`
}

// CloneSnapshot exposes only review metadata. Configuration, subscription URLs
// and credentials remain in private memory; callers must not print its buffers.
type CloneSnapshot struct {
	SourceID       string                   `json:"source_id"`
	SourceBinding  string                   `json:"source_binding"`
	SourceKind     string                   `json:"source_kind"`
	ProfileUID     string                   `json:"profile_uid,omitempty"`
	Hash           string                   `json:"sha256"`
	ProfileSHA256  string                   `json:"profile_sha256"`
	ResourceSHA256 map[string]string        `json:"resource_sha256"`
	Guards         []CloneGuard             `json:"guards"`
	Selections     map[string]string        `json:"selections"`
	Checks         []config.DiagnosticCheck `json:"checks"`
	Warnings       []string                 `json:"warnings"`
	Profile        []byte                   `json:"-"`
	Resources      map[string][]byte        `json:"-"`
}

type cloneReadFunc func(context.Context, string) (rulework.HostFile, error)
type cloneContextKey struct{}

// SnapshotTarget reads one explicit source owner and its current core. It never
// executes Verge Scripts, downloads provider replacements, stages files, reloads
// a core, changes selectors, or writes a receipt.
func SnapshotTarget(ctx context.Context, target config.Target, opts Options) (CloneSnapshot, error) {
	reader := func(ctx context.Context, path string) (rulework.HostFile, error) {
		if target.ConfigSource != nil && target.ConfigSource.Kind == "docker" {
			return cloneReadRemote(ctx, target, path, true)
		}
		if target.ManagedCoreID != "" {
			response, err := SourceOperation(ctx, target, configwork.HostRequest{Op: "read", Path: path}, opts)
			return response.File, err
		}
		if target.SSHHost == "" {
			return cloneReadLocal(path)
		}
		return cloneReadRemote(ctx, target, path, false)
	}
	return snapshotTarget(ctx, target, opts, reader)
}

func snapshotTarget(ctx context.Context, target config.Target, opts Options, reader cloneReadFunc) (CloneSnapshot, error) {
	if target.ID == "" || target.Transient || target.TransportOverride || target.ConfigSource == nil {
		return CloneSnapshot{}, errors.New("cloning requires a saved source target with an explicit configuration owner")
	}
	c := target.ConfigSource
	pathOS := target.HostOS
	if pathOS == "windows" && target.ManagedCoreID == "" {
		return CloneSnapshot{}, errors.New("Windows source snapshots require a lazyclash-owned client; use a private portable YAML input")
	}
	for _, p := range []string{c.DataDir, c.Home, c.CorePath} {
		if pathOS != "windows" && regexp.MustCompile(`^[A-Za-z]:[/\\]`).MatchString(p) {
			return CloneSnapshot{}, errors.New("Windows source snapshots are not supported by this Unix source adapter yet; use a private portable YAML input")
		}
	}
	if err := config.ValidateConfigSource(target); err != nil {
		return CloneSnapshot{}, err
	}
	if err := config.ValidateDiagnosticChecks(target.Checks); err != nil {
		return CloneSnapshot{}, err
	}
	if c.Kind != "native" && c.Kind != "mihomo" && c.Kind != "verge" && c.Kind != "docker" {
		return CloneSnapshot{}, errors.New("source cloning currently supports bound native, Docker and Verge owners")
	}
	budget := 2 * time.Minute
	// An owned Windows source uses private file RPCs for each guarded read and
	// re-read. Preserve every consistency check while allowing that bounded cost.
	if pathOS == "windows" && target.ManagedCoreID != "" {
		budget = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	snapshot := CloneSnapshot{SourceID: target.ID, SourceBinding: configwork.Binding(target), SourceKind: c.Kind, ResourceSHA256: map[string]string{}, Selections: map[string]string{}, Checks: copyCloneChecks(target.Checks), Resources: map[string][]byte{}, Guards: []CloneGuard{}, Warnings: []string{"This flattened profile includes required cached dependencies; GUI scripts, subscription scheduling state and source management credentials are excluded."}}
	files := map[string]rulework.HostFile{}
	total := 0
	read := func(path string) (rulework.HostFile, error) {
		if len(path) > 4096 || !hostpath.IsAbs(pathOS, path) || strings.IndexFunc(path, unicode.IsControl) >= 0 {
			return rulework.HostFile{}, errors.New("clone source paths must be absolute and contain no control characters")
		}
		path = hostpath.Clean(pathOS, path)
		if file, ok := files[path]; ok {
			return file, nil
		}
		file, err := reader(ctx, path)
		if err != nil {
			return file, err
		}
		if len(file.Data) > cloneFileLimit || file.Resolved == "" || file.Fingerprint == "" || file.SHA256 != hashBytes(file.Data) {
			return file, errors.New("source returned an incomplete, oversized or inconsistent file snapshot")
		}
		total += len(file.Data)
		if total > cloneBundleLimit {
			return file, errors.New("source snapshot exceeds the 128 MiB private-memory limit")
		}
		file.Path = path
		files[path] = file
		return file, nil
	}
	home, profilePath := c.Home, ""
	resolvedHome := home
	if target.SSHHost == "" && pathOS != "windows" && c.Kind != "docker" && home != "" {
		if resolved, e := filepath.EvalSymlinks(home); e == nil {
			resolvedHome = resolved
		}
	}
	switch c.Kind {
	case "native", "mihomo":
		for _, entry := range target.Configs {
			if entry.ID == c.ConfigID {
				profilePath = entry.Path
				break
			}
		}
	case "docker":
		profilePath = c.CorePath
	case "verge":
		home = c.DataDir
		snapshot.ProfileUID = c.ProfileUID
		manifest, err := read(hostpath.Join(pathOS, home, "profiles.yaml"))
		if err != nil {
			return snapshot, err
		}
		resolvedHome = hostpath.Dir(pathOS, manifest.Resolved)
		var index struct {
			Current string `yaml:"current"`
			Items   []struct {
				UID    string         `yaml:"uid"`
				Type   string         `yaml:"type"`
				File   string         `yaml:"file"`
				Option map[string]any `yaml:"option"`
			} `yaml:"items"`
		}
		if err = cloneDecode(manifest.Data, &index); err != nil {
			return snapshot, errors.New("Verge profile index is invalid")
		}
		if index.Current == "" || index.Current != c.ProfileUID {
			return snapshot, errors.New("the bound Verge profile is no longer current; rebind before cloning")
		}
		byUID := map[string]int{}
		for i, item := range index.Items {
			if item.UID == "" {
				return snapshot, errors.New("Verge profile index has an empty UID")
			}
			if _, found := byUID[item.UID]; found {
				return snapshot, errors.New("Verge profile index has duplicate UIDs")
			}
			byUID[item.UID] = i
		}
		position, found := byUID[index.Current]
		if !found {
			return snapshot, errors.New("active Verge profile is absent from its index")
		}
		active := index.Items[position]
		if active.Type != "local" && active.Type != "remote" {
			return snapshot, errors.New("active Verge profile is not a local or remote YAML profile")
		}
		ids := []string{active.UID}
		for _, uid := range []string{"Merge", "Script"} {
			if _, ok := byUID[uid]; ok {
				ids = append(ids, uid)
			}
		}
		for _, key := range []string{"proxies", "groups", "rules", "merge", "script"} {
			if uid, _ := active.Option[key].(string); uid != "" {
				if _, ok := byUID[uid]; !ok {
					return snapshot, errors.New("active Verge profile references a missing companion")
				}
				ids = append(ids, uid)
			}
		}
		for _, uid := range uniqueStrings(ids) {
			item := index.Items[byUID[uid]]
			path, err := cloneChildOS(pathOS, hostpath.Join(pathOS, home, "profiles"), item.File)
			if err != nil {
				return snapshot, err
			}
			file, err := read(path)
			if err != nil {
				return snapshot, err
			}
			if !hostpath.Within(pathOS, hostpath.Join(pathOS, resolvedHome, "profiles"), file.Resolved) {
				return snapshot, errors.New("Verge profile companion resolves outside its bound directory")
			}
		}
		// Owner settings participate in native generation, even when their
		// host-specific values are removed from the portable result.
		for _, name := range []string{"config.yaml", "verge.yaml"} {
			if _, err := read(hostpath.Join(pathOS, home, name)); err != nil {
				return snapshot, err
			}
		}
		profilePath = hostpath.Join(pathOS, home, "clash-verge.yaml")
		snapshot.Warnings = append(snapshot.Warnings, "Verge's already generated YAML is copied; later Merge/Script code is guarded as source context but is never executed or copied to the destination.")
	}
	if home == "" || profilePath == "" {
		return snapshot, errors.New("source owner has no explicit profile path and core home")
	}
	profile, err := read(profilePath)
	if err != nil {
		return snapshot, err
	}
	if len(profile.Data) > 8<<20 {
		return snapshot, errors.New("source profile exceeds 8 MiB")
	}
	var document map[string]any
	if err = cloneDecode(profile.Data, &document); err != nil || document == nil {
		return snapshot, errors.New("source profile must be one YAML mapping")
	}
	if _, ok := document["proxy-groups"].([]any); !ok {
		return snapshot, errors.New("source profile does not declare proxy-groups")
	}
	if c.Kind == "docker" {
		snapshot.Warnings = append(snapshot.Warnings, "Docker configuration and dependency bytes are read from the bound running container, not a potentially stale single-file host mount.")
	}
	stripped := stripCloneHostFields(document)
	if len(stripped) > 0 {
		snapshot.Warnings = append(snapshot.Warnings, "Destination-owned fields removed: "+strings.Join(stripped, ", "))
	}
	resourcePaths, err := cloneResourcePaths(document, home, pathOS)
	if err != nil {
		return snapshot, err
	}
	resourceFiles := map[string][]byte{}
	for _, path := range resourcePaths {
		file, e := read(path)
		if e != nil {
			return snapshot, fmt.Errorf("required source dependency is unavailable; clone does not fetch a replacement: %w", e)
		}
		if !hostpath.Within(pathOS, resolvedHome, file.Resolved) {
			return snapshot, errors.New("a source dependency resolves outside the bound core home; provide an explicit portable YAML bundle instead")
		}
		relative, _ := hostpath.Rel(pathOS, home, path)
		resourceFiles[filepath.ToSlash(relative)] = append([]byte(nil), file.Data...)
	}
	resourceCtx := context.WithValue(ctx, profileSnapshotKey{}, profileSnapshot{Home: home, Files: resourceFiles, OS: pathOS})
	resourceCtx = context.WithValue(resourceCtx, cloneContextKey{}, snapshot.Warnings)
	if err = profileResources(resourceCtx, document, "", snapshot.Resources); err != nil {
		return snapshot, err
	}
	snapshot.Profile, err = yaml.Marshal(document)
	if err != nil {
		return snapshot, errors.New("cannot render portable cloned profile")
	}
	snapshot.ProfileSHA256 = hashBytes(snapshot.Profile)
	for name, data := range snapshot.Resources {
		snapshot.ResourceSHA256[name] = hashBytes(data)
	}
	open := opts.Open
	if open == nil {
		open = connection.Open
	}
	client, closer, err := open(ctx, target, true)
	if closer != nil {
		defer closer.Close()
	}
	if client != nil {
		defer client.Close()
	}
	if err != nil {
		return snapshot, err
	}
	if client == nil {
		return snapshot, errors.New("source controller is unavailable; active selectors cannot be verified")
	}
	proxies, err := client.Proxies(ctx)
	if err != nil {
		return snapshot, err
	}
	snapshot.Selections, err = cloneSelections(document, proxies)
	if err != nil {
		return snapshot, err
	}
	// Re-read every input and selected choice to reject a mixed snapshot if a
	// native owner, provider refresh or another controller changed it mid-read.
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		original := files[path]
		current, e := reader(ctx, path)
		if e != nil {
			return snapshot, e
		}
		if current.Fingerprint != original.Fingerprint || current.SHA256 != original.SHA256 || current.Resolved != original.Resolved {
			return snapshot, errors.New("source changed while snapshotting; retry from a fresh source preview")
		}
		snapshot.Guards = append(snapshot.Guards, CloneGuard{Path: path, Resolved: original.Resolved, SHA256: original.SHA256, Fingerprint: original.Fingerprint, Size: len(original.Data)})
	}
	proxies, err = client.Proxies(ctx)
	if err != nil {
		return snapshot, err
	}
	selected, err := cloneSelections(document, proxies)
	if err != nil {
		return snapshot, err
	}
	if !reflect.DeepEqual(selected, snapshot.Selections) {
		return snapshot, errors.New("source selector choices changed while snapshotting; retry")
	}
	snapshot.Hash = cloneSnapshotHash(snapshot)
	return snapshot, nil
}

func CheckCloneSnapshot(ctx context.Context, target config.Target, snapshot CloneSnapshot, opts Options) error {
	current, err := SnapshotTarget(ctx, target, opts)
	if err != nil {
		return err
	}
	if snapshot.Hash == "" || current.Hash != snapshot.Hash {
		return errors.New("clone source changed since preview; review a fresh clone plan")
	}
	return nil
}

// ApplyCloneToRequest keeps source resource bytes in a private context and pins
// public source metadata in the destination preview digest. Callers must create
// a fresh snapshot before applying and retain normal destination digest checks.
func ApplyCloneToRequest(ctx context.Context, request Request, snapshot CloneSnapshot) (context.Context, Request, error) {
	if snapshot.Hash == "" || snapshot.Hash != cloneSnapshotHash(snapshot) || snapshot.ProfileSHA256 != hashBytes(snapshot.Profile) {
		return ctx, request, errors.New("clone snapshot metadata or private profile changed")
	}
	for name, data := range snapshot.Resources {
		if snapshot.ResourceSHA256[name] != hashBytes(data) {
			return ctx, request, errors.New("clone resource changed after snapshot")
		}
	}
	if len(snapshot.Resources) != len(snapshot.ResourceSHA256) {
		return ctx, request, errors.New("clone resource inventory changed after snapshot")
	}
	request.Input = append([]byte(nil), snapshot.Profile...)
	request.InputKind = "yaml"
	request.InputBaseDir = ""
	request.Preset = "preserve"
	request.Categories = nil
	request.PolicyRoles = nil
	request.CloneSourceID, request.CloneSourceSHA256 = snapshot.SourceID, snapshot.Hash
	request.CloneSelections = copyCloneSelections(snapshot.Selections)
	request.CloneChecks = copyCloneChecks(snapshot.Checks)
	files := map[string][]byte{}
	for name, data := range snapshot.Resources {
		files[name] = append([]byte(nil), data...)
	}
	ctx = context.WithValue(ctx, profileSnapshotKey{}, profileSnapshot{Home: "/", Files: files})
	ctx = context.WithValue(ctx, cloneContextKey{}, append([]string(nil), snapshot.Warnings...))
	return ctx, request, nil
}

func cloneSnapshotHash(snapshot CloneSnapshot) string {
	snapshot.Hash = ""
	return hashJSONClone(snapshot)
}
func hashJSONClone(value any) string { raw, _ := json.Marshal(value); return hashBytes(raw) }
func copyCloneSelections(source map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range source {
		out[k] = v
	}
	return out
}
func copyCloneChecks(source []config.DiagnosticCheck) []config.DiagnosticCheck {
	out := append([]config.DiagnosticCheck{}, source...)
	for i := range out {
		out[i].ExpectedStatuses = append([]int(nil), out[i].ExpectedStatuses...)
	}
	return out
}
func cloneDecode(data []byte, out any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("multiple or malformed YAML documents")
	}
	return nil
}
func cloneChildOS(pathOS, root, path string) (string, error) {
	if pathOS == "windows" {
		path = strings.ReplaceAll(path, `\`, "/")
	}
	if path == "" || hostpath.IsAbs(pathOS, path) || strings.Contains(path, "\\") || strings.Contains(path, ":") || strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return "", errors.New("source companion path must stay inside its bound directory")
	}
	full := hostpath.Join(pathOS, root, path)
	if !hostpath.Within(pathOS, root, full) {
		return "", errors.New("source companion path escapes its bound directory")
	}
	return full, nil
}

func cloneSelections(document map[string]any, proxies map[string]core.Proxy) (map[string]string, error) {
	selections := map[string]string{}
	names := map[string]bool{}
	for _, entry := range document["proxy-groups"].([]any) {
		group, ok := entry.(map[string]any)
		if !ok {
			return nil, errors.New("source proxy group is not a mapping")
		}
		name, _ := group["name"].(string)
		kind, _ := group["type"].(string)
		if name == "" || names[name] {
			return nil, errors.New("source proxy group has an empty or duplicate name")
		}
		names[name] = true
		runtime, found := proxies[name]
		if !found {
			return nil, errors.New("source profile group is absent from the running core; activate its owner before cloning")
		}
		if kind != "select" {
			continue
		}
		if !strings.EqualFold(runtime.Type, "Selector") || runtime.Now == "" {
			return nil, errors.New("source manual group has no verified runtime selection")
		}
		valid := false
		for _, member := range runtime.All {
			valid = valid || member == runtime.Now
		}
		if !valid {
			return nil, errors.New("source manual selection is not a runtime group member")
		}
		declared := false
		for _, member := range toStrings(group["proxies"]) {
			declared = declared || member == runtime.Now
		}
		dynamic := len(toStrings(group["use"])) > 0 || group["include-all"] == true || group["include-all-proxies"] == true || group["include-all-providers"] == true
		if !declared && !dynamic {
			return nil, errors.New("source manual selection is absent from the profile's declared members; activate its owner before cloning")
		}
		selections[name] = runtime.Now
	}
	return selections, nil
}

func stripCloneHostFields(document map[string]any) []string {
	removed := map[string]bool{}
	for _, key := range []string{"secret", "external-controller", "external-controller-tls", "external-controller-unix", "external-controller-pipe", "external-controller-cors", "external-ui", "external-ui-name", "external-ui-url", "mixed-port", "port", "socks-port", "redir-port", "tproxy-port", "allow-lan", "bind-address", "authentication", "skip-auth-prefixes", "lan-allowed-ips", "lan-disallowed-ips", "listeners", "tun", "interface-name", "routing-mark", "ebpf", "script", "post-up", "post-down", "system-proxy"} {
		if _, ok := document[key]; ok {
			delete(document, key)
			removed[key] = true
		}
	}
	var walk func(any)
	walk = func(value any) {
		switch values := value.(type) {
		case map[string]any:
			for key, item := range values {
				if key == "interface-name" || key == "routing-mark" || key == "post-up" || key == "post-down" {
					delete(values, key)
					removed[key] = true
				} else {
					walk(item)
				}
			}
		case []any:
			for _, item := range values {
				walk(item)
			}
		}
	}
	walk(document)
	if dns, ok := document["dns"].(map[string]any); ok {
		if _, ok := dns["listen"]; ok {
			delete(dns, "listen")
			removed["dns.listen"] = true
		}
	}
	document["mode"] = "rule"
	settings, _ := document["profile"].(map[string]any)
	if settings == nil {
		settings = map[string]any{}
	}
	settings["store-selected"] = true
	document["profile"] = settings
	keys := make([]string, 0, len(removed))
	for key := range removed {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func cloneResourcePaths(document map[string]any, home, pathOS string) ([]string, error) {
	paths := map[string]bool{}
	add := func(value string) error {
		if pathOS == "windows" {
			value = strings.ReplaceAll(value, `\`, "/")
			if strings.HasPrefix(value, "/") && !hostpath.IsAbs(pathOS, value) {
				return errors.New("Windows clone dependencies require a drive-qualified or relative path")
			}
		}
		if value == "" || strings.Contains(value, "://") || strings.Contains(value, "\\") || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return errors.New("source dependency is not a supported local cache path")
		}
		path := value
		if !hostpath.IsAbs(pathOS, path) {
			path = hostpath.Join(pathOS, home, path)
		}
		path = hostpath.Clean(pathOS, path)
		if !hostpath.Within(pathOS, home, path) {
			return errors.New("source dependency escapes the bound core home; provide a portable YAML bundle")
		}
		paths[path] = true
		return nil
	}
	for _, section := range []string{"proxy-providers", "rule-providers"} {
		providers, _ := document[section].(map[string]any)
		for _, value := range providers {
			provider, ok := value.(map[string]any)
			if !ok {
				return nil, errors.New("source provider is not a mapping")
			}
			if provider["type"] == "inline" {
				continue
			}
			path, _ := provider["path"].(string)
			if err := add(path); err != nil {
				return nil, err
			}
		}
	}
	var walk func(any) error
	walk = func(value any) error {
		switch values := value.(type) {
		case map[string]any:
			for key, item := range values {
				if err := walk(key); err != nil {
					return err
				}
				if key == "geoip" && item == true {
					file := "Country.mmdb"
					if document["geodata-mode"] == true {
						file = "GeoIP.dat"
					}
					if err := add(file); err != nil {
						return err
					}
				}
				fileKey := key == "certificate" || key == "certificate-path" || key == "private-key-path" || key == "ca" || (key == "private-key" && values["certificate"] != nil)
				if text, ok := item.(string); ok && fileKey && text != "" && !strings.Contains(text, "-----BEGIN") {
					if err := add(text); err != nil {
						return err
					}
				} else if err := walk(item); err != nil {
					return err
				}
			}
		case []any:
			for _, item := range values {
				if err := walk(item); err != nil {
					return err
				}
			}
		case string:
			upper := strings.ToUpper(values)
			if strings.Contains(upper, "GEOSITE,") || strings.Contains(upper, "GEOSITE:") {
				if err := add("GeoSite.dat"); err != nil {
					return err
				}
			}
			if strings.Contains(upper, "GEOIP,") || strings.Contains(upper, "GEOIP:") {
				file := "Country.mmdb"
				if document["geodata-mode"] == true {
					file = "GeoIP.dat"
				}
				if err := add(file); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(document); err != nil {
		return nil, err
	}
	if dns, ok := document["dns"].(map[string]any); ok {
		if fallback, ok := dns["fallback-filter"].(map[string]any); ok && fallback["geoip"] == true {
			file := "Country.mmdb"
			if document["geodata-mode"] == true {
				file = "GeoIP.dat"
			}
			if err := add(file); err != nil {
				return nil, err
			}
		}
	}
	result := make([]string, 0, len(paths))
	for path := range paths {
		result = append(result, path)
	}
	sort.Strings(result)
	return result, nil
}

func cloneReadLocal(path string) (rulework.HostFile, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return rulework.HostFile{}, errors.New("required source file is not readable")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return rulework.HostFile{}, errors.New("required source file is not readable")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() > cloneFileLimit {
		return rulework.HostFile{}, errors.New("source must be a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, cloneFileLimit+1))
	if err != nil || len(data) > cloneFileLimit {
		return rulework.HostFile{}, errors.New("source file could not be read within its bound")
	}
	after, err := file.Stat()
	current, currentErr := os.Stat(resolved)
	resolvedNow, resolveErr := filepath.EvalSymlinks(path)
	if err != nil || currentErr != nil || resolveErr != nil || resolvedNow != resolved || !os.SameFile(before, after) || !os.SameFile(before, current) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || before.Mode() != after.Mode() || before.Size() != current.Size() || before.ModTime() != current.ModTime() || before.Mode() != current.Mode() {
		return rulework.HostFile{}, errors.New("source file changed during read")
	}
	sha := hashBytes(data)
	fingerprint := hashJSONClone([]any{resolved, before.Size(), before.ModTime().UnixNano(), uint32(before.Mode()), sha})
	return rulework.HostFile{Path: path, Resolved: resolved, Data: data, SHA256: sha, Fingerprint: fingerprint, Mode: uint32(before.Mode().Perm())}, nil
}

func cloneReadRemote(ctx context.Context, target config.Target, path string, docker bool) (rulework.HostFile, error) {
	request := map[string]any{"path": path, "limit": cloneFileLimit, "docker": docker}
	if docker {
		request["container"] = target.ConfigSource.Container
		request["docker_host"] = target.ConfigSource.DockerHost
		request["core_path"] = target.ConfigSource.CorePath
		request["host_path"] = target.ConfigSource.HostPath
		request["home"] = target.ConfigSource.Home
	}
	raw, _ := json.Marshal(request)
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	out, err := connection.ExecutePython(ctx, target.SSHHost, cloneReadScript, raw, 32<<20)
	if err != nil {
		return rulework.HostFile{}, err
	}
	var response struct {
		File  rulework.HostFile `json:"file"`
		Error string            `json:"error"`
	}
	if json.Unmarshal(out, &response) != nil {
		return response.File, errors.New("invalid clone source reader response")
	}
	if response.Error != "" {
		return response.File, errors.New(response.Error)
	}
	return response.File, nil
}

const cloneReadScript = `import base64,hashlib,io,json,os,signal,stat,subprocess,sys,tarfile
def fail(): raise ValueError('source snapshot read failed; inspect the bound file/container privately')
def digest(data): return hashlib.sha256(data).hexdigest()
try:
 signal.alarm(30)
 r=json.load(sys.stdin);p=r['path'];limit=r['limit']
 if not os.path.isabs(p) or limit<1 or limit>24*1024*1024: fail()
 if not r.get('docker'):
  resolved=os.path.realpath(p)
  with open(resolved,'rb') as source:
   before=os.fstat(source.fileno())
   if not stat.S_ISREG(before.st_mode) or before.st_size>limit: fail()
   data=source.read(limit+1);after=os.fstat(source.fileno())
  identity=lambda s:[s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns]
  if len(data)>limit or identity(before)!=identity(after) or identity(before)!=identity(os.stat(resolved)) or os.path.realpath(p)!=resolved: fail()
  proof=[resolved,identity(before),digest(data)];mode=stat.S_IMODE(before.st_mode)
 else:
  env=dict(os.environ);env.pop('DOCKER_HOST',None);env.pop('DOCKER_CONTEXT',None)
  endpoint=r.get('docker_host') or os.environ.get('DOCKER_HOST','')
  def run(args):
   result=subprocess.run(['docker']+(['--host',endpoint] if endpoint else [])+args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=20,env=env)
   if result.returncode or len(result.stdout)>4*1024*1024: fail()
   return result.stdout
  if not endpoint:
   contexts=json.loads(run(['context','inspect']))
   endpoint=contexts[0].get('Endpoints',{}).get('docker',{}).get('Host','') if len(contexts)==1 else ''
  if not endpoint.startswith('unix://'): fail()
  items=json.loads(run(['inspect',r['container']]))
  if len(items)!=1: fail()
  item=items[0];cid=item['Id'];image=item['Image'];matched=False
  if not item.get('State',{}).get('Running'): fail()
  for mount in item.get('Mounts',[]):
   if mount.get('Type')!='bind': continue
   rel=os.path.relpath(r['core_path'],mount.get('Destination','/'))
   if rel!='..' and not rel.startswith('../') and os.path.realpath(os.path.join(mount['Source'],rel))==os.path.realpath(r['host_path']): matched=True
  if not matched: fail()
  resolved=run(['exec',cid,'readlink','-f',p]).decode().strip()
  root=run(['exec',cid,'readlink','-f',r['home']]).decode().strip()
  if not os.path.isabs(resolved) or not os.path.isabs(root): fail()
  relative=os.path.relpath(resolved,root)
  if relative=='..' or relative.startswith('../'): fail()
  process=subprocess.Popen(['docker','--host',endpoint,'cp',cid+':'+p,'-'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=env)
  try:
   archive=tarfile.open(fileobj=process.stdout,mode='r|');member=archive.next()
   if member is None or not member.isfile() or member.size>limit: fail()
   data=archive.extractfile(member).read(limit+1)
   if len(data)!=member.size or len(data)>limit or archive.next() is not None: fail()
   process.stdout.close()
   if process.wait(timeout=5): fail()
  finally:
   if process.poll() is None: process.kill();process.wait()
  mode=member.mode;proof=[endpoint,cid,image,resolved,member.size,member.mtime,member.mode,digest(data)]
 sha=digest(data)
 print(json.dumps({'file':{'path':p,'resolved':resolved,'data':base64.b64encode(data).decode(),'sha256':sha,'fingerprint':digest(json.dumps(proof,sort_keys=True).encode()),'mode':mode}}))
except Exception:
 print(json.dumps({'error':'source snapshot read failed; inspect the bound file/container privately'}))
`
