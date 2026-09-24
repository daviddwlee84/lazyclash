package managedcore

import (
	"context"
	"errors"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/hostpath"
	"go.yaml.in/yaml/v3"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// RuleSourceOperation keeps the narrower rule binding independent while using
// the same recorded owner and host protocol as configuration source edits.
func RuleSourceOperation(ctx context.Context, target config.Target, operation configwork.HostRequest, opts Options) (configwork.HostResponse, error) {
	instance, err := loadInstance(target.ManagedCoreID, opts)
	if err != nil {
		return configwork.HostResponse{}, err
	}
	expected, err := config.RuleSourceFromConfigSource(instance.Target)
	if err != nil {
		return configwork.HostResponse{}, err
	}
	if !reflect.DeepEqual(target.RuleSource, expected) {
		return configwork.HostResponse{}, errors.New("managed rule source does not match its owned configuration")
	}
	if expected.Kind == "mihomo" {
		bound, owned := "", ""
		for _, c := range target.Configs {
			if c.ID == expected.ConfigID {
				bound = c.Path
			}
		}
		for _, c := range instance.Target.Configs {
			if c.ID == expected.ConfigID {
				owned = c.Path
			}
		}
		if bound == "" || bound != owned {
			return configwork.HostResponse{}, errors.New("managed rule configuration path changed")
		}
	}
	return SourceOperation(ctx, target, operation, opts)
}

// SourceOperation grants source access only through the recorded managed owner.
// It never turns an arbitrary registered endpoint into a privileged file editor.
func SourceOperation(ctx context.Context, target config.Target, operation configwork.HostRequest, opts Options) (configwork.HostResponse, error) {
	if target.HostOS == "windows" {
		return WindowsSourceOperation(ctx, target, operation, opts)
	}
	if sourceMutation(operation.Op) {
		if opts.ReadOnly {
			return configwork.HostResponse{}, errors.New("managed source writes are disabled in read-only mode")
		}
		unlock, err := mutationLock(target.ManagedCoreID, opts)
		if err != nil {
			return configwork.HostResponse{}, err
		}
		defer unlock()
	}
	instance, err := loadInstance(target.ManagedCoreID, opts)
	if err != nil {
		return configwork.HostResponse{}, err
	}
	if instance.Removed || target.ID != instance.Target.ID || target.SSHHost != instance.SSHHost || target.Controller != instance.Target.Controller || !reflect.DeepEqual(target.ConfigSource, instance.Target.ConfigSource) {
		return configwork.HostResponse{}, errors.New("managed source binding no longer matches its owned instance")
	}
	request, err := LoadRequest(instance.ID, opts)
	if err != nil {
		return configwork.HostResponse{}, err
	}
	if err = validateSourceResourceOperation(instance, operation); err != nil {
		return configwork.HostResponse{}, err
	}
	if sourceMutation(operation.Op) && opts.ReadOnly {
		return configwork.HostResponse{}, errors.New("managed source writes are disabled in read-only mode")
	}
	if operation.Op == "write" && filepath.Clean(operation.Path) == filepath.Join(instance.Root, "home", "config.yaml") {
		before, e := SourceOperation(ctx, target, configwork.HostRequest{Op: "read", Path: operation.Path}, opts)
		if e != nil {
			return configwork.HostResponse{}, e
		}
		var original, candidate map[string]any
		if yaml.Unmarshal(before.File.Data, &original) != nil || yaml.Unmarshal(operation.Data, &candidate) != nil {
			return configwork.HostResponse{}, errors.New("managed source must be valid YAML")
		}
		for _, field := range []string{"proxies", "proxy-groups", "proxy-providers", "rule-providers", "rules"} {
			delete(original, field)
			delete(candidate, field)
		}
		if !reflect.DeepEqual(original, candidate) {
			return configwork.HostResponse{}, errors.New("source editing cannot alter managed controller, listener, DNS or TUN settings; use cores configure")
		}
	}
	if operation.Op == "validate" || operation.Op == "docker-validate" {
		if _, err := stagedSourceInventory(instance, operation.Resources); err != nil {
			return configwork.HostResponse{}, err
		}
		if err := validateOwnedResources(operation.Document, instance); err != nil {
			return configwork.HostResponse{}, err
		}
	}
	hostReq := lifecycleRequest(instance, request, "source")
	hostReq.Source = &operation
	hostReq.Expected = "" // File guards plus owned manifest lock bind source edits after a host-side rollback.
	response, err := callHost(ctx, instance.SSHHost, instance.ServiceScope == "system", hostReq, opts)
	if err != nil {
		return configwork.HostResponse{}, err
	}
	if sourceMutation(operation.Op) {
		instance.Digest = response.Digest
		if err = updateSourceResourceInventory(&instance, operation); err != nil {
			return response.Source, err
		}
		if value, ok := response.Manifest["profile_sha256"].(string); ok {
			instance.ProfileSHA256 = value
		}
		if err = saveInstance(instance, request, opts); err != nil {
			return response.Source, err
		}
		// Preserve a private source snapshot for subsequent preset/configure commands.
		// All resource paths are the installation's recorded inventory, not arbitrary
		// filenames supplied by this source-edit request.
		snapshot := lifecycleRequest(instance, request, "snapshot")
		snapshot.Resources = map[string][]byte{}
		for _, name := range instance.ResourceInventory {
			snapshot.Resources[name] = nil
		}
		saved, e := callHost(ctx, instance.SSHHost, instance.ServiceScope == "system", snapshot, opts)
		if e != nil {
			return response.Source, errors.New("source saved; private configure snapshot needs inspection")
		}
		dir, e := instanceDir(instance.ID, opts)
		if e != nil {
			return response.Source, e
		}
		dir = filepath.Join(dir, "source-snapshot")
		for name, data := range saved.Resources {
			if e = writePrivate(filepath.Join(dir, filepath.FromSlash(name)), data); e != nil {
				return response.Source, e
			}
		}
		instance.ResourceInventory = sortedResourceNames(saved.Resources)
		request.Input, request.InputKind, request.InputBaseDir, request.Preset = saved.Profile, "yaml", dir, "preserve"
		if e = saveInstance(instance, request, opts); e != nil {
			return response.Source, e
		}
	}
	return response.Source, nil
}

func sourceMutation(op string) bool {
	return op == "write" || op == "resource-write" || op == "resource-remove"
}

func sourceResourceHome(instance Instance) string {
	if instance.Client == "verge" && instance.Target.ConfigSource != nil {
		return instance.Target.ConfigSource.DataDir
	}
	return hostpath.Join(instance.Target.HostOS, instance.Root, "home")
}

func sourceResourceName(instance Instance, path string, corePath bool) (string, error) {
	osKind, home := instance.Target.HostOS, sourceResourceHome(instance)
	if corePath && instance.Backend == "docker" {
		osKind, home = "linux", "/root/.config/mihomo"
	}
	root := hostpath.Join(osKind, home, "lazyclash-resources")
	rel, err := hostpath.Rel(osKind, root, path)
	if err != nil || !hostpath.IsAbs(osKind, path) || rel == "" || rel == "." || rel == ".." || strings.ContainsAny(rel, `/\\`) {
		return "", errors.New("migrated resource must be a direct child of the owned lazyclash-resources directory")
	}
	return "lazyclash-resources/" + rel, nil
}

func validateSourceResourceOperation(instance Instance, request configwork.HostRequest) error {
	if request.Op != "resource-inspect" && request.Op != "resource-write" && request.Op != "resource-remove" {
		return nil
	}
	if _, err := sourceResourceName(instance, request.Path, false); err != nil {
		return err
	}
	osKind := instance.Target.HostOS
	want := hostpath.Join(osKind, sourceResourceHome(instance), "lazyclash-resources")
	if rel, err := hostpath.Rel(osKind, want, request.ResourceRoot); err != nil || rel != "." {
		return errors.New("resource operation root differs from owned migration directory")
	}
	return nil
}

func stagedSourceInventory(instance Instance, resources map[string][]byte) (Instance, error) {
	total := 0
	for path, data := range resources {
		name, err := sourceResourceName(instance, path, true)
		if err != nil {
			return instance, err
		}
		total += len(data)
		if len(data) == 0 || len(data) > 8<<20 || total > 16<<20 {
			return instance, errors.New("staged provider resources exceed their size limits")
		}
		instance.ResourceInventory = append(append([]string(nil), instance.ResourceInventory...), name)
	}
	return instance, nil
}

func updateSourceResourceInventory(instance *Instance, request configwork.HostRequest) error {
	if request.Op != "resource-write" && request.Op != "resource-remove" {
		return nil
	}
	name, err := sourceResourceName(*instance, request.Path, false)
	if err != nil {
		return err
	}
	items := map[string]bool{}
	for _, n := range instance.ResourceInventory {
		items[n] = true
	}
	if request.Op == "resource-write" {
		items[name] = true
	} else {
		delete(items, name)
	}
	instance.ResourceInventory = nil
	for n := range items {
		instance.ResourceInventory = append(instance.ResourceInventory, n)
	}
	sort.Strings(instance.ResourceInventory)
	return nil
}

func validateOwnedResources(document any, instance Instance) error {
	osKind := instance.Target.HostOS
	home := hostpath.Join(osKind, instance.Root, "home")
	if instance.Backend == "docker" {
		osKind = "linux"
		home = "/root/.config/mihomo"
	}
	check := func(value string) error {
		if value == "" || strings.Contains(value, "-----BEGIN") {
			return nil
		}
		path := value
		if !hostpath.IsAbs(osKind, path) {
			path = hostpath.Join(osKind, home, path)
		}
		relative, err := hostpath.Rel(osKind, home, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, "../") {
			return errors.New("candidate resource escapes the managed home")
		}
		return nil
	}
	if values, ok := document.(map[string]any); ok {
		for _, section := range []string{"proxy-providers", "rule-providers"} {
			providers, _ := values[section].(map[string]any)
			for _, value := range providers {
				provider, _ := value.(map[string]any)
				if path, ok := provider["path"].(string); ok {
					if err := check(path); err != nil {
						return err
					}
				}
			}
		}
	}
	var walk func(any) error
	walk = func(value any) error {
		switch values := value.(type) {
		case map[string]any:
			for key, item := range values {
				if key == "certificate" || key == "certificate-path" || key == "private-key-path" || key == "ca" {
					if text, ok := item.(string); ok {
						if err := check(text); err != nil {
							return err
						}
					}
				}
				if err := walk(item); err != nil {
					return err
				}
			}
		case []any:
			for _, item := range values {
				if err := walk(item); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(document)
}
