package managedcore

import (
	"context"
	"errors"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"go.yaml.in/yaml/v3"
	"path/filepath"
	"reflect"
	"strings"
)

// SourceOperation grants source access only through the recorded managed owner.
// It never turns an arbitrary registered endpoint into a privileged file editor.
func SourceOperation(ctx context.Context, target config.Target, operation configwork.HostRequest, opts Options) (configwork.HostResponse, error) {
	if operation.Op == "write" {
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
	if operation.Op == "write" && opts.ReadOnly {
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
	if operation.Op == "write" {
		instance.Digest = response.Digest
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
		request.Input, request.InputKind, request.InputBaseDir, request.Preset = saved.Profile, "yaml", dir, "preserve"
		if e = saveInstance(instance, request, opts); e != nil {
			return response.Source, e
		}
	}
	return response.Source, nil
}

func validateOwnedResources(document any, instance Instance) error {
	home := filepath.Join(instance.Root, "home")
	if instance.Backend == "docker" {
		home = "/root/.config/mihomo"
	}
	check := func(value string) error {
		if value == "" || strings.Contains(value, "-----BEGIN") {
			return nil
		}
		path := value
		if !filepath.IsAbs(path) {
			path = filepath.Join(home, path)
		}
		relative, err := filepath.Rel(home, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
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
