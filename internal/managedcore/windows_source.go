package managedcore

import (
	"context"
	"errors"
	"reflect"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/hostpath"
	"go.yaml.in/yaml/v3"
)

func sameWindowsPath(a, b string) bool {
	return hostpath.IsAbs("windows", a) && hostpath.IsAbs("windows", b) && strings.EqualFold(hostpath.Clean("windows", a), hostpath.Clean("windows", b))
}
func windowsValidateSourceWrite(ctx context.Context, instance Instance, request Request, source *configwork.HostRequest, opts Options) error {
	home := winJoin(instance.Root, "home")
	base := winJoin(home, "config.yaml")
	if instance.Client == "verge" {
		home = instance.Target.ConfigSource.DataDir
		base = winJoin(home, "profiles", instance.ProfileUID+".yaml")
	}
	isBase := sameWindowsPath(source.Path, base)
	allowed := isBase
	isMerge := false
	if instance.Client == "verge" {
		for _, kind := range []string{"rules", "proxies", "groups", "merge"} {
			if sameWindowsPath(source.Path, winJoin(home, "profiles", instance.ProfileUID+"_"+kind+".yaml")) {
				allowed = true
				isMerge = kind == "merge"
			}
		}
	}
	if !allowed {
		return errors.New("Windows source edits are limited to the owned native profile and existing Rules/Proxies/Groups/Merge companions")
	}
	var candidate map[string]any
	if yaml.Unmarshal(source.Data, &candidate) != nil || candidate == nil {
		return errors.New("Windows source must be a YAML mapping")
	}
	if !isBase && !isMerge {
		for k := range candidate {
			if k != "prepend" && k != "append" && k != "delete" {
				return errors.New("Windows companion source has an unsupported field")
			}
		}
		return nil
	}
	read := windowsHostRequest(instance, request, "source")
	read.Expected = ""
	read.Source = &configwork.HostRequest{Op: "read", Path: source.Path}
	before, err := callWindows(ctx, instance.SSHHost, read, opts)
	if err != nil {
		return err
	}
	var original map[string]any
	if yaml.Unmarshal(before.Source.File.Data, &original) != nil || (original == nil && !isMerge) {
		return errors.New("owned Windows profile is not a YAML mapping")
	}
	if original == nil {
		original = map[string]any{}
	}
	if err = validateWindowsOwnedResources(candidate, instance); err != nil {
		return err
	}
	fields := []string{"proxies", "proxy-groups", "proxy-providers", "rule-providers", "rules"}
	if isMerge {
		fields = []string{"proxy-providers", "rule-providers", "rules"}
	}
	for _, field := range fields {
		delete(original, field)
		delete(candidate, field)
	}
	if !reflect.DeepEqual(original, candidate) {
		return errors.New("node and rule editing cannot alter owned Windows controller, listener, DNS or TUN settings")
	}
	// Bind this independently read before-image to the atomic host commit, even
	// when the caller omitted its own guard for the profile path.
	source.Guards = append(source.Guards, configwork.HostGuard{Path: source.Path, Fingerprint: before.Source.File.Fingerprint})
	return nil
}
func validateWindowsOwnedResources(document any, instance Instance) error {
	home := winJoin(instance.Root, "home")
	if instance.Client == "verge" {
		home = instance.Target.ConfigSource.DataDir
	}
	inventory := map[string]bool{}
	for _, name := range instance.ResourceInventory {
		inventory[strings.ToLower(hostpath.Clean("windows", winJoin(home, name)))] = true
	}
	check := func(value string) error {
		if value == "" || strings.Contains(value, "-----BEGIN") {
			return nil
		}
		p := value
		if !hostpath.IsAbs("windows", p) {
			p = winJoin(home, p)
		}
		if !hostpath.Within("windows", home, p) || !inventory[strings.ToLower(hostpath.Clean("windows", p))] {
			return errors.New("Windows candidate resource is not in the owned bundled inventory")
		}
		return nil
	}
	var walk func(any) error
	walk = func(v any) error {
		switch obj := v.(type) {
		case map[string]any:
			for key, item := range obj {
				switch key {
				case "post-up", "post-down":
					if item != nil && item != "" {
						return errors.New("Windows managed profiles cannot execute host hooks")
					}
				case "private-key":
					if _, certificate := obj["certificate"]; certificate {
						if text, ok := item.(string); ok {
							if err := check(text); err != nil {
								return err
							}
						}
					}
				case "certificate", "certificate-path", "private-key-path", "ca":
					if text, ok := item.(string); ok {
						if err := check(text); err != nil {
							return err
						}
					}
				}
				if key == "proxy-providers" || key == "rule-providers" {
					if providers, ok := item.(map[string]any); ok {
						for _, entry := range providers {
							if provider, ok := entry.(map[string]any); ok {
								if p, ok := provider["path"].(string); ok {
									if err := check(p); err != nil {
										return err
									}
								}
							}
						}
					}
				}
				if err := walk(item); err != nil {
					return err
				}
			}
		case []any:
			for _, item := range obj {
				if err := walk(item); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(document)
}
