package configwork

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"path"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/hostpath"
	"go.yaml.in/yaml/v3"
)

//go:embed resources.py
var resourceScript string

func ResourceHostScript() string { return resourceScript }
func defaultResourceOperation(ctx context.Context, t config.Target, r HostRequest) (HostResponse, error) {
	if t.HostOS == "windows" {
		return HostResponse{}, errors.New("resource migration requires an owned Windows resource adapter")
	}
	input, err := json.Marshal(r)
	if err != nil {
		return HostResponse{}, err
	}
	out, err := connection.ExecutePython(ctx, t.SSHHost, resourceScript, input, 16<<20)
	if err != nil {
		return HostResponse{}, err
	}
	var result struct {
		HostResponse
		Error string `json:"error"`
	}
	if json.Unmarshal(out, &result) != nil {
		return HostResponse{}, errors.New("invalid resource host response")
	}
	if result.Error != "" {
		return result.HostResponse, errors.New(result.Error)
	}
	return result.HostResponse, nil
}
func resourceHome(t config.Target) string {
	c := t.ConfigSource
	if c.Home != "" {
		return c.Home
	}
	if c.Kind == "verge" {
		return c.DataDir
	}
	return ""
}

func prepareChangeSetResources(ctx context.Context, from, to config.Target, c *StructuralComposition, opts Options) ([]ResourceChange, error) {
	out := []ResourceChange{}
	var err error
	from, err = changeSetTarget(from)
	if err != nil {
		return out, err
	}
	to, err = changeSetTarget(to)
	if err != nil {
		return out, err
	}
	selected := map[string]bool{}
	for _, id := range append(append([]string{}, c.Selected...), c.AutoSelected...) {
		selected[id] = true
	}
	for _, object := range c.SourceSnapshot.Objects {
		if !selected[object.ID] || (object.Kind != "proxy-provider" && object.Kind != "rule-provider") {
			continue
		}
		provider := object.Node
		kind := scalar(provider, "type")
		if kind == "inline" {
			continue
		}
		if kind != "file" && kind != "http" {
			return out, fmt.Errorf("provider %q has no supported transferable resource", object.Name)
		}
		sourcePath := scalar(provider, "path")
		if sourcePath == "" {
			return out, fmt.Errorf("provider %q needs an explicit existing resource/cache path", object.Name)
		}
		file, err := ReadProviderResource(ctx, from, c.SourceSnapshot.source, object, opts)
		if err != nil {
			return out, fmt.Errorf("provider %q resource/cache cannot be captured: %w", object.Name, err)
		}
		if object.resource != nil && object.resource.SHA256 != file.SHA256 {
			return out, errors.New("provider snapshot changed after dependency composition; review a new plan")
		}
		if kind == "file" && object.ResourceStatus == "available" && object.ResourceSHA256 != file.SHA256 {
			return out, errors.New("source provider changed between snapshot and resource staging")
		}
		if len(file.Data) == 0 || len(file.Data) > MaxDocument || file.SHA256 != hash(file.Data) {
			return out, fmt.Errorf("provider %q resource bytes could not be verified", object.Name)
		}
		if object.Kind == "proxy-provider" {
			node, e := decode(file.Data)
			if e != nil {
				return out, fmt.Errorf("provider %q snapshot is not a supported YAML mapping", object.Name)
			}
			defs, e := definitions(node, "proxies", "proxy", "")
			if e != nil || get(node, "proxies") == nil {
				return out, fmt.Errorf("provider %q snapshot has no verifiable raw nodes", object.Name)
			}
			for _, d := range defs {
				if e = transferDefinitionCheck(d.Map()); e != nil {
					return out, fmt.Errorf("provider %q contains unsupported host-local dependencies: %w", object.Name, e)
				}
				if kind == "http" {
					if dialer := scalar(d.Node, "dialer-proxy"); dialer != "" && !plannedChangeSetOutbound(*c, dialer) {
						return out, fmt.Errorf("HTTP provider %q cached node %q has unplanned dialer-proxy %q; explicitly select/copy that proxy or group dependency before transferring this provider", object.Name, d.Name, dialer)
					}
				}
			}
		}
		name := hashJSON([]string{Binding(from), object.ID, semantic(provider), file.SHA256}) + ".yaml"
		coreHome := resourceHome(to)
		hostHome := coreHome
		if to.ConfigSource.Kind == "docker" {
			result, e := hostOperation(ctx, to, HostRequest{Op: "docker-resource-home"}, opts)
			if e != nil {
				return out, e
			}
			if result.ContainerID != c.DestinationSnapshot.source.dockerID || result.Image != c.DestinationSnapshot.source.dockerImage {
				return out, errors.New("destination Docker owner changed while resolving provider storage")
			}
			hostHome = result.File.Path
			if hostHome == "" {
				return out, errors.New("destination Docker home needs a writable directory bind for migrated provider resources")
			}
		}
		if hostHome == "" {
			return out, errors.New("destination owner has no declared provider resource home")
		}
		root := hostpath.Join(to.HostOS, hostHome, "lazyclash-resources")
		hostFile := hostpath.Join(to.HostOS, root, name)
		coreFile := hostpath.Join(to.HostOS, coreHome, "lazyclash-resources", name)
		if to.ConfigSource.Kind == "docker" {
			coreFile = path.Join(coreHome, "lazyclash-resources", name)
		}
		resource := ResourceChange{Provider: object.Name, Section: object.Section, Path: hostFile, CorePath: coreFile, SHA256: file.SHA256, Bytes: len(file.Data), Mutable: kind == "http", Status: "planned", data: append([]byte(nil), file.Data...), root: root}
		resource.sourceObject = object
		resource.sourceObject.Node = clone(object.Node)
		resource.sourceSHA256 = file.SHA256
		prior, e := hostOperation(ctx, to, HostRequest{Op: "resource-inspect", Path: hostFile, ResourceRoot: root}, opts)
		if e != nil {
			return out, e
		}
		if prior.Exists && prior.File.SHA256 != resource.SHA256 && !resource.Mutable {
			return out, fmt.Errorf("provider %q migration path already contains different bytes", object.Name)
		}
		if prior.Exists && resource.Mutable {
			resource.data = prior.File.Data
			resource.SHA256 = prior.File.SHA256
			resource.Bytes = len(prior.File.Data)
			resource.Status = "reused_cache"
		}
		resource.Created = !prior.Exists
		set(get(get(c.Root, object.Section), object.Name), "path", str(coreFile))
		out = append(out, resource)
	}
	total := 0
	for _, r := range out {
		total += r.Bytes
	}
	if total > 16<<20 {
		return out, errors.New("selected provider resources exceed 16 MiB")
	}
	return out, nil
}

func plannedChangeSetOutbound(c StructuralComposition, name string) bool {
	if structuralBuiltin(name) {
		return true
	}
	ids := map[string]bool{}
	for _, id := range append(append(append([]string{}, c.Selected...), c.AutoSelected...), c.Reused...) {
		ids[id] = true
	}
	if object, found, ambiguous := structuralResolve(c.SourceSnapshot.Objects, structuralReference{kind: "outbound", name: name}); found && !ambiguous && ids[object.ID] {
		return true
	}
	if c.DestinationSnapshot != nil {
		if object, found, ambiguous := structuralResolve(c.DestinationSnapshot.Objects, structuralReference{kind: "outbound", name: name}); found && !ambiguous && containsString(c.Reused, object.ID) {
			return true
		}
	}
	return false
}

func resourceBytes(resources []ResourceChange) map[string][]byte {
	out := map[string][]byte{}
	for _, r := range resources {
		out[r.CorePath] = r.data
	}
	return out
}
func cloneOwnerSource(s *source) *source {
	out := *s
	out.docs = map[string]*yaml.Node{}
	for p, n := range s.docs {
		out.docs[p] = clone(n)
	}
	out.files = map[string]HostFile{}
	for p, f := range s.files {
		out.files[p] = f
	}
	out.guards = append([]HostGuard(nil), s.guards...)
	out.Warnings = append([]string(nil), s.Warnings...)
	return &out
}

// ReadProviderResource captures bytes from the declared owner without downloads.
func ReadProviderResource(ctx context.Context, t config.Target, owner *source, object ConfigObject, opts Options) (HostFile, error) {
	var err error
	t, err = changeSetTarget(t)
	if err != nil {
		return HostFile{}, err
	}
	sourcePath := scalar(object.Node, "path")
	if sourcePath == "" {
		return HostFile{}, errors.New("provider requires an explicit existing resource/cache path")
	}
	if t.ConfigSource.Kind == "docker" {
		if !path.IsAbs(sourcePath) {
			sourcePath = path.Join(t.ConfigSource.Home, sourcePath)
		}
		result, e := hostOperation(ctx, t, HostRequest{Op: "docker-read-resource", Path: sourcePath}, opts)
		if e != nil {
			return HostFile{}, e
		}
		if result.ContainerID != owner.dockerID || result.Image != owner.dockerImage {
			return HostFile{}, errors.New("source Docker owner changed while reading provider")
		}
		return result.File, nil
	}
	home := resourceHome(t)
	if !hostpath.IsAbs(t.HostOS, sourcePath) {
		sourcePath = hostpath.Join(t.HostOS, home, sourcePath)
	}
	if !hostpath.Within(t.HostOS, home, sourcePath) || sourcePath == home {
		return HostFile{}, errors.New("source provider resource escapes its bound home")
	}
	result, e := hostOperation(ctx, t, HostRequest{Op: "source-resource-read", Path: sourcePath, ResourceRoot: home}, opts)
	return result.File, e
}
