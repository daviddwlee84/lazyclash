package configwork

import (
	"context"
	"errors"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"github.com/daviddwlee84/lazyclash/internal/sourceowner"
)

type HostFile = rulework.HostFile
type HostGuard = rulework.FileGuard

// HostRequest is a closed operation protocol. It never carries executable code.
// Docker path fields are copied from the bound source, not inferred from files.
type HostRequest struct {
	Op                   string            `json:"op"`
	Path                 string            `json:"path,omitempty"`
	Data                 []byte            `json:"data,omitempty"`
	Guards               []HostGuard       `json:"guards,omitempty"`
	Binary               string            `json:"binary,omitempty"`
	Home                 string            `json:"home,omitempty"`
	Version              string            `json:"version,omitempty"`
	Document             any               `json:"document,omitempty"`
	Container            string            `json:"container,omitempty"`
	HostPath             string            `json:"host_path,omitempty"`
	CorePath             string            `json:"core_path,omitempty"`
	ValidationDockerHost string            `json:"validation_docker_host,omitempty"`
	ValidationImage      string            `json:"validation_image,omitempty"`
	Resources            map[string][]byte `json:"resources,omitempty"`
	ResourceRoot         string            `json:"resource_root,omitempty"`
	ExpectedSHA256       string            `json:"expected_sha256,omitempty"`
}
type HostResponse struct {
	File         HostFile `json:"file"`
	ContainerID  string   `json:"container_id,omitempty"`
	Image        string   `json:"image,omitempty"`
	SourceSHA256 string   `json:"source_sha256,omitempty"`
	SingleFile   bool     `json:"single_file,omitempty"`
	Exists       bool     `json:"exists,omitempty"`
	Created      bool     `json:"created,omitempty"`
}

func SourceHostScript() string { return rulework.SourceHostScript() }
func DockerHostScript() string { return dockerScript }

func hostOperation(ctx context.Context, t config.Target, req HostRequest, opts Options) (HostResponse, error) {
	if opts.Host != nil {
		return opts.Host(ctx, t, req)
	}
	return DefaultHostOperation(ctx, t, req)
}
func DefaultHostOperation(ctx context.Context, t config.Target, req HostRequest) (HostResponse, error) {
	if t.HostOS == "windows" {
		return HostResponse{}, errors.New("Windows source access requires its explicitly managed host adapter")
	}
	var result HostResponse
	var err error
	switch req.Op {
	case "read":
		result.File, err = rulework.ReadHostFile(ctx, t.SSHHost, req.Path)
	case "check":
		err = rulework.CheckHostFiles(ctx, t.SSHHost, req.Guards)
	case "write":
		result.File, err = rulework.WriteHostFile(ctx, t.SSHHost, req.Path, req.Data, req.Guards)
	case "resource-inspect", "resource-write", "resource-remove", "source-resource-read":
		return defaultResourceOperation(ctx, t, req)
	case "validate":
		candidate := t
		candidate.RuleSource = &config.RuleSource{Kind: "mihomo", Binary: req.Binary, Home: req.Home}
		raw, encodeErr := encode(mapNode(req.Document))
		if encodeErr != nil {
			return result, encodeErr
		}
		if len(req.Resources) > 0 {
			err = rulework.ValidateSourceDocumentWithResources(ctx, candidate, req.Document, req.Version, rulework.ValidationSandbox{DockerHost: req.ValidationDockerHost, Image: req.ValidationImage}, req.Resources)
		} else {
			err = rulework.ValidateSourceCandidateWithSandbox(ctx, candidate, raw, req.Version, rulework.ValidationSandbox{DockerHost: req.ValidationDockerHost, Image: req.ValidationImage})
		}
	case "docker-inspect", "docker-validate", "docker-read-resource", "docker-resource-home":
		op := "inspect"
		var data []byte
		if req.Op == "docker-validate" {
			op = "validate"
			data, err = encode(mapNode(req.Document))
			if err != nil {
				return result, err
			}
		}
		if req.Op == "docker-read-resource" {
			op = "read-resource"
		}
		if req.Op == "docker-resource-home" {
			op = "resource-home"
		}
		s := t.ConfigSource
		request := sourceowner.DockerRequest{DockerSource: sourceowner.DockerSource{DockerHost: s.DockerHost, Container: s.Container, HostPath: s.HostPath, CorePath: s.CorePath, Binary: s.Binary, Home: s.Home}, Op: op, Document: req.Document, Version: req.Version, ResourcePath: req.Path, Resources: req.Resources}
		_ = data
		info, e := sourceowner.DockerOperation(ctx, t.SSHHost, request)
		result.ContainerID, result.Image = info.ContainerID, info.Image
		result.SourceSHA256, result.SingleFile = info.SourceSHA256, info.SingleFile
		if op == "read-resource" {
			result.File = HostFile{Path: req.Path, Resolved: req.Path, Data: info.ResourceData, SHA256: info.ResourceSHA256, Fingerprint: info.ResourceSHA256}
		}
		if op == "resource-home" {
			result.File.Path = info.ResourceHomeHost
		}
		err = e
	default:
		err = errors.New("unknown configuration source operation")
	}
	return result, err
}
func readSourceFile(ctx context.Context, t config.Target, path string, opts Options) (HostFile, error) {
	result, err := hostOperation(ctx, t, HostRequest{Op: "read", Path: path}, opts)
	return result.File, err
}
func checkSourceFiles(ctx context.Context, t config.Target, guards []HostGuard, opts Options) error {
	_, err := hostOperation(ctx, t, HostRequest{Op: "check", Guards: guards}, opts)
	return err
}
func writeSourceFile(ctx context.Context, t config.Target, path string, data []byte, guards []HostGuard, opts Options) (HostFile, error) {
	result, err := hostOperation(ctx, t, HostRequest{Op: "write", Path: path, Data: data, Guards: guards}, opts)
	return result.File, err
}
func dockerSourceOperation(ctx context.Context, t config.Target, op string, data []byte, version string, opts Options) (HostResponse, error) {
	s := t.ConfigSource
	req := HostRequest{Op: "docker-" + op, Container: s.Container, HostPath: s.HostPath, CorePath: s.CorePath, Binary: s.Binary, Home: s.Home, Version: version}
	if data != nil {
		node, err := decode(data)
		if err != nil {
			return HostResponse{}, err
		}
		if err = node.Decode(&req.Document); err != nil {
			return HostResponse{}, errors.New("invalid Docker validation document")
		}
	}
	return hostOperation(ctx, t, req, opts)
}
