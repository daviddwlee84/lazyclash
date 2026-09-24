// Package sourceowner provides source transport mechanics without granting ownership.
package sourceowner

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/connection"
)

// DockerSource is supplied from the caller's explicitly authorized binding.
type DockerSource struct {
	DockerHost string `json:"docker_host,omitempty"`
	Container  string `json:"container"`
	HostPath   string `json:"host_path"`
	CorePath   string `json:"core_path"`
	Binary     string `json:"binary"`
	Home       string `json:"home"`
}
type DockerRequest struct {
	DockerSource
	Op           string            `json:"op"`
	Version      string            `json:"version,omitempty"`
	Document     any               `json:"document,omitempty"`
	ResourcePath string            `json:"resource_path,omitempty"`
	Resources    map[string][]byte `json:"resources,omitempty"`
}
type DockerInfo struct {
	ContainerID      string `json:"container_id"`
	Image            string `json:"image"`
	Error            string `json:"error,omitempty"`
	ErrorKind        string `json:"error_kind,omitempty"`
	SourceSHA256     string `json:"source_sha256"`
	SingleFile       bool   `json:"single_file"`
	ResourceData     []byte `json:"resource_data,omitempty"`
	ResourceSHA256   string `json:"resource_sha256,omitempty"`
	ResourceHomeHost string `json:"resource_home_host,omitempty"`
}

var ErrUnavailable = errors.New("Docker source owner is unavailable")

//go:embed docker.py
var dockerScript string

func DockerHostScript() string { return dockerScript }

func DockerOperation(ctx context.Context, host string, req DockerRequest) (DockerInfo, error) {
	if req.Op != "inspect" && req.Op != "validate" && req.Op != "read-resource" && req.Op != "resource-home" {
		return DockerInfo{}, errors.New("invalid Docker source operation")
	}
	input, err := json.Marshal(req)
	if err != nil {
		return DockerInfo{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	limit := 1 << 20
	if req.Op == "read-resource" {
		limit = 16 << 20
	}
	out, err := connection.ExecutePython(ctx, host, dockerScript, input, limit)
	if err != nil {
		return DockerInfo{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	var result DockerInfo
	if json.Unmarshal(out, &result) != nil {
		return result, errors.New("invalid Docker validation response")
	}
	if result.Error != "" {
		if result.ErrorKind == "unavailable" {
			return result, fmt.Errorf("%w: %s", ErrUnavailable, result.Error)
		}
		return result, errors.New(result.Error)
	}
	return result, nil
}
