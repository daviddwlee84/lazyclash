package configwork

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"time"
)

//go:embed docker.py
var dockerScript string

type dockerInfo struct {
	ContainerID  string `json:"container_id"`
	Image        string `json:"image"`
	Error        string `json:"error"`
	SourceSHA256 string `json:"source_sha256"`
	SingleFile   bool   `json:"single_file"`
}

func dockerCall(ctx context.Context, t config.Target, op string, data []byte, version string) (dockerInfo, error) {
	s := t.ConfigSource
	req := map[string]any{"op": op, "docker_host": s.DockerHost, "container": s.Container, "host_path": s.HostPath, "core_path": s.CorePath, "binary": s.Binary, "home": s.Home, "version": version}
	if data != nil {
		n, e := decode(data)
		if e != nil {
			return dockerInfo{}, e
		}
		var doc any
		if n.Decode(&doc) != nil {
			return dockerInfo{}, errors.New("invalid validation document")
		}
		req["document"] = doc
	}
	input, _ := json.Marshal(req)
	ctx, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	out, e := connection.ExecutePython(ctx, t.SSHHost, dockerScript, input, 1<<20)
	if e != nil {
		return dockerInfo{}, e
	}
	var result dockerInfo
	if json.Unmarshal(out, &result) != nil {
		return result, errors.New("invalid Docker validation response")
	}
	if result.Error != "" {
		return result, errors.New(result.Error)
	}
	return result, nil
}
