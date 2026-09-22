package rulework

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/connection"
)

//go:embed host.py
var hostScript string

type hostRequest struct {
	Op                   string      `json:"op"`
	Path                 string      `json:"path,omitempty"`
	Data                 []byte      `json:"data,omitempty"`
	Guards               []fileGuard `json:"guards,omitempty"`
	Binary               string      `json:"binary,omitempty"`
	Home                 string      `json:"home,omitempty"`
	Version              string      `json:"version,omitempty"`
	Document             any         `json:"document,omitempty"`
	ValidationDockerHost string      `json:"validation_docker_host,omitempty"`
	ValidationImage      string      `json:"validation_image,omitempty"`
}

func hostCall(ctx context.Context, host string, req hostRequest) (hostFile, error) {
	timeout := 45 * time.Second
	if req.Op == "validate" && (req.ValidationDockerHost != "" || req.ValidationImage != "") {
		// Leave time for bounded image/daemon checks and container cleanup after
		// the independent 30-second Mihomo validation deadline expires.
		timeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	body, err := json.Marshal(req)
	if err != nil {
		return hostFile{}, err
	}
	out, err := connection.ExecutePython(ctx, host, hostScript, body, 16<<20)
	if err != nil {
		return hostFile{}, err
	}
	var response struct {
		File  hostFile `json:"file"`
		Error string   `json:"error"`
	}
	if json.Unmarshal(out, &response) != nil {
		return hostFile{}, errors.New("invalid rule host response")
	}
	if response.Error != "" {
		return hostFile{}, fmt.Errorf("rule source: %s", response.Error)
	}
	return response.File, nil
}

func readHost(ctx context.Context, host, path string) (hostFile, error) {
	return hostCall(ctx, host, hostRequest{Op: "read", Path: path})
}
