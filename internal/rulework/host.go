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
	Op       string      `json:"op"`
	Path     string      `json:"path,omitempty"`
	Data     []byte      `json:"data,omitempty"`
	Guards   []fileGuard `json:"guards,omitempty"`
	Binary   string      `json:"binary,omitempty"`
	Home     string      `json:"home,omitempty"`
	Version  string      `json:"version,omitempty"`
	Document any         `json:"document,omitempty"`
}

func hostCall(ctx context.Context, host string, req hostRequest) (hostFile, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
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
