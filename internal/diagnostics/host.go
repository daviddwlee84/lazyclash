package diagnostics

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/connection"
)

//go:embed host_probe.py
var hostProbeScript string

func CollectHost(ctx context.Context, sshHost string, request HostRequest) (HostEvidence, error) {
	scope := "local process"
	if sshHost != "" {
		scope = "SSH noninteractive process"
	}
	result := HostEvidence{Protocol: 1, Scope: scope, Capabilities: []Capability{}, DNS: DNSResult{Source: "host native resolver", Addresses: []string{}}, Routes: []RouteEvidence{}, Requests: []RequestEvidence{}}
	ctx, cancel := context.WithTimeout(ctx, 22*time.Second)
	defer cancel()
	input, err := json.Marshal(request)
	if err != nil {
		return result, errors.New("cannot encode host evidence request")
	}
	data, err := connection.ExecutePython(ctx, sshHost, hostProbeScript, input, 128*1024)
	if err != nil {
		result.Error = "host evidence unavailable"
		if errors.Is(err, connection.ErrPythonUnavailable) {
			result.Error = err.Error()
		}
		result.Capabilities = append(result.Capabilities, Capability{Name: "python3", Available: false, Detail: result.Error})
		return result, err
	}
	if err := json.Unmarshal(data, &result); err != nil || result.Protocol != 1 {
		return result, errors.New("host helper returned an unsupported evidence format")
	}
	result.Scope = scope
	result.Capabilities = append(result.Capabilities, Capability{Name: "python3", Available: true})
	for i := range result.Requests {
		result.Requests[i].Source = scope + "/" + result.Requests[i].Source
	}
	return result, nil
}
