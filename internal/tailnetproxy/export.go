package tailnetproxy

import (
	"encoding/json"
	"errors"

	"go.yaml.in/yaml/v3"
)

const prerequisite = "The client must be connected to the same Tailnet (or an explicitly shared node) and have access to this peer and proxy port."

func (s Service) ClientNode(id string) ([]byte, error) {
	j, err := s.load(id)
	if err != nil {
		return nil, err
	}
	if j.Phase == "removed" || j.Phase == "installing" || j.Phase == "core_unverified" {
		return nil, errors.New("only a deployed Tailnet proxy can export credentials")
	}
	return yaml.Marshal(clientMap(j))
}
func (s Service) Export(id, format string) ([]byte, error) {
	node, err := s.ClientNode(id)
	if err != nil {
		return nil, err
	}
	j, err := s.load(id)
	if err != nil {
		return nil, err
	}
	if format == "yaml" || format == "mihomo" {
		return append([]byte("# "+prerequisite+"\n"), node...), nil
	}
	starter, err := yaml.Marshal(map[string]any{"mixed-port": 7890, "allow-lan": false, "bind-address": "127.0.0.1", "mode": "rule", "log-level": "warning", "proxies": []any{clientMap(j)}, "proxy-groups": []any{map[string]any{"name": "PROXY", "type": "select", "proxies": []string{j.Request.Name}}}, "rules": []string{"MATCH,PROXY"}})
	if err != nil {
		return nil, err
	}
	switch format {
	case "starter":
		return append([]byte("# "+prerequisite+"\n"), starter...), nil
	case "client-bundle":
		return json.MarshalIndent(map[string]any{"kind": "lazyclash-client-bundle", "version": 1, "id": id, "recipe": "tailnet-proxy", "prerequisite": prerequisite, "peer_id": j.PeerID, "endpoint": endpoint(j), "mode": j.Request.Mode, "udp": j.Request.UDP, "udp_access": "Tailnet policy; SOCKS UDP datagrams do not carry TCP credentials", "deployment_status": j.Phase, "last_verified_at": j.VerifiedAt, "observed_exit_ip": j.ObservedExitIP, "mihomo": string(node), "starter": string(starter)}, "", "  ")
	default:
		return nil, errors.New("Tailnet proxy export format must be yaml, starter or client-bundle")
	}
}
