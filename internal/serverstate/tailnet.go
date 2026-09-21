package serverstate

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

type TailnetNode struct {
	VerifiedAt  time.Time `toml:"verified_at" json:"verified_at"`
	ID          string    `toml:"id" json:"id"`
	PeerID      string    `toml:"peer_id" json:"peer_id"`
	SSHHost     string    `toml:"ssh_host" json:"ssh_host"`
	Hostname    string    `toml:"hostname" json:"hostname"`
	IPs         []string  `toml:"ips" json:"ips"`
	OS          string    `toml:"os" json:"os"`
	ExitManaged bool      `toml:"exit_managed" json:"exit_managed"`
	ExitStatus  string    `toml:"exit_status" json:"exit_status"`
	CreatedAt   time.Time `toml:"created_at" json:"created_at"`
	UpdatedAt   time.Time `toml:"updated_at" json:"updated_at"`
}

type TailnetProxy struct {
	ID             string    `toml:"id" json:"id"`
	NodeID         string    `toml:"node_id" json:"node_id"`
	PeerID         string    `toml:"peer_id" json:"peer_id"`
	SSHHost        string    `toml:"ssh_host" json:"ssh_host"`
	Name           string    `toml:"name" json:"name"`
	Mode           string    `toml:"mode" json:"mode"`
	Backend        string    `toml:"backend" json:"backend"`
	Egress         string    `toml:"egress" json:"egress"`
	Upstream       string    `toml:"upstream" json:"upstream"`
	ListenIP       string    `toml:"listen_ip" json:"listen_ip"`
	Port           int       `toml:"port" json:"port"`
	LocalPort      int       `toml:"local_port" json:"local_port"`
	CoreID         string    `toml:"core_id" json:"core_id"`
	Status         string    `toml:"status" json:"status"`
	ObservedExitIP string    `toml:"observed_exit_ip" json:"observed_exit_ip"`
	UDP            bool      `toml:"udp" json:"udp"`
	VerifiedAt     time.Time `toml:"verified_at" json:"verified_at"`
	CreatedAt      time.Time `toml:"created_at" json:"created_at"`
	UpdatedAt      time.Time `toml:"updated_at" json:"updated_at"`
}

func validateTailnet(inv Inventory) error {
	nodes := map[string]bool{}
	for _, n := range inv.TailnetNodes {
		if err := ValidateID(n.ID); err != nil {
			return err
		}
		if nodes[n.ID] {
			return fmt.Errorf("duplicate tailnet ID %q", n.ID)
		}
		nodes[n.ID] = true
		if n.PeerID == "" || n.SSHHost == "" {
			return errors.New("tailnet node requires peer ID and SSH host")
		}
		if err := tailnetStrings(n.PeerID, n.SSHHost, n.Hostname, n.OS, n.ExitStatus); err != nil {
			return err
		}
		if strings.HasPrefix(n.SSHHost, "-") || strings.ContainsAny(n.SSHHost, " \t") {
			return errors.New("tailnet SSH host must be an alias or user@host")
		}
		for _, ip := range n.IPs {
			if _, err := netip.ParseAddr(ip); err != nil {
				return errors.New("tailnet node has an invalid address")
			}
		}
	}
	proxies := map[string]bool{}
	for _, p := range inv.TailnetProxies {
		if err := ValidateID(p.ID); err != nil {
			return err
		}
		if proxies[p.ID] {
			return fmt.Errorf("duplicate tailnet proxy ID %q", p.ID)
		}
		proxies[p.ID] = true
		if !nodes[p.NodeID] {
			return fmt.Errorf("tailnet proxy %q refers to an unregistered node", p.ID)
		}
		if err := tailnetStrings(p.PeerID, p.SSHHost, p.Name, p.Mode, p.Backend, p.Egress, p.Upstream, p.ListenIP, p.CoreID, p.Status); err != nil {
			return err
		}
		if p.Port < 1 || p.Port > 65535 || p.LocalPort < 1 || p.LocalPort > 65535 {
			return errors.New("tailnet proxy ports must be in range 1–65535")
		}
	}
	return nil
}
func tailnetStrings(values ...string) error {
	for _, v := range values {
		if strings.IndexFunc(v, unicode.IsControl) >= 0 {
			return errors.New("tailnet fields cannot contain control characters")
		}
	}
	return nil
}
func (i Inventory) TailnetNode(id string) (TailnetNode, error) {
	for _, n := range i.TailnetNodes {
		if n.ID == id {
			return n, nil
		}
	}
	return TailnetNode{}, fmt.Errorf("tailnet node %q is not registered", id)
}
func (i *Inventory) UpsertTailnetNode(n TailnetNode) error {
	if err := ValidateID(n.ID); err != nil {
		return err
	}
	for j := range i.TailnetNodes {
		if i.TailnetNodes[j].ID == n.ID {
			i.TailnetNodes[j] = n
			return nil
		}
	}
	i.TailnetNodes = append(i.TailnetNodes, n)
	return nil
}
func (i *Inventory) RemoveTailnetNode(id string) error {
	for _, p := range i.TailnetProxies {
		if p.NodeID == id {
			return errors.New("remove this node's proxy shares before removing its registration")
		}
	}
	for j, n := range i.TailnetNodes {
		if n.ID == id {
			i.TailnetNodes = append(i.TailnetNodes[:j], i.TailnetNodes[j+1:]...)
			return nil
		}
	}
	return nil
}
func (i Inventory) TailnetProxy(id string) (TailnetProxy, error) {
	for _, p := range i.TailnetProxies {
		if p.ID == id {
			return p, nil
		}
	}
	return TailnetProxy{}, fmt.Errorf("tailnet proxy %q is not registered", id)
}
func (i *Inventory) UpsertTailnetProxy(p TailnetProxy) error {
	if err := ValidateID(p.ID); err != nil {
		return err
	}
	for j := range i.TailnetProxies {
		if i.TailnetProxies[j].ID == p.ID {
			i.TailnetProxies[j] = p
			return nil
		}
	}
	i.TailnetProxies = append(i.TailnetProxies, p)
	return nil
}
func (i *Inventory) RemoveTailnetProxy(id string) error {
	for j, p := range i.TailnetProxies {
		if p.ID == id {
			i.TailnetProxies = append(i.TailnetProxies[:j], i.TailnetProxies[j+1:]...)
			return nil
		}
	}
	return nil
}
func (s Store) PrivateDir(kind, id string) (string, error) {
	if err := ValidateID(kind); err != nil {
		return "", err
	}
	if err := ValidateID(id); err != nil {
		return "", err
	}
	root, err := s.StateRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, kind, id), nil
}
