package tailnetproxy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/managedcore"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

func (s Service) now() time.Time {
	if s.Options.Now != nil {
		return s.Options.Now().UTC()
	}
	return time.Now().UTC()
}

func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func randomSecret() (string, error) {
	var data [24]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(data[:]), nil
}
func (s Service) path(id string) (string, error) {
	dir, err := s.Options.Store.PrivateDir("tailnet-proxy", id)
	return filepath.Join(dir, "state.json"), err
}
func (s Service) load(id string) (journal, error) {
	path, err := s.path(id)
	if err != nil {
		return journal{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return journal{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return journal{}, errors.New("tailnet proxy state must be a private regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return journal{}, err
	}
	var j journal
	if json.Unmarshal(data, &j) != nil || j.Request.ID != id || j.Token == "" || j.PeerID == "" || j.Password == "" {
		return j, errors.New("invalid tailnet proxy state")
	}
	j.Request.Upstream = j.Upstream
	return j, nil
}
func (s Service) save(j journal) error {
	path, err := s.path(j.Request.ID)
	if err != nil {
		return err
	}
	j.Upstream = j.Request.Upstream
	j.UpdatedAt = s.now()
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	if err = serverstate.WritePrivate(path, data); err != nil {
		return err
	}
	p := serverstate.TailnetProxy{ID: j.Request.ID, NodeID: j.Request.NodeID, PeerID: j.PeerID, SSHHost: j.SSHHost, Name: j.Request.Name, Mode: j.Request.Mode, Backend: j.Request.Backend, Egress: j.Request.Egress, Upstream: redactedUpstream(j.Upstream), ListenIP: j.ListenIP, Port: j.Request.Port, LocalPort: j.Request.LocalPort, CoreID: j.CoreID, Status: j.Phase, UDP: j.Request.UDP, ObservedExitIP: j.ObservedExitIP, VerifiedAt: j.VerifiedAt, CreatedAt: j.CreatedAt, UpdatedAt: j.UpdatedAt}
	return s.Options.Store.Update(func(i *serverstate.Inventory) error {
		n, err := i.TailnetNode(j.Request.NodeID)
		if err != nil {
			return err
		}
		if n.PeerID != j.PeerID || n.SSHHost != j.SSHHost {
			return errors.New("tailnet node registration changed")
		}
		return i.UpsertTailnetProxy(p)
	})
}
func (s Service) lock(id string) (func(), error) {
	path, err := s.path(id)
	if err != nil {
		return nil, err
	}
	return serverstate.Lock(path + ".lock")
}
func (s Service) coreOptions() (managedcore.Options, error) {
	opts := s.Options.Core
	root, err := s.Options.Store.StateRoot()
	if err != nil {
		return opts, err
	}
	if opts.StateDir == "" {
		opts.StateDir = filepath.Join(root, "tailnet-managed-cores")
	}
	opts.ReadOnly = opts.ReadOnly || s.Options.ReadOnly
	// Gateways are remote infrastructure, not controller-target registrations.
	opts.Register, opts.Unregister = nil, nil
	return opts, nil
}
func coreID(id string) string { return "tailnet-" + hash([]byte(id))[:20] }
