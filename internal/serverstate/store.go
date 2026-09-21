// Package serverstate stores VPS and proxy-server registrations separately from
// Mihomo controller targets. Reads never create files or contact a host.
package serverstate

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/pelletier/go-toml/v2"
)

var ErrConflict = errors.New("server inventory changed during this operation; reload before retrying")
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

type Resource struct {
	Kind  string `toml:"kind" json:"kind"`
	ID    string `toml:"id" json:"id"`
	Owned bool   `toml:"owned" json:"owned"`
}

type Host struct {
	ID             string     `toml:"id" json:"id"`
	Name           string     `toml:"name,omitempty" json:"name,omitempty"`
	Provider       string     `toml:"provider" json:"provider"`
	Profile        string     `toml:"profile,omitempty" json:"profile,omitempty"`
	ResourceID     string     `toml:"resource_id,omitempty" json:"resource_id,omitempty"`
	Region         string     `toml:"region,omitempty" json:"region,omitempty"`
	Plan           string     `toml:"plan,omitempty" json:"plan,omitempty"`
	MonthlyUSD     float64    `toml:"monthly_usd,omitempty" json:"monthly_usd,omitempty"`
	Transfer       int        `toml:"transfer,omitempty" json:"transfer,omitempty"`
	TransferUnit   string     `toml:"transfer_unit,omitempty" json:"transfer_unit,omitempty"`
	PriceCheckedAt time.Time  `toml:"price_checked_at" json:"price_checked_at"`
	BillingBasis   string     `toml:"billing_basis,omitempty" json:"billing_basis,omitempty"`
	SSHHost        string     `toml:"ssh_host,omitempty" json:"ssh_host,omitempty"`
	PublicHost     string     `toml:"public_host,omitempty" json:"public_host,omitempty"`
	Status         string     `toml:"status,omitempty" json:"status,omitempty"`
	OperationID    string     `toml:"operation_id,omitempty" json:"operation_id,omitempty"`
	Owned          bool       `toml:"owned" json:"owned"`
	CreatedAt      time.Time  `toml:"created_at" json:"created_at"`
	UpdatedAt      time.Time  `toml:"updated_at" json:"updated_at"`
	Resources      []Resource `toml:"resources,omitempty" json:"resources,omitempty"`
}

type Deployment struct {
	ID         string    `toml:"id" json:"id"`
	HostID     string    `toml:"host_id" json:"host_id"`
	Recipe     string    `toml:"recipe" json:"recipe"`
	Backend    string    `toml:"backend" json:"backend"`
	PublicHost string    `toml:"public_host" json:"public_host"`
	PublicPort int       `toml:"public_port" json:"public_port"`
	ListenPort int       `toml:"listen_port" json:"listen_port"`
	Domain     string    `toml:"domain,omitempty" json:"domain,omitempty"`
	Status     string    `toml:"status" json:"status"`
	Version    string    `toml:"version,omitempty" json:"version,omitempty"`
	CreatedAt  time.Time `toml:"created_at" json:"created_at"`
	UpdatedAt  time.Time `toml:"updated_at" json:"updated_at"`
}

type Inventory struct {
	Version     int          `toml:"version" json:"version"`
	Hosts       []Host       `toml:"hosts" json:"hosts"`
	Deployments []Deployment `toml:"deployments" json:"deployments"`
}

type Store struct{ Path, StateDir string }

func DefaultPath(settingsPath string) (string, error) {
	if settingsPath == "" {
		var err error
		settingsPath, err = config.DefaultPath()
		if err != nil {
			return "", err
		}
	}
	abs, err := filepath.Abs(settingsPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(abs), "servers.toml"), nil
}

func (s Store) path() (string, error) {
	if s.Path == "" {
		return DefaultPath("")
	}
	return filepath.Abs(s.Path)
}

// StateRoot isolates histories belonging to different selected inventories.
func (s Store) StateRoot() (string, error) {
	if s.StateDir != "" {
		if !filepath.IsAbs(s.StateDir) {
			return "", errors.New("server state directory must be absolute")
		}
		return s.StateDir, nil
	}
	base := os.Getenv("XDG_STATE_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil || !filepath.IsAbs(home) {
			return "", errors.New("cannot determine server state home")
		}
		base = filepath.Join(home, ".local", "state")
	}
	p, err := s.path()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(p))
	return filepath.Join(base, "lazyclash", "servers", fmt.Sprintf("%x", sum[:12])), nil
}

func (s Store) Load() (Inventory, error) {
	p, err := s.path()
	if err != nil {
		return Inventory{}, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return Inventory{Version: 1, Hosts: []Host{}, Deployments: []Deployment{}}, nil
	}
	if err != nil {
		return Inventory{}, fmt.Errorf("read server inventory: %w", err)
	}
	return decode(data)
}

func decode(data []byte) (Inventory, error) {
	var inv Inventory
	if err := toml.Unmarshal(data, &inv); err != nil {
		return inv, errors.New("invalid servers TOML; check syntax and field types")
	}
	if inv.Version == 0 {
		inv.Version = 1
	}
	if inv.Hosts == nil {
		inv.Hosts = []Host{}
	}
	if inv.Deployments == nil {
		inv.Deployments = []Deployment{}
	}
	return inv, Validate(inv)
}

// Update serializes writers, rereads under the lock, and detects external edits.
func (s Store) Update(fn func(*Inventory) error) error {
	p, err := s.path()
	if err != nil {
		return err
	}
	unlock, err := Lock(p + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	before, err := os.ReadFile(p)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	inv := Inventory{Version: 1, Hosts: []Host{}, Deployments: []Deployment{}}
	if len(before) > 0 {
		inv, err = decode(before)
		if err != nil {
			return err
		}
	}
	if err = fn(&inv); err != nil {
		return err
	}
	if err = Validate(inv); err != nil {
		return err
	}
	data, err := preserve(before, inv)
	if err != nil {
		return err
	}
	current, err := os.ReadFile(p)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !bytes.Equal(current, before) {
		return ErrConflict
	}
	return WritePrivate(p, data)
}

func ValidateID(id string) error {
	if !idPattern.MatchString(id) {
		return errors.New("ID must be 1–64 letters, numbers, '.', '_' or '-', beginning with a letter or number")
	}
	return nil
}

func Validate(inv Inventory) error {
	if inv.Version != 1 {
		return errors.New("unsupported server inventory version")
	}
	hosts := map[string]bool{}
	for _, h := range inv.Hosts {
		if err := ValidateID(h.ID); err != nil {
			return err
		}
		if hosts[h.ID] {
			return fmt.Errorf("duplicate host ID %q", h.ID)
		}
		hosts[h.ID] = true
		for _, v := range []string{h.Name, h.Provider, h.Profile, h.SSHHost, h.PublicHost, h.ResourceID, h.Region, h.Plan, h.Status, h.OperationID} {
			if strings.IndexFunc(v, unicode.IsControl) >= 0 {
				return errors.New("host fields cannot contain control characters")
			}
		}
		if strings.HasPrefix(h.SSHHost, "-") || strings.ContainsAny(h.SSHHost, " \t") {
			return errors.New("SSH host must be a host alias or user@host, not command arguments")
		}
	}
	ids := map[string]bool{}
	for _, d := range inv.Deployments {
		if err := ValidateID(d.ID); err != nil {
			return err
		}
		if ids[d.ID] {
			return fmt.Errorf("duplicate deployment ID %q", d.ID)
		}
		ids[d.ID] = true
		if !hosts[d.HostID] {
			return fmt.Errorf("deployment %q refers to an unregistered host", d.ID)
		}
		for _, p := range []int{d.PublicPort, d.ListenPort} {
			if p < 0 || p > 65535 {
				return errors.New("server port must be in range 1–65535")
			}
		}
	}
	return nil
}

func (i Inventory) Host(id string) (Host, error) {
	for _, h := range i.Hosts {
		if h.ID == id {
			return h, nil
		}
	}
	return Host{}, fmt.Errorf("host %q is not registered", id)
}
func (i Inventory) Deployment(id string) (Deployment, error) {
	for _, d := range i.Deployments {
		if d.ID == id {
			return d, nil
		}
	}
	return Deployment{}, fmt.Errorf("server %q is not registered", id)
}
func (i *Inventory) UpsertHost(h Host) error {
	if err := ValidateID(h.ID); err != nil {
		return err
	}
	for n := range i.Hosts {
		if i.Hosts[n].ID == h.ID {
			i.Hosts[n] = h
			return nil
		}
	}
	i.Hosts = append(i.Hosts, h)
	return nil
}
func (i *Inventory) UpsertDeployment(d Deployment) error {
	if err := ValidateID(d.ID); err != nil {
		return err
	}
	for n := range i.Deployments {
		if i.Deployments[n].ID == d.ID {
			i.Deployments[n] = d
			return nil
		}
	}
	i.Deployments = append(i.Deployments, d)
	return nil
}

func WritePrivate(path string, data []byte) error {
	if !filepath.IsAbs(path) {
		return errors.New("private state path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("private state must be a regular file")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".server-state-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
