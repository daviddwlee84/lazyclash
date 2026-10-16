package discoveryguard

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/privatefs"
)

type Status struct {
	ID        string    `json:"id"`
	TargetID  string    `json:"target_id"`
	Phase     string    `json:"phase"`
	Group     string    `json:"group,omitempty"`
	Previous  string    `json:"previous,omitempty"`
	Deadline  time.Time `json:"deadline"`
	UpdatedAt time.Time `json:"updated_at"`
	Restored  bool      `json:"restored"`
	Message   string    `json:"message,omitempty"`
}

// Pending includes conflicts: only explicit recovery may resolve an older
// guard before a new DIRECT session takes ownership of this controller.
func (s Status) Pending() bool {
	return s.Phase != "restored" && s.Phase != "failed"
}

type journal struct {
	Version      int    `json:"version"`
	SettingsPath string `json:"settings_path"`
	Plan         Plan   `json:"plan"`
	Status       Status `json:"status"`
	NeedRestore  bool   `json:"need_restore"`
}

func newID() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(data[:]), nil
}

func validID(id string) bool {
	_, err := hex.DecodeString(id)
	return len(id) == 32 && err == nil && id == strings.ToLower(id)
}

func stateRoot(create bool) (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	if !filepath.IsAbs(base) {
		return "", errors.New("XDG_STATE_HOME must be absolute")
	}
	root := filepath.Join(base, "lazyclash", "discovery-guards")
	if create {
		_, beforeErr := os.Lstat(root)
		if err := os.MkdirAll(root, 0700); err != nil {
			return "", err
		}
		if errors.Is(beforeErr, os.ErrNotExist) {
			if err := secureDirectory(root); err != nil {
				return "", err
			}
		}
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || !privatefs.Private(root) {
		return "", errors.New("discovery recovery directory must be an ordinary private directory")
	}
	return root, nil
}

func readJournal(root, id string) (journal, error) {
	var j journal
	if !validID(id) {
		return j, errors.New("invalid discovery guard ID")
	}
	path := filepath.Join(root, id+".json")
	if !privatefs.Private(path) {
		return j, errors.New("discovery journal is absent or not private")
	}
	f, err := os.Open(path)
	if err != nil {
		return j, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 128<<10))
	if err != nil || len(data) >= 128<<10 || json.Unmarshal(data, &j) != nil || j.Version != 1 || j.Status.ID != id || j.Plan.ControllerKey == "" || j.Plan.TargetID != j.Status.TargetID {
		return journal{}, errors.New("invalid discovery recovery journal")
	}
	p := j.Plan
	want := p.Digest
	p.Digest = ""
	if want == "" || digest(p) != want {
		return journal{}, errors.New("discovery recovery plan is invalid")
	}
	return j, nil
}

func saveJournal(root string, j journal) error {
	if !validID(j.Status.ID) {
		return errors.New("invalid discovery guard ID")
	}
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(root, ".journal-")
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
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), filepath.Join(root, j.Status.ID+".json"))
	}
	if err != nil {
		return err
	}
	return syncDirectory(root)
}

func takeLock(root, key string) (io.Closer, error) {
	if len(key) != 64 {
		return nil, errors.New("invalid controller identity")
	}
	if _, err := hex.DecodeString(key); err != nil {
		return nil, errors.New("invalid controller identity")
	}
	path := filepath.Join(root, key+".lock")
	if _, err := os.Lstat(path); err == nil && !privatefs.Private(path) {
		return nil, errors.New("controller lock is not private")
	}
	f, err := platformLock(path)
	if err != nil {
		return nil, err
	}
	if !privatefs.Private(path) {
		f.Close()
		return nil, errors.New("controller lock is not private")
	}
	return f, nil
}

func journals(root string) ([]journal, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var result []journal
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		j, err := readJournal(root, id)
		if err != nil {
			// An unreadable journal may be an outstanding rollback obligation.
			return nil, err
		}
		result = append(result, j)
	}
	return result, nil
}

// List reads journals belonging to this settings file without probing a core.
func List(settingsPath string) ([]Status, error) {
	path, err := filepath.Abs(settingsPath)
	if err != nil {
		return nil, err
	}
	root, err := stateRoot(false)
	if errors.Is(err, os.ErrNotExist) {
		return []Status{}, nil
	}
	if err != nil {
		return nil, err
	}
	items, err := journals(root)
	if err != nil {
		return nil, err
	}
	result := []Status{}
	for _, j := range items {
		if j.SettingsPath == path {
			result = append(result, j.Status)
		}
	}
	sort.Slice(result, func(i, k int) bool { return result[i].UpdatedAt.After(result[k].UpdatedAt) })
	return result, nil
}

// CheckIdle guards other rule-writing entry points against an active or
// unresolved DIRECT session, including a saved alias in another settings file.
// This is an observed preflight check, not a controller compare-and-set.
func CheckIdle(target config.Target) error {
	if err := config.ValidateController(target.Controller); err != nil {
		return err
	}
	root, err := stateRoot(false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	items, err := journals(root)
	if err != nil {
		return err
	}
	key := controllerKey(target)
	for _, j := range items {
		if j.Plan.ControllerKey == key && j.Status.Pending() {
			return fmt.Errorf("controller has an active or unresolved DIRECT discovery guard %s (%s); stop or recover it before applying rules", j.Status.ID, j.Status.Phase)
		}
	}
	return nil
}
