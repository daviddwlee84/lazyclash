package managedcore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func stateRoot(opts Options) (string, error) {
	if opts.StateDir != "" {
		if !filepath.IsAbs(opts.StateDir) {
			return "", errors.New("managed state directory must be absolute")
		}
		return opts.StateDir, nil
	}
	base := os.Getenv("XDG_STATE_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil || !filepath.IsAbs(home) {
			return "", errors.New("cannot determine managed state home")
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "lazyclash", "managed"), nil
}
func instanceDir(id string, opts Options) (string, error) {
	if !idPattern.MatchString(id) {
		return "", errors.New("invalid managed core ID")
	}
	root, err := stateRoot(opts)
	return filepath.Join(root, "instances", id), err
}
func writePrivate(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("private managed state must be a regular file")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".managed-state-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(file.Name(), path)
}
func saveInstance(instance Instance, request Request, opts Options) error {
	dir, err := instanceDir(instance.ID, opts)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(struct {
		Instance
		OwnerToken    string `json:"owner_token"`
		CoreGuardRef  string `json:"core_guard_ref,omitempty"`
		ProxyGuardRef string `json:"proxy_guard_ref,omitempty"`
	}{instance, instance.OwnerToken, instance.CoreGuardRef, instance.ProxyGuardRef}, "", "  ")
	if err != nil {
		return err
	}
	if err = writePrivate(filepath.Join(dir, "instance.json"), data); err != nil {
		return err
	}
	data, err = json.Marshal(struct {
		Request
		InputBaseDir string `json:"input_base_dir,omitempty"`
		ArtifactFile string `json:"artifact_file,omitempty"`
	}{request, request.InputBaseDir, request.ArtifactFile})
	if err != nil {
		return err
	}
	if err = writePrivate(filepath.Join(dir, "request.json"), data); err != nil {
		return err
	}
	return writePrivate(filepath.Join(dir, "input"), request.Input)
}
func loadInstance(id string, opts Options) (Instance, error) {
	dir, err := instanceDir(id, opts)
	if err != nil {
		return Instance{}, err
	}
	data, err := os.ReadFile(filepath.Join(dir, "instance.json"))
	if err != nil {
		return Instance{}, err
	}
	var saved struct {
		Instance
		OwnerToken    string `json:"owner_token"`
		CoreGuardRef  string `json:"core_guard_ref"`
		ProxyGuardRef string `json:"proxy_guard_ref"`
	}
	err = json.Unmarshal(data, &saved)
	instance := saved.Instance
	instance.OwnerToken = saved.OwnerToken
	instance.CoreGuardRef = saved.CoreGuardRef
	instance.ProxyGuardRef = saved.ProxyGuardRef
	if err != nil || instance.ID != id || instance.OwnerToken == "" {
		return instance, errors.New("invalid managed instance record")
	}
	return instance, nil
}
func LoadRequest(id string, opts Options) (Request, error) {
	dir, err := instanceDir(id, opts)
	if err != nil {
		return Request{}, err
	}
	data, err := os.ReadFile(filepath.Join(dir, "request.json"))
	if err != nil {
		return Request{}, err
	}
	var saved struct {
		Request
		InputBaseDir string `json:"input_base_dir"`
		ArtifactFile string `json:"artifact_file"`
	}
	if json.Unmarshal(data, &saved) != nil {
		return Request{}, errors.New("invalid saved setup request")
	}
	request := saved.Request
	request.InputBaseDir = saved.InputBaseDir
	request.ArtifactFile = saved.ArtifactFile
	request.Input, err = os.ReadFile(filepath.Join(dir, "input"))
	return request, err
}
func saveReceipt(receipt Receipt, opts Options) error {
	root, err := stateRoot(opts)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(filepath.Join(root, "receipts", receipt.ID+".json"), data)
}
func List(opts Options) ([]Instance, error) {
	root, err := stateRoot(opts)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(root, "instances"))
	if os.IsNotExist(err) {
		return []Instance{}, nil
	}
	if err != nil {
		return nil, err
	}
	instances := []Instance{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		instance, err := loadInstance(entry.Name(), opts)
		if os.IsNotExist(err) {
			continue
		} // No owner receipt was committed for this incomplete local draft.
		if err != nil {
			return nil, err
		}
		instances = append(instances, instance)
	}
	sort.Slice(instances, func(i, j int) bool { return instances[i].ID < instances[j].ID })
	return instances, nil
}

func persistProfileSnapshot(instance Instance, request Request, profile []byte, resources map[string][]byte, opts Options) (Request, error) {
	dir, err := instanceDir(instance.ID, opts)
	if err != nil {
		return request, err
	}
	dir = filepath.Join(dir, "source-snapshot")
	for name, data := range resources {
		clean := filepath.Clean(name)
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return request, errors.New("invalid snapshot resource path")
		}
		if err = writePrivate(filepath.Join(dir, clean), data); err != nil {
			return request, err
		}
	}
	request.Input = profile
	request.InputKind = "yaml"
	request.InputBaseDir = dir
	return request, nil
}
