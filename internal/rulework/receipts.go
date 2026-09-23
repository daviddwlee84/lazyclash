package rulework

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/daviddwlee84/lazyclash/internal/privatefs"
	"os"
	"path/filepath"
)

func receiptDirectory(opts Options, id string, create bool) (string, error) {
	if len(id) != 32 {
		return "", errors.New("invalid rule receipt ID")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", errors.New("invalid rule receipt ID")
	}
	root := opts.StateDir
	if root == "" {
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
		root = filepath.Join(base, "lazyclash", "rule-receipts")
	}
	if !filepath.IsAbs(root) {
		return "", errors.New("rule receipt state directory must be absolute")
	}
	dir := filepath.Join(root, id)
	if create {
		if err := os.MkdirAll(root, 0700); err != nil {
			return "", err
		}
		rootInfo, err := os.Lstat(root)
		if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("rule receipt root must be an ordinary private directory")
		}
		if err := os.Chmod(root, 0700); err != nil {
			return "", err
		}
		if err := os.Mkdir(dir, 0700); err != nil {
			return "", err
		}
		if err := os.Chmod(dir, 0700); err != nil {
			return "", err
		}
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !privatefs.Private(dir) {
		return "", errors.New("receipt directory is absent or not private")
	}
	return dir, nil
}
func prepareReceipt(opts Options, r Receipt, before []byte) error {
	dir, err := receiptDirectory(opts, r.ID, true)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "before.yaml"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	_, err = f.Write(before)
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
	return saveReceipt(opts, r)
}
func saveReceipt(opts Options, r Receipt) error {
	dir, err := receiptDirectory(opts, r.ID, false)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".receipt-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	_, err = f.Write(data)
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
	return os.Rename(f.Name(), filepath.Join(dir, "receipt.json"))
}
func loadReceipt(opts Options, id string) (Receipt, error) {
	var r Receipt
	dir, err := receiptDirectory(opts, id, false)
	if err != nil {
		return r, err
	}
	path := filepath.Join(dir, "receipt.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || !privatefs.Private(path) || info.Size() > 64<<10 {
		return r, errors.New("receipt metadata is absent or unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if json.Unmarshal(data, &r) != nil || r.ID != id {
		return r, errors.New("invalid rule receipt")
	}
	return r, nil
}
