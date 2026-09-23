//go:build windows

package managedcore

import (
	"github.com/daviddwlee84/lazyclash/internal/windowslock"
	"os"
	"path/filepath"
)

func mutationLock(id string, opts Options) (func(), error) {
	dir, err := instanceDir(id, opts)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return nil, err
	}
	return windowslock.Acquire(dir+".lock", true)
}
