//go:build !darwin && !linux && !windows

package managedcore

import "errors"

func mutationLock(string, Options) (func(), error) {
	return nil, errors.New("managed lifecycle changes currently require a macOS or Linux client")
}
