//go:build !darwin && !linux

package serverstate

import "errors"

func Lock(string) (func(), error) {
	return nil, errors.New("server mutations require a macOS or Linux client")
}
