//go:build windows

package serverstate

import "github.com/daviddwlee84/lazyclash/internal/windowslock"

func Lock(path string) (func(), error) { return windowslock.Acquire(path, true) }
