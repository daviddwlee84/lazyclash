//go:build windows

package analytics

import "github.com/daviddwlee84/lazyclash/internal/windowslock"

func lockCollector(path string) (func(), error) {
	return windowslock.Acquire(path+".collector.lock", false)
}
