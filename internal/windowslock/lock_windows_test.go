//go:build windows

package windowslock

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeLockExclusionAndRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locks", "writer.lock")
	release, err := Acquire(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := Acquire(path, false); err == nil {
		other()
		t.Fatal("second writer acquired lock")
	}
	release()
	again, err := Acquire(path, false)
	if err != nil {
		t.Fatal(err)
	}
	again()
}
func TestNativeLockRejectsAliasedFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.WriteFile(target, nil, 0600)
	link := filepath.Join(dir, "linked")
	if err := os.Link(target, link); err != nil {
		t.Fatal(err)
	}
	if release, err := Acquire(link, false); err == nil {
		release()
		t.Fatal("hard linked lock accepted")
	}
	if release, err := Acquire(dir, false); err == nil {
		release()
		t.Fatal("directory lock accepted")
	}
}
