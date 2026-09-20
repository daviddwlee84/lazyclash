package selfupdate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshotIncludesParentAndChainedSymlinks(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(directory, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(real, "binary")
	if err := os.WriteFile(executable, []byte("original executable"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("binary", filepath.Join(real, "lazyclash")); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(directory, "bin")
	if err := os.Symlink("real", parent); err != nil {
		t.Fatal(err)
	}
	installation := Installation{Executable: filepath.Join(parent, "lazyclash"), ResolvedPath: executable}
	snapshot, err := snapshotInstallation(installation)
	if err != nil || len(snapshot.links) != 2 {
		t.Fatalf("snapshot=%+v error=%v", snapshot, err)
	}
	if err := snapshot.validate(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, parent); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.validate(); err == nil || !strings.Contains(err.Error(), "symlink changed") {
		t.Fatal("parent symlink change was not detected:", err)
	}
}

func TestSnapshotRejectsFileChangedAfterMetadataInspection(t *testing.T) {
	installation, _ := updateFixture(t)
	var err error
	installation.fileInfo, err = os.Stat(installation.ResolvedPath)
	if err != nil {
		t.Fatal(err)
	}
	other := installation.ResolvedPath + ".new"
	if err := os.WriteFile(other, []byte("another installation"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, installation.ResolvedPath); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotInstallation(installation); err == nil || !strings.Contains(err.Error(), "metadata was inspected") {
		t.Fatal("stale inspection accepted:", err)
	}
}
