package ruleobserve

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPrivateSnapshotRoundTripAndStableCheckpoint(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")
	at := time.Now().UTC()
	a := New("desktop", at)
	a.Add(Event{At: at, Kind: KindDialError, Host: "example.com", Policy: "Final", Rule: "Match", ErrorKind: "timeout", Summary: "https://user:SECRET@example.com"})
	s := a.Snapshot(at)
	s.TargetIdentity = "transport-hash"
	s.Mode, s.FallbackPolicy, s.PreviousSelection, s.GuardID = "fallback_direct", "Final", "PROXY", "guard"
	path, err := Save(dir, s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir, s.ID)
	if err != nil || got.ID != s.ID || got.Mode != s.Mode || got.TargetIdentity != s.TargetIdentity || got.Groups[0].ErrorCount != 1 {
		t.Fatalf("load: %+v %v", got, err)
	}
	if runtime.GOOS != "windows" {
		for _, tc := range []struct {
			path string
			mode os.FileMode
		}{{dir, 0700}, {path, 0600}} {
			info, err := os.Stat(tc.path)
			if err != nil || info.Mode().Perm() != tc.mode {
				t.Fatalf("permissions: %v %v", info, err)
			}
		}
	}
	a.Add(Event{At: at, Kind: KindDialError, Host: "example.com", ErrorKind: "timeout"})
	if _, err = Save(dir, a.Snapshot(at)); err != nil {
		t.Fatal(err)
	}
	list, err := List(dir)
	if err != nil || len(list) != 1 || list[0].Groups[0].ErrorCount != 2 {
		t.Fatalf("checkpoint duplicated history: %+v %v", list, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(data), "SECRET") {
		t.Fatalf("privacy: %s %v", data, err)
	}
}

func TestLoadScrubsUntrustedFreeformSamplesAndRejectsUnsafeFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")
	at := time.Now().UTC()
	a := New("desktop", at)
	a.Add(Event{At: at, Kind: KindDialError, Host: "example.com", ErrorKind: "timeout"})
	s := a.Snapshot(at)
	path, err := Save(dir, s)
	if err != nil {
		t.Fatal(err)
	}
	s.Groups[0].Variants[0].Samples = []string{"password=SECRET\x1b]52;SECRET\a"}
	s.GapDetails = []Gap{{At: at, Reason: "token=SECRET"}}
	data, _ := json.Marshal(s)
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	clean, _ := json.Marshal(got)
	if strings.Contains(string(clean), "SECRET") {
		t.Fatalf("untrusted persisted text leaked: %s", clean)
	}
	if _, err = Load(dir, "../../secret"); err == nil {
		t.Fatal("path traversal accepted")
	}
	if runtime.GOOS != "windows" {
		if err = os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err = Load(dir, s.ID); err == nil {
			t.Fatal("public file accepted")
		}
		if err = os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err = os.Symlink(filepath.Join(t.TempDir(), "outside"), path); err != nil {
			t.Fatal(err)
		}
		if _, err = Save(dir, s); err == nil {
			t.Fatal("symlink overwritten")
		}
		if _, err = Load(dir, s.ID); err == nil {
			t.Fatal("symlink loaded")
		}
	}
}

func TestStateDefaultsAndAbsentHistory(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_STATE_HOME", base)
	want := filepath.Join(base, "lazyclash", "rule-discovery")
	if DefaultDir() != want {
		t.Fatalf("XDG default: %s", DefaultDir())
	}
	list, err := List("")
	if err != nil || len(list) != 0 {
		t.Fatalf("absent history: %+v %v", list, err)
	}
	if _, err = Load("relative", "12345678901234567890123456789012"); err == nil {
		t.Fatal("relative state directory accepted")
	}
	if _, err = os.Stat(want); !os.IsNotExist(err) {
		t.Fatal("read created state")
	}
}
