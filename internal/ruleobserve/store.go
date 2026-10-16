package ruleobserve

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/privatefs"
)

const maxSnapshotBytes = 32 << 20

func DefaultDir() string {
	base := os.Getenv("XDG_STATE_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "lazyclash", "rule-discovery")
}

// Save atomically replaces a private structured snapshot. Its stable ID allows
// checkpoints without appending unbounded raw log files.
func Save(dir string, snapshot Snapshot) (string, error) {
	s, err := safeSnapshot(snapshot)
	if err != nil {
		return "", err
	}
	dir, err = stateDir(dir, true)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, s.ID+".json")
	if info, statErr := os.Lstat(path); statErr == nil {
		if !info.Mode().IsRegular() || !privatefs.Private(path) {
			return "", errors.New("existing discovery snapshot is not a private ordinary file")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", statErr
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	if len(data) > maxSnapshotBytes {
		return "", errors.New("discovery snapshot exceeds 32 MiB")
	}
	f, err := os.CreateTemp(dir, ".snapshot-")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	if !privatefs.Private(f.Name()) {
		return "", errors.New("discovery snapshot requires private file permissions")
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return "", err
	}
	return path, nil
}

func Load(dir, id string) (Snapshot, error) {
	if !validID(id) {
		return Snapshot{}, errors.New("invalid discovery session ID")
	}
	dir, err := stateDir(dir, false)
	if err != nil {
		return Snapshot{}, err
	}
	path := filepath.Join(dir, id+".json")
	info, err := os.Lstat(path)
	if err != nil {
		return Snapshot{}, err
	}
	if !info.Mode().IsRegular() || !privatefs.Private(path) || info.Size() > maxSnapshotBytes {
		return Snapshot{}, errors.New("discovery snapshot is not a bounded private ordinary file")
	}
	f, err := os.Open(path)
	if err != nil {
		return Snapshot{}, err
	}
	defer f.Close()
	var s Snapshot
	decoder := json.NewDecoder(io.LimitReader(f, maxSnapshotBytes+1))
	if err = decoder.Decode(&s); err != nil {
		return Snapshot{}, errors.New("invalid discovery snapshot")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || s.ID != id {
		return Snapshot{}, errors.New("invalid discovery snapshot")
	}
	return safeSnapshot(s)
}

// List returns snapshots newest first. An absent state directory is an empty
// history. An unsafe or corrupt session remains an error, not a healthy result.
func List(dir string) ([]Snapshot, error) {
	dir, err := stateDir(dir, false)
	if errors.Is(err, os.ErrNotExist) {
		return []Snapshot{}, nil
	}
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	result := []Snapshot{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !validID(id) {
			continue
		}
		s, err := Load(dir, id)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].StartedAt.Equal(result[j].StartedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].StartedAt.After(result[j].StartedAt)
	})
	return result, nil
}

func stateDir(dir string, create bool) (string, error) {
	if dir == "" {
		dir = DefaultDir()
	}
	if !filepath.IsAbs(dir) {
		return "", errors.New("discovery state directory must be absolute")
	}
	if create {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return "", err
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("discovery state must be an ordinary private directory")
	}
	if create {
		if err = os.Chmod(dir, 0700); err != nil {
			return "", err
		}
	}
	if !privatefs.Private(dir) {
		return "", errors.New("discovery state directory is not private")
	}
	return dir, nil
}

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func safeSnapshot(s Snapshot) (Snapshot, error) {
	if s.Version != 1 || !validID(s.ID) || s.TargetID == "" || s.StartedAt.IsZero() || s.UpdatedAt.Before(s.StartedAt) || len(s.Groups) > MaxGroups || len(s.GapDetails) > MaxGapDetails || s.Observed < 0 || s.Dropped < 0 || s.Unparsed < 0 || s.Gaps < 0 {
		return Snapshot{}, errors.New("invalid discovery snapshot metadata")
	}
	for _, field := range []string{s.TargetID, s.TargetIdentity, s.Mode, s.Status, s.FallbackPolicy, s.PreviousSelection, s.GuardID} {
		if metadataText(field) != field {
			return Snapshot{}, errors.New("invalid discovery snapshot text")
		}
	}
	if s.Mode != "normal" && s.Mode != "fallback_direct" {
		return Snapshot{}, errors.New("invalid discovery mode")
	}
	s.Groups = append([]Group{}, s.Groups...)
	s.GapDetails = append([]Gap{}, s.GapDetails...)
	for i := range s.GapDetails {
		s.GapDetails[i].Reason = safeGapReason(s.GapDetails[i].Reason)
	}
	seen := map[string]bool{}
	for i := range s.Groups {
		g := &s.Groups[i]
		if g.Host != "" {
			var err error
			g.Host, g.IsIP, err = normalizeHost(g.Host)
			if err != nil {
				return Snapshot{}, errors.New("invalid discovery destination")
			}
		} else {
			g.IsIP = false
		}
		g.Key = groupKey(g.Host, g.IsIP)
		if seen[g.Key] || g.Count < 0 || g.ErrorCount < 0 || g.SuccessCount < 0 || g.OtherCount < 0 || g.Count != g.ErrorCount+g.SuccessCount+g.OtherCount || g.DroppedVariants < 0 || len(g.Variants) > MaxVariants {
			return Snapshot{}, errors.New("invalid discovery group")
		}
		seen[g.Key] = true
		g.Variants = append([]Variant{}, g.Variants...)
		for j := range g.Variants {
			v := &g.Variants[j]
			if v.Count < 0 || len(v.Samples) > MaxSamples {
				return Snapshot{}, errors.New("invalid discovery variant")
			}
			e := safeEvent(Event{Host: g.Host, IsIP: g.IsIP, Kind: v.Kind, Network: v.Network, Port: v.Port, Process: v.Process, Rule: v.Rule, RulePayload: v.RulePayload, Policy: v.Policy, ErrorKind: v.ErrorKind})
			v.Kind, v.Network, v.Port, v.Process, v.Rule, v.RulePayload, v.Policy, v.ErrorKind = e.Kind, e.Network, e.Port, e.Process, e.Rule, e.RulePayload, e.Policy, e.ErrorKind
			// Regenerate safe descriptions even for externally supplied JSON.
			v.Samples = []string{e.Summary}
		}
	}
	return s, nil
}
