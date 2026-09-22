package analytics

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testAccessLine = "2026/09/22 00:00:01.123 from 192.0.2.3:54321 accepted tcp:example.test:443 [proxy -> direct] email: alice\n"

func accessAppend(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}

func TestAccessTailCheckpointPartialRotationAndTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, []byte(testAccessLine), 0600); err != nil {
		t.Fatal(err)
	}
	a := &accessTail{source: SourceConfig{ID: "server", Kind: "xray-access", Path: path}, zone: time.UTC}
	defer a.close()
	now := time.Date(2026, 9, 22, 0, 1, 0, 0, time.UTC)
	b, _, _, err := a.poll(context.Background(), now)
	if err != nil || len(b.Events) != 0 {
		t.Fatal("initial log history must baseline at EOF", err)
	}
	accessAppend(t, path, testAccessLine+"2026/09/22 00:00:02 from 192.0.2.4:123 accepted tcp:partial.test:443")
	b, _, drop, err := a.poll(context.Background(), now.Add(time.Second))
	if err != nil || len(b.Events) != 1 || drop != 0 {
		t.Fatalf("partial line was mishandled: %#v %d %v", b, drop, err)
	}
	checkpoint := a.position
	a.close()
	a = &accessTail{source: a.source, zone: time.UTC, position: checkpoint, restored: true}
	defer a.close()
	accessAppend(t, path, " [in -> out]\n")
	b, _, _, err = a.poll(context.Background(), now.Add(2*time.Second))
	if err != nil || len(b.Events) != 1 || b.Events[0].Domain != "partial.test" {
		t.Fatalf("restart checkpoint lost partial: %#v %v", b, err)
	}
	if err = os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte(testAccessLine), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = a.poll(context.Background(), now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	b, _, _, err = a.poll(context.Background(), now.Add(4*time.Second))
	if err != nil || len(b.Events) != 1 {
		t.Fatalf("replacement file not followed: %#v %v", b, err)
	}
	// Same inode, truncated and regrown beyond prior offset: the anchor detects it.
	if err = os.WriteFile(path, []byte(strings.ReplaceAll(testAccessLine, "example.test", "different.test")+testAccessLine), 0600); err != nil {
		t.Fatal(err)
	}
	b, gaps, _, err := a.poll(context.Background(), now.Add(5*time.Second))
	if err != nil || gaps != 1 || len(b.Events) != 2 {
		t.Fatalf("copytruncate/regrow missed: %#v gaps=%d %v", b, gaps, err)
	}
}

func TestAccessOversizeMalformedAndIPv6(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	_ = os.WriteFile(path, nil, 0600)
	a := &accessTail{source: SourceConfig{ID: "s", Kind: "xray-access", Path: path}, zone: time.UTC}
	defer a.close()
	now := time.Date(2026, 9, 22, 1, 0, 0, 0, time.UTC)
	_, _, _, _ = a.poll(context.Background(), now)
	accessAppend(t, path, strings.Repeat("x", maxAccessLine*2)+"\nmalformed\n"+testAccessLine)
	b, _, d, err := a.poll(context.Background(), now.Add(time.Second))
	if err != nil || d != 2 || len(b.Events) != 1 {
		t.Fatalf("oversize should recover boundedly: events=%d drop=%d err=%v", len(b.Events), d, err)
	}
	e, ok := parseAccessLine("2026/09/22 00:00:01 [2001:db8::1]:123 accepted udp:[2001:db8::2]:443 [in -> out]", time.UTC)
	if !ok || e.ClientIP != "2001:db8::1" || e.Domain != "2001:db8::2" {
		t.Fatalf("IPv6 failed: %#v", e)
	}
}
