package analytics

import (
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/core"
)

func TestConnectionIntervalsDoNotDoubleCountTotals(t *testing.T) {
	start := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	tracker := counterTracker{}
	a := observedCounter{Upload: 500, Download: 700, Identity: "a-start", Domain: "a.example", Start: start.Add(-time.Hour)}
	d, e, coverage, _, _ := tracker.observeConnections("client", start, map[string]observedCounter{"a": a}, &observedCounter{Upload: 1000, Download: 2000}, 6*time.Second)
	if len(d) != 0 || len(e) != 1 || !coverage.IsZero() {
		t.Fatalf("first snapshot must baseline: %#v %#v %v", d, e, coverage)
	}
	a.Upload += 100
	a.Download += 200
	b := observedCounter{Upload: 50, Download: 75, Identity: "b-start", Domain: "b.example", Start: start.Add(time.Second)}
	d, e, coverage, reset, mismatch := tracker.observeConnections("client", start.Add(2*time.Second), map[string]observedCounter{"a": a, "b": b}, &observedCounter{Upload: 1200, Download: 2300}, 6*time.Second)
	var up, down int64
	var residual *Delta
	for i := range d {
		up += d[i].UploadBytes
		down += d[i].DownloadBytes
		if d[i].Route == "unattributed" {
			residual = &d[i]
		}
	}
	if up != 200 || down != 300 || len(e) != 1 || coverage != start || reset != 0 || mismatch {
		t.Fatalf("wrong accounting: %#v %#v coverage=%v resets=%d mismatch=%v", d, e, coverage, reset, mismatch)
	}
	if residual == nil || residual.UploadBytes != 50 || residual.DownloadBytes != 25 {
		t.Fatalf("missing unattributed bytes: %#v", d)
	}
	if d[1].Domain == "b.example" && d[1].Start != b.Start {
		t.Fatal("new connection must start in its observed interval")
	}
}

func TestConnectionGapResetAndMismatch(t *testing.T) {
	start := time.Now()
	tr := counterTracker{}
	values := map[string]observedCounter{"a": {Upload: 100, Download: 100, Identity: "a"}}
	tr.observeConnections("s", start, values, &observedCounter{Upload: 100, Download: 100}, 6*time.Second)
	values = map[string]observedCounter{"a": {Upload: 200, Download: 200, Identity: "a"}}
	d, _, c, _, _ := tr.observeConnections("s", start.Add(time.Minute), values, &observedCounter{Upload: 200, Download: 200}, 6*time.Second)
	if len(d) != 0 || !c.IsZero() {
		t.Fatal("gap must not backcharge the intervening bytes")
	}
	values = map[string]observedCounter{"a": {Upload: 400, Download: 400, Identity: "a"}}
	d, _, c, _, mismatch := tr.observeConnections("s", start.Add(time.Minute+time.Second), values, &observedCounter{Upload: 210, Download: 210}, 6*time.Second)
	if len(d) != 1 || d[0].UploadBytes != 10 || d[0].DownloadBytes != 10 || d[0].Route != "unattributed" || !c.IsZero() || !mismatch {
		t.Fatal("inconsistent flow attribution must retain valid aggregate bytes as unattributed")
	}
	d, _, c, resets, _ := tr.observeConnections("s", start.Add(time.Minute+2*time.Second), values, &observedCounter{Upload: 1, Download: 1}, 6*time.Second)
	if len(d) != 0 || !c.IsZero() || resets == 0 {
		t.Fatal("core reset must establish a fresh baseline")
	}
}

func TestMihomoMetadataAndBoundedCounters(t *testing.T) {
	v, d, err := parseMihomoCounters(core.Object{"connections": []any{core.Object{"id": "1", "upload": float64(10), "download": float64(20), "start": "2026-09-22T00:00:00Z", "metadata": core.Object{"host": "wrong.example", "sniffHost": "RIGHT.Example.", "sourceIP": "192.0.2.4", "inboundUser": "test-user", "processPath": "/Applications/Test.app/Test"}}, core.Object{"id": "2", "upload": float64(1), "download": float64(2), "metadata": core.Object{"destinationIP": "203.0.113.8"}}, core.Object{"id": "bad", "upload": -1, "download": 1}}})
	if err != nil || d != 1 || v["1"].Domain != "right.example" || v["1"].Principal != "test-user" || v["1"].Process != "Test" || v["2"].Domain != "203.0.113.8" {
		t.Fatalf("unexpected metadata: %#v dropped=%d err=%v", v, d, err)
	}
}

func TestStatsCommandNeverResetsOrUsesShell(t *testing.T) {
	for _, format := range []string{"xray", "v2ray", "v2ctl"} {
		_, args, err := statsCommand(SourceConfig{Format: format, Address: "127.0.0.1:10085"})
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "reset=false") && !strings.Contains(joined, "reset: false") {
			t.Fatalf("command lacks explicit non-reset behavior: %v", args)
		}
	}
	if _, _, err := statsCommand(SourceConfig{Address: "203.0.113.5:10085"}); err == nil {
		t.Fatal("stats must remain collector-host local")
	}
	v, err := parseStatsCounters([]byte(`{"stat":[{"name":"user>>>alice>>>traffic>>>uplink","value":"10"},{"name":"user>>>alice>>>traffic>>>downlink","value":20},{"name":"inbound>>>proxy>>>traffic>>>uplink","value":"10"}]}`))
	if err != nil || len(v) != 1 || v["alice"].Upload != 10 || v["alice"].Download != 20 {
		t.Fatalf("must not double count user+inbound: %#v %v", v, err)
	}
	if _, err = parseStatsCounters([]byte(`{"stat":[{"name":"inbound>>>proxy>>>traffic>>>uplink","value":"10"}]}`)); err == nil {
		t.Fatal("missing per-user stats must be unsupported, not zero")
	}
	v, err = parseStatsCounters([]byte("stat: <\n name: \"user>>>legacy>>>traffic>>>uplink\"\n value: 42\n>\nstat: < name: \"user>>>legacy>>>traffic>>>downlink\" >"))
	if err != nil || v["legacy"].Upload != 42 || v["legacy"].Download != 0 {
		t.Fatalf("legacy v2ctl protobuf counters unsupported: %#v %v", v, err)
	}
}
