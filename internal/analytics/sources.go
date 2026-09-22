package analytics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

const maxSourceItems = 2000
const maxCommandBytes = 8 << 20

// Capability reports what can be observed, without enabling collection or writing state.
type Capability struct {
	SourceID    string   `json:"source_id"`
	Kind        string   `json:"kind"`
	Scope       string   `json:"scope"`
	Enabled     bool     `json:"enabled"`
	Available   bool     `json:"available"`
	State       string   `json:"state"`
	Message     string   `json:"message"`
	Dimensions  []string `json:"dimensions,omitempty"`
	PollSeconds int      `json:"poll_seconds"`
}

func ValidateSource(s SourceConfig) error {
	if !sourceIDPattern.MatchString(s.ID) {
		return errors.New("source id must be a safe name (1–64 characters)")
	}
	if s.PollSeconds < 0 || s.PollSeconds > 3600 {
		return errors.New("poll_seconds must be 0–3600")
	}
	if s.Timezone != "" {
		if _, err := time.LoadLocation(s.Timezone); err != nil {
			return errors.New("source timezone is invalid")
		}
	}
	if s.Scope != "" && s.Scope != sourceScope(SourceConfig{Kind: s.Kind}) {
		return errors.New("source scope does not match its measurement kind")
	}
	switch s.Kind {
	case "mihomo":
		if s.Target == "" {
			return errors.New("Mihomo source needs a registered target id")
		}
	case "interface", "host-interface", "vnstat":
		if s.Interface == "" || s.Interface == "." || s.Interface == ".." || strings.ContainsAny(s.Interface, "/\\\x00\r\n") {
			return errors.New("an explicit valid interface is required")
		}
	case "access", "xray-access", "v2ray-access":
		if !filepath.IsAbs(s.Path) {
			return errors.New("access log path must be absolute on the collector host")
		}
		if s.Format != "" && s.Format != "xray" && s.Format != "v2ray" {
			return errors.New("access format must be xray or v2ray")
		}
	case "stats", "xray-stats", "v2ray-stats":
		_, _, err := statsCommand(s)
		return err
	default:
		return errors.New("source kind must be mihomo, interface, xray-access, xray-stats or vnstat")
	}
	return nil
}

func sourceScope(s SourceConfig) string {
	if s.Scope != "" {
		return s.Scope
	}
	switch s.Kind {
	case "mihomo":
		return "client"
	case "access", "xray-access", "v2ray-access", "stats", "xray-stats", "v2ray-stats":
		return "server"
	default:
		return "host"
	}
}

func sourceInterval(s SourceConfig) time.Duration {
	if s.PollSeconds > 0 {
		return time.Duration(s.PollSeconds) * time.Second
	}
	switch s.Kind {
	case "mihomo", "access", "xray-access", "v2ray-access":
		return 2 * time.Second
	case "stats", "xray-stats", "v2ray-stats":
		return 15 * time.Second
	default:
		return 30 * time.Second
	}
}

func findSourceTarget(id string, targets []config.Target) (config.Target, error) {
	for _, t := range targets {
		if t.ID == id {
			return t, nil
		}
	}
	return config.Target{}, errors.New("configured Mihomo target is not registered on this collector host")
}

func resolvedSourceBinding(s SourceConfig, targets []config.Target) (string, error) {
	host, _ := os.Hostname()
	parts := []string{"node-local-v1", host}
	if s.Kind == "mihomo" {
		t, err := findSourceTarget(s.Target, targets)
		if err != nil {
			return "", err
		}
		parts = append(parts, t.Controller, t.SSHHost, t.CAFile)
	}
	if (s.Kind == "access" || s.Kind == "xray-access" || s.Kind == "v2ray-access") && s.Timezone == "" {
		parts = append(parts, os.Getenv("TZ"), time.Local.String())
		// Local wall-clock logs change meaning if the collecting host's zone
		// changes. Hash the zone definition, not today's DST-dependent offset.
		if f, err := os.Open("/etc/localtime"); err == nil {
			b, e := io.ReadAll(io.LimitReader(f, 1<<20))
			_ = f.Close()
			if e == nil {
				parts = append(parts, stableSourceID(string(b)))
			}
		}
	}
	return stableSourceID(parts...), nil
}

// Doctor opens only read-only endpoints/files. Disabled sources are checked only
// for configuration; they are never contacted as a side effect of inspection.
func Doctor(ctx context.Context, cfg Config, targets []config.Target) []Capability {
	return DoctorWithOptions(ctx, cfg, targets, CollectorOptions{})
}

func DoctorWithOptions(ctx context.Context, cfg Config, targets []config.Target, opts CollectorOptions) []Capability {
	open := opts.Open
	if open == nil {
		open = connection.Open
	}
	out := make([]Capability, 0, len(cfg.Sources))
	for _, s := range cfg.Sources {
		c := Capability{SourceID: s.ID, Kind: s.Kind, Scope: sourceScope(s), Enabled: s.Enabled, State: "disabled", Message: "source is disabled", PollSeconds: int(sourceInterval(s) / time.Second)}
		if err := ValidateSource(s); err != nil {
			c.State = "invalid"
			c.Message = err.Error()
			out = append(out, c)
			continue
		}
		if !s.Enabled {
			out = append(out, c)
			continue
		}
		c.State = "unavailable"
		probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		var err error
		switch s.Kind {
		case "mihomo":
			c.Dimensions = []string{"client_ip", "domain", "process", "route", "observed_bytes"}
			var t config.Target
			t, err = findSourceTarget(s.Target, targets)
			if err == nil && t.SSHHost != "" {
				cancel()
				c.State = "remote-target"
				c.Message = "run the collector on the target host with a local target and local secret references"
				out = append(out, c)
				continue
			}
			if err == nil {
				var client *core.Client
				var close io.Closer
				client, close, err = open(probeCtx, t, true)
				if err == nil {
					_, err = client.Connections(probeCtx)
					_ = close.Close()
				}
			}
			c.Message = "connection snapshots are sampled; short connections and final closed-connection bytes may be missed"
		case "interface", "host-interface":
			c.Dimensions = []string{"host_interface_bytes"}
			_, _, err = readInterfaceCounters(s.Interface)
			c.Message = "whole-interface counters; includes non-proxy traffic"
		case "access", "xray-access", "v2ray-access":
			c.Dimensions = []string{"client_ip", "domain", "principal", "route", "connection_events"}
			err = checkAccessPath(s.Path)
			c.Message = "accepted connection events; access logs do not measure bytes or human attention"
		case "stats", "xray-stats", "v2ray-stats":
			c.Dimensions = []string{"principal", "cumulative_bytes"}
			var b []byte
			b, err = runStatsCommand(probeCtx, s)
			if err == nil {
				_, err = parseStatsCounters(b)
			}
			c.Message = "per-user counters require unique configured user labels and enabled stats policy"
		case "vnstat":
			c.Dimensions = []string{"native_daily_interface_bytes"}
			if strings.TrimSpace(s.Interface) == "" {
				err = errors.New("an explicit interface is required")
			}
			c.State = "import-only"
			c.Message = "import completed daily vnStat JSON buckets explicitly; no live collector"
		default:
			err = errors.New("unsupported source kind")
		}
		cancel()
		if err != nil {
			c.Message = safeSourceError(s.Kind, err)
		} else {
			c.Available = true
			if c.State != "import-only" {
				c.State = "ready"
			}
		}
		out = append(out, c)
	}
	return out
}

func safeSourceError(kind string, err error) string {
	// Never include raw logs, subprocess stderr, URLs, or secret-bearing paths.
	var ce *core.Error
	if errors.As(err, &ce) {
		return ce.Error()
	}
	if errors.Is(err, context.Canceled) {
		return "source read canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "source read timed out"
	}
	return kind + " source unavailable; check its collector-host configuration and read permissions"
}

type observedCounter struct {
	Upload, Download                            int64
	ClientIP, Domain, Process, Route, Principal string
	Identity                                    string
	Start                                       time.Time
}

type counterTracker struct {
	last     time.Time
	previous map[string]observedCounter
	total    *observedCounter
}

func (t *counterTracker) reset() { t.last = time.Time{}; t.previous = nil; t.total = nil }

func (t *counterTracker) observe(sourceID string, now time.Time, values map[string]observedCounter, maxGap time.Duration, connections bool) (deltas []Delta, events []Event, coverage time.Time, resets int64) {
	continuous := !t.last.IsZero() && now.After(t.last) && now.Sub(t.last) <= maxGap
	if continuous {
		coverage = t.last
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		cur := values[key]
		prev, known := t.previous[key]
		if connections && (!known || prev.Identity != cur.Identity) {
			events = append(events, Event{ID: stableSourceID(sourceID, "connection", key, cur.Identity), At: now, ClientIP: cur.ClientIP, Domain: cur.Domain, Process: cur.Process, Route: cur.Route, Principal: cur.Principal, Count: 1})
		}
		start := t.last
		if !continuous {
			continue
		}
		if !known || prev.Identity != cur.Identity {
			if !connections || cur.Start.IsZero() || cur.Start.Before(t.last) || cur.Start.After(now) {
				continue
			}
			prev = observedCounter{}
			start = cur.Start
			if !start.Before(now) {
				continue
			}
		}
		if cur.Upload < prev.Upload || cur.Download < prev.Download {
			resets++
			continue
		}
		up, down := cur.Upload-prev.Upload, cur.Download-prev.Download
		if up == 0 && down == 0 {
			continue
		}
		deltas = append(deltas, Delta{ID: stableSourceID(sourceID, "delta", key, start.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano)), Start: start, End: now, UploadBytes: up, DownloadBytes: down, ClientIP: cur.ClientIP, Domain: cur.Domain, Process: cur.Process, Route: cur.Route, Principal: cur.Principal})
	}
	t.last, t.previous = now, values
	return
}

func (t *counterTracker) observeConnections(sourceID string, now time.Time, values map[string]observedCounter, total *observedCounter, maxGap time.Duration) (deltas []Delta, events []Event, coverage time.Time, resets int64, mismatch bool) {
	last, previousTotal := t.last, t.total
	deltas, events, coverage, resets = t.observe(sourceID, now, values, maxGap, true)
	t.total = total
	if coverage.IsZero() {
		return
	}
	if total == nil || previousTotal == nil {
		mismatch = true
		return
	}
	if total.Upload < previousTotal.Upload || total.Download < previousTotal.Download {
		resets++
		deltas = nil
		coverage = time.Time{}
		return
	}
	up, down := total.Upload-previousTotal.Upload, total.Download-previousTotal.Download
	aggregateUp, aggregateDown := up, down
	for _, d := range deltas {
		if d.UploadBytes > up || d.DownloadBytes > down {
			mismatch = true
			// The aggregate counter remains valid even when per-connection
			// snapshots are inconsistent. Preserve its measured bytes without
			// claiming site/client attribution for this interval.
			deltas = []Delta{{ID: stableSourceID(sourceID, "unattributed", last.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano)), Start: last, End: now, UploadBytes: aggregateUp, DownloadBytes: aggregateDown, Route: "unattributed"}}
			coverage = time.Time{}
			return
		}
		up -= d.UploadBytes
		down -= d.DownloadBytes
	}
	if up > 0 || down > 0 {
		deltas = append(deltas, Delta{ID: stableSourceID(sourceID, "unattributed", last.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano)), Start: last, End: now, UploadBytes: up, DownloadBytes: down, Route: "unattributed"})
	}
	return
}

func stableSourceID(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%d:", len(p))
		_, _ = io.WriteString(h, p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func parseMihomoCounters(data core.Object) (map[string]observedCounter, int64, error) {
	items, ok := data["connections"].([]any)
	if !ok { // The HTTP client returns []any; typed forms also support fixtures.
		switch v := data["connections"].(type) {
		case []core.Object:
			for _, item := range v {
				items = append(items, item)
			}
		case []map[string]any:
			for _, item := range v {
				items = append(items, item)
			}
		default:
			return nil, 0, errors.New("invalid connections response")
		}
	}
	out := make(map[string]observedCounter, min(len(items), maxSourceItems))
	var dropped int64
	for _, raw := range items {
		if len(out) >= maxSourceItems {
			dropped++
			continue
		}
		item := sourceObject(raw)
		id := sourceString(item["id"])
		up, uok := sourceInt(item["upload"])
		down, dok := sourceInt(item["download"])
		if id == "" || !uok || !dok {
			dropped++
			continue
		}
		meta := sourceObject(item["metadata"])
		process := sourceString(meta["process"])
		if process == "" {
			process = filepath.Base(sourceString(meta["processPath"]))
			if process == "." {
				process = ""
			}
		}
		var routes []string
		if r := sourceString(item["rule"]); r != "" {
			routes = append(routes, r)
		}
		if chain, ok := item["chains"].([]any); ok {
			for _, r := range chain {
				if s := sourceString(r); s != "" {
					routes = append(routes, s)
				}
			}
		}
		domain := sourceString(meta["sniffHost"])
		if domain == "" {
			domain = sourceString(meta["host"])
		}
		if domain == "" {
			domain = sourceString(meta["destinationIP"])
		}
		identity := sourceString(item["start"])
		start, _ := time.Parse(time.RFC3339Nano, identity)
		out[id] = observedCounter{Upload: up, Download: down, ClientIP: sourceString(meta["sourceIP"]), Domain: strings.ToLower(strings.TrimSuffix(domain, ".")), Process: process, Route: strings.Join(routes, " → "), Principal: sourceString(meta["inboundUser"]), Identity: identity, Start: start}
	}
	return out, dropped, nil
}

func sourceObject(v any) core.Object {
	switch x := v.(type) {
	case core.Object:
		return x
	case map[string]any:
		return core.Object(x)
	default:
		return nil
	}
}
func sourceString(v any) string {
	s, _ := v.(string)
	if len(s) > 1024 {
		s = s[:1024]
	}
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
}
func sourceInt(v any) (int64, bool) {
	var n int64
	var err error
	switch x := v.(type) {
	case float64:
		if x < 0 || x > float64(1<<53) || x != float64(int64(x)) {
			return 0, false
		}
		n = int64(x)
	case int64:
		n = x
	case int:
		n = int64(x)
	case json.Number:
		n, err = x.Int64()
	case string:
		n, err = strconv.ParseInt(x, 10, 64)
	default:
		return 0, false
	}
	return n, err == nil && n >= 0
}

func readInterfaceCounters(iface string) (int64, int64, error) {
	if runtime.GOOS != "linux" {
		return 0, 0, errors.New("host interface collection requires Linux sysfs")
	}
	if iface == "" || iface == "." || iface == ".." || strings.ContainsAny(iface, "/\\\x00\r\n") {
		return 0, 0, errors.New("explicit valid interface is required")
	}
	read := func(name string) (int64, error) {
		b, err := os.ReadFile(filepath.Join("/sys/class/net", iface, "statistics", name))
		if err != nil {
			return 0, err
		}
		return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	}
	tx, err := read("tx_bytes")
	if err != nil {
		return 0, 0, err
	}
	rx, err := read("rx_bytes")
	if tx < 0 || rx < 0 {
		return 0, 0, errors.New("invalid interface counters")
	}
	return tx, rx, err
}

func statsCommand(s SourceConfig) (string, []string, error) {
	address := s.Address
	if address == "" {
		address = "127.0.0.1:10085"
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return "", nil, errors.New("stats address must be a loopback host:port")
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", nil, errors.New("stats address must be loopback on the collector host")
	}
	format := s.Format
	if format == "" {
		if s.Kind == "v2ray-stats" {
			format = "v2ray"
		} else {
			format = "xray"
		}
	}
	binary := s.Binary
	if binary == "" {
		binary = format
	}
	if strings.HasPrefix(binary, "-") || strings.ContainsAny(binary, "\x00\r\n") {
		return "", nil, errors.New("invalid stats binary")
	}
	switch format {
	case "xray":
		return binary, []string{"api", "statsquery", "--server=" + address, "--reset=false"}, nil
	case "v2ray":
		return binary, []string{"api", "stats", "--server=" + address, "--json", "--reset=false"}, nil
	case "v2ctl":
		return binary, []string{"api", "--server=" + address, "StatsService.QueryStats", `pattern: "" reset: false`}, nil
	default:
		return "", nil, errors.New("stats format must be xray, v2ray or v2ctl")
	}
}

type sourceLimitWriter struct {
	bytes.Buffer
	limit int
}

func (w *sourceLimitWriter) Write(p []byte) (int, error) {
	if w.Len()+len(p) > w.limit {
		return 0, errors.New("source command output exceeds limit")
	}
	return w.Buffer.Write(p)
}
func runStatsCommand(ctx context.Context, s SourceConfig) ([]byte, error) {
	binary, args, err := statsCommand(s)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.WaitDelay = time.Second
	out := &sourceLimitWriter{limit: maxCommandBytes}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if err = cmd.Run(); err != nil {
		return nil, errors.New("stats command unavailable or unsupported")
	}
	return out.Bytes(), nil
}

type sourceStatEntry struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

var sourceProtoStatPattern = regexp.MustCompile(`(?s)stat\s*:\s*[<{]\s*name\s*:\s*("(?:[^"\\]|\\.)*")\s*(?:value\s*:\s*([0-9]+)\s*)?[>}]`)

func parseStatsCounters(data []byte) (map[string]observedCounter, error) {
	var reply struct {
		Stat []sourceStatEntry `json:"stat"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&reply); err != nil {
		// V2Ray 4's installed v2ctl emits protobuf text, while Xray and V2Ray
		// 5 expose JSON. Accept the bounded canonical QueryStats text form.
		matches := sourceProtoStatPattern.FindAllSubmatch(data, maxSourceItems*2+1)
		if len(matches) == 0 {
			return nil, errors.New("stats command did not return supported counters")
		}
		if len(bytes.TrimSpace(sourceProtoStatPattern.ReplaceAll(data, nil))) != 0 {
			return nil, errors.New("stats command returned malformed protobuf counters")
		}
		for _, match := range matches {
			name, e := strconv.Unquote(string(match[1]))
			if e != nil {
				return nil, errors.New("invalid stats label")
			}
			value := match[2]
			if len(value) == 0 {
				value = []byte("0")
			}
			reply.Stat = append(reply.Stat, sourceStatEntry{Name: name, Value: json.RawMessage(value)})
		}
	}
	if len(reply.Stat) > maxSourceItems*2 {
		return nil, errors.New("stats response exceeds counter limit")
	}
	out := map[string]observedCounter{}
	for _, stat := range reply.Stat {
		parts := strings.Split(stat.Name, ">>>")
		if len(parts) != 4 || parts[2] != "traffic" {
			continue
		}
		// User counters are one independent accounting plane. Inbound/outbound
		// totals describe the same bytes and must never be added to user totals.
		if parts[0] != "user" {
			continue
		}
		if parts[3] != "uplink" && parts[3] != "downlink" {
			continue
		}
		var value any
		if len(stat.Value) == 0 {
			stat.Value = json.RawMessage("0")
		}
		d := json.NewDecoder(bytes.NewReader(stat.Value))
		d.UseNumber()
		if err := d.Decode(&value); err != nil {
			return nil, errors.New("invalid stats value")
		}
		n, ok := sourceInt(value)
		if !ok {
			return nil, errors.New("invalid stats value")
		}
		key := sourceString(parts[1])
		if key == "" {
			continue
		}
		v := out[key]
		v.Principal = key
		v.Identity = key
		if parts[3] == "uplink" {
			v.Upload = n
		} else {
			v.Download = n
		}
		out[key] = v
		if len(out) > maxSourceItems {
			return nil, errors.New("stats response exceeds user limit")
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no per-user stats; enable user stats and configure unique user labels")
	}
	return out, nil
}
