// Package testcore provides an in-memory Mihomo-compatible controller for tests
// and terminal demos. It never reads configurations or opens outbound proxies.
package testcore

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
)

// These stable names include characters that routinely expose URL/UI bugs.
const (
	Selector      = "🚀 Proxy"
	Automatic     = "♻️ Auto"
	Taipei        = "🇹🇼 台北"
	Tokyo         = "🇯🇵 東京/01"
	ProxyProvider = "示範訂閱"
	RuleProvider  = "示範規則"
)

type object = map[string]any

// Request excludes authentication headers. Path is decoded; EscapedPath retains
// segment boundaries so tests can distinguish a slash in a proxy name.
type Request struct {
	Method      string
	Path        string
	EscapedPath string
	Query       url.Values
	Body        map[string]any
}

// Controller is a concurrent, stateful HTTP fixture. Requests and LastApplied
// return copies/snapshots; handlers never perform external I/O.
type Controller struct {
	mu          sync.Mutex
	config      object
	proxies     map[string]object
	connections map[string]object
	providers   map[string]map[string]object
	requests    []Request
	lastApplied string
}

func NewHandler() *Controller {
	stamp := "2026-09-20T07:00:00Z"
	leaf := func(name, kind string, delay int) object {
		return object{"name": name, "type": kind, "udp": true, "alive": true, "history": []any{object{"time": stamp, "delay": delay}}}
	}
	group := func(name, kind, now string, all []string) object {
		return object{"name": name, "type": kind, "udp": true, "alive": true, "now": now, "all": all, "history": []any{}}
	}
	proxies := map[string]object{
		"DIRECT":     leaf("DIRECT", "Direct", 8),
		"REJECT":     leaf("REJECT", "Reject", 0),
		Taipei:       leaf(Taipei, "Shadowsocks", 38),
		Tokyo:        leaf(Tokyo, "Vmess", 62),
		Selector:     group(Selector, "Selector", Taipei, []string{Taipei, Tokyo, Automatic, "DIRECT"}),
		Automatic:    group(Automatic, "URLTest", Taipei, []string{Taipei, Tokyo}),
		"⚖️ Balance": group("⚖️ Balance", "LoadBalance", "", []string{Taipei, Tokyo}),
	}
	connection := func(id, host, proxy string) object {
		return object{
			"id": id, "start": stamp, "upload": 1024, "download": 8192,
			"chains": []string{proxy, Selector}, "rule": "DomainSuffix", "rulePayload": "example.test",
			"metadata": object{"network": "tcp", "type": "HTTP", "sourceIP": "127.0.0.1", "sourcePort": "49152", "destinationIP": "203.0.113.10", "destinationPort": "443", "host": host, "dnsMode": "normal", "process": "curl", "processPath": "/usr/bin/curl"},
		}
	}
	tcp := connection("conn-1", "api.example.test", Taipei)
	tcp["chains"] = []string{Taipei, Automatic, Selector}
	udp := connection("conn-2", "static.example.test", Tokyo)
	udp["metadata"].(object)["network"] = "udp"
	udp["metadata"].(object)["type"] = "Socks5"
	udp["rule"], udp["rulePayload"] = "Match", ""
	return &Controller{
		config:      object{"mode": "rule", "allow-lan": false, "mixed-port": 7890, "port": 7890, "socks-port": 7891, "log-level": "info", "ipv6": false, "tun": object{"enable": false, "device": "utun-fixture", "stack": "mixed"}},
		proxies:     proxies,
		connections: map[string]object{"conn-1": tcp, "conn-2": udp},
		providers: map[string]map[string]object{
			"proxies": {ProxyProvider: {"name": ProxyProvider, "type": "Proxy", "vehicleType": "HTTP", "updatedAt": stamp, "proxies": []any{proxies[Taipei], proxies[Tokyo]}}},
			"rules":   {RuleProvider: {"name": RuleProvider, "type": "Rule", "vehicleType": "HTTP", "behavior": "domain", "ruleCount": 2, "updatedAt": stamp}},
		},
	}
}

// NewServer starts an isolated controller; callers must close the returned server.
func NewServer() *httptest.Server { return httptest.NewServer(NewHandler()) }

func (c *Controller) Requests() []Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]Request, len(c.requests))
	for i, request := range c.requests {
		result[i] = request
		result[i].Query = cloneQuery(request.Query)
		if request.Body != nil {
			result[i].Body = cloneObject(request.Body)
		}
	}
	return result
}

func (c *Controller) LastApplied() string { c.mu.Lock(); defer c.mu.Unlock(); return c.lastApplied }

func cloneQuery(values url.Values) url.Values {
	copy := make(url.Values, len(values))
	for key, value := range values {
		copy[key] = append([]string(nil), value...)
	}
	return copy
}

func cloneObject(value object) object {
	encoded, _ := json.Marshal(value)
	var copy object
	_ = json.Unmarshal(encoded, &copy)
	return copy
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func fail(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(object{"message": message})
}

func segments(r *http.Request) ([]string, error) {
	parts := strings.Split(strings.Trim(r.URL.EscapedPath(), "/"), "/")
	for i, part := range parts {
		decoded, err := url.PathUnescape(part)
		if err != nil {
			return nil, err
		}
		parts[i] = decoded
	}
	return parts, nil
}

func (c *Controller) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parts, err := segments(r)
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid path")
		return
	}
	var body object
	if r.Body != nil {
		data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
		if err != nil || len(data) > 1<<20 {
			fail(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if len(data) > 0 && (json.Unmarshal(data, &body) != nil || body == nil) {
			fail(w, http.StatusBadRequest, "expected JSON object")
			return
		}
	}
	c.mu.Lock()
	c.requests = append(c.requests, Request{Method: r.Method, Path: r.URL.Path, EscapedPath: r.URL.EscapedPath(), Query: cloneQuery(r.URL.Query()), Body: cloneObject(body)})
	if len(c.requests) > 512 {
		c.requests = append([]Request(nil), c.requests[len(c.requests)-512:]...)
	}
	c.mu.Unlock()
	if len(parts) == 1 && slices.Contains([]string{"logs", "traffic", "memory"}, parts[0]) && r.Method == http.MethodGet {
		c.stream(w, r, parts[0])
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch parts[0] {
	case "version":
		if r.Method == http.MethodGet && len(parts) == 1 {
			writeJSON(w, object{"version": "fixture-1.0.0", "meta": true})
			return
		}
	case "configs":
		if len(parts) == 1 {
			c.handleConfig(w, r, body)
			return
		}
	case "proxies":
		c.handleProxy(w, r, parts[1:], body)
		return
	case "connections":
		c.handleConnections(w, r, parts[1:])
		return
	case "rules":
		if r.Method == http.MethodGet && len(parts) == 1 {
			writeJSON(w, object{"rules": []any{object{"type": "DomainSuffix", "payload": "example.test", "proxy": Selector}, object{"type": "RuleSet", "payload": RuleProvider, "proxy": Selector}, object{"type": "GeoIP", "payload": "LAN", "proxy": "DIRECT"}, object{"type": "Match", "payload": "", "proxy": Selector}}})
			return
		}
	case "providers":
		c.handleProvider(w, r, parts[1:])
		return
	}
	fail(w, http.StatusNotFound, "fixture endpoint not found")
}

func (c *Controller) handleConfig(w http.ResponseWriter, r *http.Request, body object) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, c.config)
	case http.MethodPatch:
		if len(body) == 0 {
			fail(w, http.StatusBadRequest, "empty settings patch")
			return
		}
		if mode, present := body["mode"]; present {
			text, ok := mode.(string)
			if !ok || !slices.Contains([]string{"rule", "global", "direct"}, text) {
				fail(w, http.StatusBadRequest, "invalid mode")
				return
			}
		}
		merge(c.config, body)
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPut:
		file, _ := body["path"].(string)
		if !path.IsAbs(file) || file == "/" || r.URL.Query().Get("force") != "true" {
			fail(w, http.StatusBadRequest, "absolute path and force=true required")
			return
		}
		c.lastApplied = file
		w.WriteHeader(http.StatusNoContent)
	default:
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func merge(destination, patch object) {
	for key, value := range patch {
		if nested, ok := value.(map[string]any); ok {
			if existing, ok := destination[key].(map[string]any); ok {
				merge(existing, nested)
				continue
			}
		}
		destination[key] = value
	}
}

func (c *Controller) handleProxy(w http.ResponseWriter, r *http.Request, parts []string, body object) {
	if len(parts) == 0 && r.Method == http.MethodGet {
		writeJSON(w, object{"proxies": c.proxies})
		return
	}
	if len(parts) < 1 {
		fail(w, http.StatusNotFound, "proxy not found")
		return
	}
	proxy, ok := c.proxies[parts[0]]
	if !ok {
		fail(w, http.StatusNotFound, "proxy not found")
		return
	}
	if len(parts) == 2 && parts[1] == "delay" && r.Method == http.MethodGet {
		delay := 38
		if parts[0] == Tokyo {
			delay = 62
		}
		proxy["history"] = []any{object{"time": time.Now().UTC().Format(time.RFC3339), "delay": delay}}
		writeJSON(w, object{"delay": delay})
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, proxy)
			return
		case http.MethodPut:
			kind, _ := proxy["type"].(string)
			members, _ := proxy["all"].([]string)
			selected, _ := body["name"].(string)
			if !slices.Contains([]string{"Selector", "URLTest", "Fallback"}, kind) || !slices.Contains(members, selected) {
				fail(w, http.StatusBadRequest, "proxy is not selectable or member is missing")
				return
			}
			proxy["now"] = selected
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	fail(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (c *Controller) handleConnections(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodGet:
			ids := make([]string, 0, len(c.connections))
			for id := range c.connections {
				ids = append(ids, id)
			}
			slices.Sort(ids)
			items := make([]any, 0, len(ids))
			for _, id := range ids {
				items = append(items, c.connections[id])
			}
			writeJSON(w, object{"connections": items, "uploadTotal": 2048, "downloadTotal": 16384, "memory": 16777216})
			return
		case http.MethodDelete:
			clear(c.connections)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	if len(parts) == 1 && r.Method == http.MethodDelete {
		delete(c.connections, parts[0])
		w.WriteHeader(http.StatusNoContent)
		return
	}
	fail(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (c *Controller) handleProvider(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) < 1 {
		fail(w, http.StatusNotFound, "provider not found")
		return
	}
	providers, ok := c.providers[parts[0]]
	if !ok {
		fail(w, http.StatusNotFound, "provider kind not found")
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		writeJSON(w, object{"providers": providers})
		return
	}
	if len(parts) < 2 {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	provider, ok := providers[parts[1]]
	if !ok {
		fail(w, http.StatusNotFound, "provider not found")
		return
	}
	if len(parts) == 2 {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, provider)
			return
		case http.MethodPut:
			provider["updatedAt"] = time.Now().UTC().Format(time.RFC3339)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	if len(parts) == 3 && parts[0] == "proxies" && parts[2] == "healthcheck" && r.Method == http.MethodGet {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	fail(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (c *Controller) stream(w http.ResponseWriter, r *http.Request, resource string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		fail(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	logLevels := []string{"debug", "info", "warning", "error", "silent"}
	minimumLevel := 0
	if resource == "logs" {
		level := r.URL.Query().Get("level")
		if level == "" {
			level = "info"
		}
		minimumLevel = slices.Index(logLevels, level)
		if minimumLevel < 0 {
			fail(w, http.StatusBadRequest, "invalid log level")
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	encoder := json.NewEncoder(w)
	for index := 0; ; index++ {
		var event object
		switch resource {
		case "logs":
			level := []string{"info", "debug", "warning", "error"}[index%4]
			if slices.Index(logLevels, level) >= minimumLevel {
				event = object{"type": level, "payload": "[fixture] TCP api.example.test:443 via " + Taipei}
			}
		case "traffic":
			// Repeat a deterministic burst/idle profile so short PTY sessions
			// exercise slopes and measured zero without real outbound traffic.
			upload := [...]int{5120, 6144, 9216, 16384, 8192, 2048, 0, 0, 1024, 3072, 12288, 6144}
			download := [...]int{20480, 32768, 65536, 98304, 49152, 16384, 2048, 0, 4096, 12288, 49152, 24576}
			event = object{"up": upload[index%len(upload)], "down": download[index%len(download)]}
		case "memory":
			// Mihomo emits a zero initialization frame; subsequent values are
			// core RSS, deliberately independent of the host's physical RAM.
			memory := [...]int{16, 17, 19, 18, 17, 16, 18, 20, 19, 17, 18, 16}
			inuse := 0
			if index > 0 {
				inuse = memory[(index-1)%len(memory)] << 20
			}
			event = object{"inuse": inuse, "oslimit": 0}
		}
		if event != nil {
			if err := encoder.Encode(event); err != nil {
				return
			}
			flusher.Flush()
		}
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}
