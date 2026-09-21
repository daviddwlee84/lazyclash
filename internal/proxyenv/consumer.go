package proxyenv

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const OriginVariable = "LAZYCLASH_PROXY_ORIGIN"

var ErrNoProxyConfigured = errors.New("no local proxy target found; set --target ID or --endpoint URL")
var ErrTemporaryProxy = errors.New("a service cannot use a temporary SSH proxy endpoint; choose a stable proxy endpoint")

// ConsumerOptions keeps service validation read-only and injectable. Directory
// is the private proxy session registry; empty uses the normal XDG location.
type ConsumerOptions struct {
	Directory string
	Getenv    func(string) string
}

type temporaryOrigin struct {
	Version int    `json:"version"`
	Kind    string `json:"kind"`
	HTTP    string `json:"http_proxy"`
	All     string `json:"all_proxy"`
}

// TemporaryOrigin binds lifetime metadata to endpoints, never credentials or
// controller secrets. It is evidence for consumer safety, not an authorization
// token. Remote shells cannot consult the source machine's local registry.
func TemporaryOrigin(p Plan, kind string) (string, error) {
	if kind != "ssh-forward" && kind != "ssh-reverse" {
		return "", errors.New("invalid proxy origin kind")
	}
	if err := p.Validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(temporaryOrigin{1, kind, p.HTTP, p.All})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func parseOrigin(raw string) (temporaryOrigin, error) {
	var origin temporaryOrigin
	if len(raw) > 16384 {
		return origin, errors.New("invalid proxy origin metadata")
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || json.Unmarshal(data, &origin) != nil || origin.Version != 1 || (origin.Kind != "ssh-forward" && origin.Kind != "ssh-reverse") {
		return origin, errors.New("invalid proxy origin metadata")
	}
	if err := (Plan{HTTP: origin.HTTP, All: origin.All}).Validate(); err != nil {
		return origin, errors.New("invalid proxy origin metadata")
	}
	return origin, nil
}

// Listener identity intentionally ignores scheme: a mixed listener can be
// copied as HTTP or SOCKS. IPv6 remains distinct from an IPv4-only listener.
func endpointListener(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" {
		host = "127.0.0.1"
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		}
	}
	if numeric, err := strconv.Atoi(port); err == nil {
		port = strconv.Itoa(numeric)
	}
	return net.JoinHostPort(host, port)
}

func sameListener(a, b Plan) bool {
	for _, first := range []string{a.HTTP, a.All} {
		key := endpointListener(first)
		if key == "" {
			continue
		}
		for _, second := range []string{b.HTTP, b.All} {
			if key == endpointListener(second) {
				return true
			}
		}
	}
	return false
}

func matchingOrigin(p Plan, raw string) (bool, error) {
	if raw == "" {
		return false, nil
	}
	origin, err := parseOrigin(raw)
	if err != nil {
		return false, err
	}
	return sameListener(p, Plan{HTTP: origin.HTTP, All: origin.All}), nil
}

func environmentOrigin(p Plan) (string, error) {
	if p.Origin != "" {
		matches, err := matchingOrigin(p, p.Origin)
		if err != nil || !matches {
			return "", errors.New("proxy origin does not match the selected endpoint")
		}
		return p.Origin, nil
	}
	raw := os.Getenv(OriginVariable)
	if matches, err := matchingOrigin(p, raw); err == nil && matches {
		return raw, nil
	}
	return "", nil
}

// ValidateConsumer refuses known short-lived endpoints for persistent services.
// It neither probes endpoints nor starts, stops or refreshes any SSH session.
func ValidateConsumer(p Plan, consumer string, opts ConsumerOptions) error {
	if consumer == "" || consumer == "process" {
		return nil
	}
	if consumer != "service" {
		return errors.New("consumer must be process or service")
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if p.SSHHost != "" {
		return ErrTemporaryProxy
	}
	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	for _, raw := range []string{p.Origin, getenv(OriginVariable)} {
		matches, err := matchingOrigin(p, raw)
		if err != nil {
			return err
		}
		if matches {
			return ErrTemporaryProxy
		}
	}
	dir, err := sessionDir(SessionOptions{Directory: opts.Directory}, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("cannot inspect private proxy sessions for service use")
	}
	registry, err := os.Open(dir)
	if err != nil {
		return errors.New("cannot inspect private proxy sessions for service use")
	}
	defer registry.Close()
	entries, err := registry.ReadDir(4097)
	if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > 4096 {
		return errors.New("cannot inspect private proxy sessions for service use")
	}
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if entry.Name() == id || !sessionID.MatchString(id) {
			continue
		}
		s, err := readSession(dir, id)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return errors.New("cannot inspect private proxy session record for service use")
		}
		if s.State == "ready" && s.Plan.SSHHost != "" && sameListener(p, s.Local) {
			return ErrTemporaryProxy
		}
	}
	return nil
}
