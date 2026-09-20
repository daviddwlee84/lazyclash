// Package core speaks the external controller API shared by Mihomo and Clash.
// Runtime settings returned by Config are not the complete source YAML.
package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

const (
	maxResponseBytes   = 8 << 20
	maxStreamLineBytes = 1 << 20
)

// ErrorKind lets both terminal and machine clients distinguish actionable errors.
type ErrorKind string

const (
	KindAuth         ErrorKind = "auth"
	KindTLS          ErrorKind = "tls"
	KindUnreachable  ErrorKind = "unreachable"
	KindUnsupported  ErrorKind = "unsupported"
	KindInvalid      ErrorKind = "invalid"
	KindRejected     ErrorKind = "rejected"
	KindUnknownWrite ErrorKind = "unknown-write-result"
	KindReadOnly     ErrorKind = "read-only"
	KindCanceled     ErrorKind = "canceled"
)

// Error deliberately excludes controller response bodies and raw transport errors:
// either may contain credentials or untrusted terminal escape sequences.
type Error struct {
	Kind       ErrorKind
	Operation  string
	StatusCode int
	cause      error
}

func (e *Error) Error() string {
	message := map[ErrorKind]string{
		KindAuth:         "controller authentication failed",
		KindTLS:          "controller TLS verification failed; check the hostname and CA certificate",
		KindUnreachable:  "controller is unavailable or the request timed out",
		KindUnsupported:  "controller does not support this endpoint or the resource no longer exists",
		KindInvalid:      "invalid controller request or response",
		KindRejected:     "controller rejected the operation or read-back did not match",
		KindUnknownWrite: "operation result is unknown; refresh before retrying",
		KindReadOnly:     "operation is disabled in read-only mode",
		KindCanceled:     "request canceled",
	}[e.Kind]
	if message == "" {
		message = "controller request failed"
	}
	if e.StatusCode != 0 {
		message += fmt.Sprintf(" (HTTP %d)", e.StatusCode)
	}
	if e.Operation != "" {
		return e.Operation + ": " + message
	}
	return message
}

func (e *Error) Unwrap() error { return e.cause }

// Client is safe for concurrent use. Every operation is bound to its caller's
// context; it never retries a write or follows redirects with a bearer token.
type Client struct {
	base         *url.URL
	http         *http.Client
	transport    *http.Transport
	secret       string
	readOnly     bool
	timeout      time.Duration
	delayURL     string
	delayTimeout time.Duration
}

func New(options Options) (*Client, error) {
	endpoint := options.Endpoint
	if endpoint == "" {
		endpoint = "http://127.0.0.1:9090"
	}
	base, err := url.Parse(endpoint)
	if err != nil || base.User != nil || base.RawQuery != "" || base.Fragment != "" || strings.ContainsAny(options.Secret, "\r\n") {
		return nil, &Error{Kind: KindInvalid, Operation: "connect"}
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dial := options.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext
	}
	if base.Scheme == "unix" {
		if base.Host != "" || !path.IsAbs(base.Path) || base.Path == "/" || options.DialContext != nil {
			return nil, &Error{Kind: KindInvalid, Operation: "connect to Unix socket"}
		}
		socket := base.Path
		dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", socket)
		}
		base = &url.URL{Scheme: "http", Host: "localhost"}
	} else if (base.Scheme != "http" && base.Scheme != "https") || base.Hostname() == "" {
		return nil, &Error{Kind: KindInvalid, Operation: "connect"}
	}
	if base.RawPath != "" || strings.Contains(base.Path, "..") {
		return nil, &Error{Kind: KindInvalid, Operation: "connect"}
	}
	base.Path = strings.TrimRight(base.Path, "/")
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if options.CAFile != "" {
		cert, err := os.ReadFile(options.CAFile)
		if err != nil {
			return nil, &Error{Kind: KindTLS, Operation: "read controller CA"}
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(cert) {
			return nil, &Error{Kind: KindTLS, Operation: "read controller CA"}
		}
		tlsConfig.RootCAs = roots
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dial,
		TLSClientConfig:        tlsConfig,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		IdleConnTimeout:        90 * time.Second,
		MaxIdleConns:           16,
		MaxIdleConnsPerHost:    8,
		MaxResponseHeaderBytes: 1 << 20,
		ForceAttemptHTTP2:      true,
	}
	delayURL := options.DelayURL
	if delayURL == "" {
		delayURL = "https://www.gstatic.com/generate_204"
	}
	delayURLParsed, err := url.Parse(delayURL)
	if err != nil || (delayURLParsed.Scheme != "http" && delayURLParsed.Scheme != "https") || delayURLParsed.Hostname() == "" || delayURLParsed.User != nil {
		return nil, &Error{Kind: KindInvalid, Operation: "configure latency test URL"}
	}
	delayTimeout := options.DelayTimeout
	if delayTimeout <= 0 {
		delayTimeout = 5 * time.Second
	}
	return &Client{
		base: base, secret: options.Secret, readOnly: options.ReadOnly,
		timeout: timeout, delayURL: delayURL, delayTimeout: delayTimeout,
		transport: transport,
		http:      &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

func (c *Client) IsReadOnly() bool { return c.readOnly }
func (c *Client) Close() error     { c.transport.CloseIdleConnections(); return nil }

// Selectable matches the Mihomo adapters implementing outboundgroup.SelectAble.
func (p Proxy) Selectable() bool {
	return len(p.All) > 0 && slices.Contains([]string{"selector", "urltest", "fallback"}, strings.ToLower(p.Type))
}

func (c *Client) endpoint(segments []string, query url.Values) string {
	u := *c.base
	escaped := c.base.EscapedPath()
	for _, segment := range segments {
		part := url.PathEscape(segment)
		// Dot-only names must not become path traversal components in proxies.
		if segment == "." || segment == ".." {
			part = strings.ReplaceAll(segment, ".", "%2E")
		}
		escaped += "/" + part
	}
	u.Path, _ = url.PathUnescape(escaped)
	u.RawPath = escaped
	u.RawQuery = query.Encode()
	return u.String()
}

func (c *Client) checkWrite(op string) error {
	if c.readOnly {
		return &Error{Kind: KindReadOnly, Operation: op}
	}
	return nil
}

func (c *Client) request(ctx context.Context, method string, segments []string, query url.Values, body any, write, stream bool, op string) (*http.Response, context.CancelFunc, error) {
	if write {
		if err := c.checkWrite(op); err != nil {
			return nil, nil, err
		}
	}
	var cancel context.CancelFunc
	if stream {
		ctx, cancel = context.WithCancel(ctx)
	} else {
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
	}
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			cancel()
			return nil, nil, &Error{Kind: KindInvalid, Operation: op}
		}
		payload = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(segments, query), payload)
	if err != nil {
		cancel()
		return nil, nil, &Error{Kind: KindInvalid, Operation: op}
	}
	if write {
		// A non-replayable body prevents net/http from retrying even a GET-based
		// side effect (latency test or provider health check) on a stale socket.
		if req.Body == nil {
			req.Body = io.NopCloser(strings.NewReader(""))
		}
		req.GetBody = nil
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
	var sent atomic.Bool
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{WroteHeaders: func() { sent.Store(true) }}))
	resp, err := c.http.Do(req)
	if err != nil {
		requestErr := transportError(err, ctx.Err(), write && sent.Load(), op)
		cancel()
		return nil, nil, requestErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		cancel()
		kind := KindRejected
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			kind = KindAuth
		case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented:
			kind = KindUnsupported
		case http.StatusBadRequest, http.StatusUnprocessableEntity:
			kind = KindInvalid
		}
		return nil, nil, &Error{Kind: kind, Operation: op, StatusCode: resp.StatusCode}
	}
	return resp, cancel, nil
}

func transportError(err, ctxErr error, uncertain bool, op string) error {
	kind := KindUnreachable
	var certErr *tls.CertificateVerificationError
	var unknownCA x509.UnknownAuthorityError
	var hostError x509.HostnameError
	var recordError tls.RecordHeaderError
	switch {
	case uncertain:
		kind = KindUnknownWrite
	case errors.As(err, &certErr), errors.As(err, &unknownCA), errors.As(err, &hostError), errors.As(err, &recordError):
		kind = KindTLS
	case errors.Is(ctxErr, context.Canceled):
		kind = KindCanceled
	}
	return &Error{Kind: kind, Operation: op, cause: ctxErr}
}

func (c *Client) object(ctx context.Context, method string, segments []string, query url.Values, body any, write bool, op string) (Object, error) {
	resp, cancel, err := c.request(ctx, method, segments, query, body, write, false, op)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, transportError(err, ctx.Err(), write, op)
	}
	if len(data) > maxResponseBytes {
		return nil, &Error{Kind: KindInvalid, Operation: op}
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return Object{}, nil
	}
	var result Object
	if err := json.Unmarshal(data, &result); err != nil || result == nil {
		return nil, &Error{Kind: KindInvalid, Operation: op}
	}
	return result, nil
}

func (c *Client) Version(ctx context.Context) (Object, error) {
	return c.object(ctx, http.MethodGet, []string{"version"}, nil, nil, false, "read version")
}

func (c *Client) Config(ctx context.Context) (Object, error) {
	return c.object(ctx, http.MethodGet, []string{"configs"}, nil, nil, false, "read runtime settings")
}

func (c *Client) Proxies(ctx context.Context) (map[string]Proxy, error) {
	obj, err := c.object(ctx, http.MethodGet, []string{"proxies"}, nil, nil, false, "read proxies")
	if err != nil {
		return nil, err
	}
	raw, ok := obj["proxies"]
	if !ok {
		return nil, &Error{Kind: KindInvalid, Operation: "read proxies"}
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, &Error{Kind: KindInvalid, Operation: "read proxies"}
	}
	var proxies map[string]Proxy
	if err := json.Unmarshal(encoded, &proxies); err != nil || proxies == nil {
		return nil, &Error{Kind: KindInvalid, Operation: "read proxies"}
	}
	for name, proxy := range proxies {
		if proxy.Name == "" {
			proxy.Name = name
			proxies[name] = proxy
		}
	}
	return proxies, nil
}

func (c *Client) Connections(ctx context.Context) (Object, error) {
	return c.object(ctx, http.MethodGet, []string{"connections"}, nil, nil, false, "read connections")
}
func (c *Client) Rules(ctx context.Context) (Object, error) {
	return c.object(ctx, http.MethodGet, []string{"rules"}, nil, nil, false, "read rules")
}
func providerKind(kind string) bool { return kind == "proxies" || kind == "rules" }
func (c *Client) Providers(ctx context.Context, kind string) (Object, error) {
	if !providerKind(kind) {
		return nil, &Error{Kind: KindInvalid, Operation: "read providers"}
	}
	return c.object(ctx, http.MethodGet, []string{"providers", kind}, nil, nil, false, "read providers")
}

func (c *Client) Select(ctx context.Context, group, member string) error {
	const op = "select proxy"
	if err := c.checkWrite(op); err != nil {
		return err
	}
	proxies, err := c.Proxies(ctx)
	if err != nil {
		return err
	}
	proxy, ok := proxies[group]
	if !ok || !proxy.Selectable() || !slices.Contains(proxy.All, member) {
		return &Error{Kind: KindInvalid, Operation: op}
	}
	if _, err := c.object(ctx, http.MethodPut, []string{"proxies", group}, nil, Object{"name": member}, true, op); err != nil {
		return err
	}
	proxies, err = c.Proxies(ctx)
	if err != nil {
		return &Error{Kind: KindUnknownWrite, Operation: op}
	}
	if updated, ok := proxies[group]; !ok || updated.Now != member {
		return &Error{Kind: KindRejected, Operation: op}
	}
	return nil
}

func (c *Client) Delay(ctx context.Context, name string) (Object, error) {
	if name == "" {
		return nil, &Error{Kind: KindInvalid, Operation: "test proxy latency"}
	}
	query := url.Values{"url": {c.delayURL}, "timeout": {fmt.Sprint(c.delayTimeout.Milliseconds())}}
	return c.object(ctx, http.MethodGet, []string{"proxies", name, "delay"}, query, nil, true, "test proxy latency")
}

func (c *Client) SetConfig(ctx context.Context, patch Object) (Object, error) {
	const op = "change runtime settings"
	if len(patch) == 0 {
		return nil, &Error{Kind: KindInvalid, Operation: op}
	}
	if _, err := c.object(ctx, http.MethodPatch, []string{"configs"}, nil, patch, true, op); err != nil {
		return nil, err
	}
	actual, err := c.Config(ctx)
	if err != nil {
		return nil, &Error{Kind: KindUnknownWrite, Operation: op}
	}
	// Compare decoded JSON so nested Object values and integers match the
	// ordinary map/float64 representation returned by the controller.
	encoded, err := json.Marshal(patch)
	if err != nil {
		return nil, &Error{Kind: KindInvalid, Operation: op}
	}
	var expected Object
	if json.Unmarshal(encoded, &expected) != nil || !containsSettings(actual, expected) {
		return actual, &Error{Kind: KindRejected, Operation: op}
	}
	return actual, nil
}

func containsSettings(actual, expected map[string]any) bool {
	for key, value := range expected {
		found, ok := actual[key]
		if !ok {
			return false
		}
		if nested, ok := value.(map[string]any); ok {
			actualNested, ok := found.(map[string]any)
			if !ok || !containsSettings(actualNested, nested) {
				return false
			}
		} else if !reflect.DeepEqual(found, value) {
			return false
		}
	}
	return true
}

func (c *Client) CloseConnections(ctx context.Context, id string) error {
	segments := []string{"connections"}
	if id != "" {
		segments = append(segments, id)
	}
	_, err := c.object(ctx, http.MethodDelete, segments, nil, nil, true, "close connections")
	return err
}

func (c *Client) UpdateProvider(ctx context.Context, kind, name string) error {
	if !providerKind(kind) || name == "" {
		return &Error{Kind: KindInvalid, Operation: "update provider"}
	}
	_, err := c.object(ctx, http.MethodPut, []string{"providers", kind, name}, nil, nil, true, "update provider")
	return err
}

func (c *Client) HealthcheckProvider(ctx context.Context, name string) error {
	if name == "" {
		return &Error{Kind: KindInvalid, Operation: "health check provider"}
	}
	_, err := c.object(ctx, http.MethodGet, []string{"providers", "proxies", name, "healthcheck"}, nil, nil, true, "health check provider")
	return err
}

func (c *Client) ApplyConfig(ctx context.Context, configPath string) (Object, error) {
	const op = "apply YAML configuration"
	if !path.IsAbs(configPath) || configPath == "/" || strings.ContainsAny(configPath, "\x00\r\n") {
		return nil, &Error{Kind: KindInvalid, Operation: op}
	}
	if _, err := c.object(ctx, http.MethodPut, []string{"configs"}, url.Values{"force": {"true"}}, Object{"path": configPath}, true, op); err != nil {
		return nil, err
	}
	result, err := c.Config(ctx)
	if err != nil {
		return nil, &Error{Kind: KindUnknownWrite, Operation: op}
	}
	return result, nil
}

// Stream consumes newline-delimited objects until cancellation or disconnect.
// The caller controls reconnection; this method never silently restarts a stream.
func (c *Client) Stream(ctx context.Context, resource string, query url.Values, consume func(Object)) error {
	const op = "stream controller events"
	if !slices.Contains([]string{"logs", "traffic", "memory"}, resource) || consume == nil {
		return &Error{Kind: KindInvalid, Operation: op}
	}
	resp, cancel, err := c.request(ctx, http.MethodGet, []string{resource}, query, nil, false, true, op)
	if err != nil {
		return err
	}
	defer cancel()
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 16<<10), maxStreamLineBytes)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var object Object
		if err := json.Unmarshal(scanner.Bytes(), &object); err != nil || object == nil {
			return &Error{Kind: KindInvalid, Operation: op}
		}
		consume(object)
	}
	if ctx.Err() != nil {
		return &Error{Kind: KindCanceled, Operation: op, cause: ctx.Err()}
	}
	if scanner.Err() != nil {
		return &Error{Kind: KindUnreachable, Operation: op}
	}
	// EOF is a disconnect, not a successful long-lived subscription.
	return &Error{Kind: KindUnreachable, Operation: op}
}
