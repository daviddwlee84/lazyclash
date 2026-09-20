package diagnostics

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

type probeTransport struct {
	transport *http.Transport
	tunnel    io.Closer
}

// OpenProxyClient opens an explicit authenticated data route for an authorized
// download. The caller bounds request sizes and closes the returned transport.
// SSH forwarding preserves the original HTTPS proxy hostname for TLS checking.
func OpenProxyClient(ctx context.Context, target config.Target, timeout time.Duration) (*http.Client, io.Closer, error) {
	transport, err := newProbe(ctx, target, Options{})
	if err != nil {
		return nil, nil, err
	}
	return probeClient(transport, timeout), transport, nil
}

func (p *probeTransport) Close() error {
	p.transport.CloseIdleConnections()
	if p.tunnel != nil {
		return p.tunnel.Close()
	}
	return nil
}

func newProbe(ctx context.Context, t config.Target, opts Options) (*probeTransport, error) {
	if opts.ReadOnly {
		return nil, ErrReadOnly
	}
	if t.ProbeProxy == "" {
		return nil, ErrNoProxy
	}
	if err := config.ValidateProbe(t); err != nil {
		return nil, err
	}
	// The data route can be tested while the controller is unreachable. Validate
	// its independent SSH alias without opening or relying on the controller.
	if err := config.ValidateTarget(config.Target{Controller: "http://127.0.0.1:9090", SSHHost: t.SSHHost}); err != nil {
		return nil, err
	}
	u, _ := url.Parse(t.ProbeProxy)
	password, err := proxyPassword(t)
	if err != nil {
		return nil, err
	}
	if t.ProbeUsername != "" || t.ProbePasswordEnv != "" || t.ProbePasswordFile != "" {
		u.User = url.UserPassword(t.ProbeUsername, password)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if t.ProbeCAFile != "" {
		data, err := limitedFile(t.ProbeCAFile, 1024*1024)
		if err != nil {
			return nil, errors.New("cannot read configured proxy CA file")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("proxy CA file contains no valid certificates")
		}
		tlsConfig.RootCAs = roots
	}
	dialAddress := u.Host
	p := &probeTransport{}
	if t.SSHHost != "" {
		open := opts.OpenTunnel
		if open == nil {
			open = connection.OpenProxyTunnel
		}
		dialAddress, p.tunnel, err = open(ctx, t.SSHHost, t.ProbeProxy)
		if err != nil {
			return nil, err
		}
	}
	// Proxy is always explicit. Never inherit HTTP_PROXY/ALL_PROXY or fall back
	// to direct dialing; the guard also prevents a future transport change from
	// accidentally sending destinations to the controller or local network.
	p.transport = &http.Transport{
		Proxy: http.ProxyURL(u),
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != u.Host {
				return nil, errors.New("unexpected address outside the configured data proxy")
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", dialAddress)
		},
		TLSClientConfig:        tlsConfig,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  8 * time.Second,
		MaxResponseHeaderBytes: 64 * 1024,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      false,
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	return p, nil
}

func proxyPassword(t config.Target) (string, error) {
	var password string
	if t.ProbePasswordEnv != "" {
		var ok bool
		password, ok = os.LookupEnv(t.ProbePasswordEnv)
		if !ok {
			return "", errors.New("configured proxy password environment variable is not set")
		}
	} else if t.ProbePasswordFile != "" {
		data, err := limitedFile(t.ProbePasswordFile, 64*1024)
		if err != nil {
			return "", errors.New("cannot read configured proxy password file")
		}
		password = strings.TrimRight(string(data), "\r\n")
	}
	if len(password) > 64*1024 || strings.IndexFunc(password, unicode.IsControl) >= 0 {
		return "", errors.New("proxy password exceeds its limit or contains control characters")
	}
	return password, nil
}

func limitedFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("expected a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errors.New("file exceeds size limit")
	}
	return data, nil
}

func probeClient(p *probeTransport, timeout time.Duration) *http.Client {
	return &http.Client{Transport: p.transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func safeRequestError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return errors.New("proxy request timed out")
	}
	return errors.New("proxy request failed; check proxy connectivity, authentication and TLS certificates")
}

func destination(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.IndexFunc(endpoint, unicode.IsControl) >= 0 {
		return errors.New("invalid diagnostic destination")
	}
	return nil
}

// IP samples IP.SB through the explicit data proxy. Its address describes this
// request's egress; rule-based routing may choose another route for other sites.
func IP(ctx context.Context, target config.Target, opts Options) (IPResult, error) {
	result := IPResult{TargetID: target.ID, Source: "IP.SB egress", Country: "unknown", City: "unknown", Organization: "unknown", ASN: "unknown"}
	p, err := newProbe(ctx, target, opts)
	if err != nil {
		return result, err
	}
	defer p.Close()
	result.Route = route(target, target.ProbeProxy)
	result.SampledAt = opts.now()
	endpoint := opts.IPURL
	if endpoint == "" {
		endpoint = "https://api.ip.sb/geoip"
	}
	if err := destination(endpoint); err != nil {
		return result, err
	}
	timeout := opts.IPTimeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return result, errors.New("cannot create IP probe request")
	}
	req.Header.Set("User-Agent", "lazyclash")
	req.Header.Set("Accept", "application/json")
	resp, err := probeClient(p, timeout).Do(req)
	if err != nil {
		return result, safeRequestError(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, fmt.Errorf("IP probe returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil {
		return result, safeRequestError(ctx, err)
	}
	if len(data) > 64*1024 {
		return result, errors.New("IP response exceeds 64 KiB")
	}
	var geo map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&geo); err != nil {
		return result, errors.New("IP response is not a valid JSON object")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return result, errors.New("IP response contains trailing data")
	}
	ip, _ := geo["ip"].(string)
	if net.ParseIP(ip) == nil {
		return result, errors.New("IP response does not contain a valid IP address")
	}
	result.IP = ip
	result.Country = geoText(geo["country"])
	result.City = geoText(geo["city"])
	result.Organization = geoText(geo["organization"])
	if result.Organization == "unknown" {
		result.Organization = geoText(geo["asn_organization"])
	}
	result.ASN = geoText(geo["asn"])
	return result, nil
}

func geoText(value any) string {
	var text string
	switch v := value.(type) {
	case string:
		text = v
	case json.Number:
		text = string(v)
	}
	text = strings.Join(strings.Fields(core.Sanitize(text)), " ")
	if text == "" {
		return "unknown"
	}
	runes := []rune(text)
	if len(runes) > 256 {
		text = string(runes[:256])
	}
	return text
}

// Latency measures fresh proxied HTTP requests from request start until response
// headers, excluding SSH setup. A failed site retains its own timing and status.
func Latency(ctx context.Context, target config.Target, opts Options) (LatencyResult, error) {
	result := LatencyResult{TargetID: target.ID}
	p, err := newProbe(ctx, target, opts)
	if err != nil {
		return result, err
	}
	defer p.Close()
	result.Route, result.SampledAt = route(target, target.ProbeProxy), opts.now()
	sites := opts.Sites
	if sites == nil {
		sites = []Site{{"Google", "https://www.google.com/generate_204"}, {"Cloudflare", "https://cp.cloudflare.com/generate_204"}, {"GitHub", "https://github.com"}}
	}
	for _, site := range sites {
		if err := destination(site.URL); err != nil {
			return result, err
		}
	}
	timeout := opts.LatencyTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client := probeClient(p, timeout)
	result.Sites = make([]SiteResult, len(sites))
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	for i, site := range sites {
		wg.Add(1)
		go func(i int, site Site) {
			defer wg.Done()
			sr := SiteResult{Name: geoText(site.Name), URL: site.URL}
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				sr.Error = ctx.Err().Error()
				result.Sites[i] = sr
				return
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, site.URL, nil)
			if err != nil {
				sr.Error = "cannot create latency request"
				result.Sites[i] = sr
				return
			}
			req.Header.Set("User-Agent", "lazyclash")
			started := time.Now()
			resp, err := client.Do(req)
			sr.Milliseconds = float64(time.Since(started)) / float64(time.Millisecond)
			if err != nil {
				sr.Error = safeRequestError(ctx, err).Error()
			} else {
				sr.StatusCode = resp.StatusCode
				_ = resp.Body.Close()
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					sr.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
				}
			}
			result.Sites[i] = sr
		}(i, site)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	for _, site := range result.Sites {
		if site.Error != "" {
			return result, ErrPartial
		}
	}
	return result, nil
}
