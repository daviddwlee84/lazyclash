package proxyenv

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const DefaultTestURL = "https://www.gstatic.com/generate_204"

func Test(ctx context.Context, p Plan, destination string) (TestResult, error) {
	if destination == "" {
		destination = DefaultTestURL
	}
	u, err := url.Parse(destination)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return TestResult{}, errors.New("test URL must be HTTP(S) without credentials or fragment")
	}
	values, err := Values(p)
	if err != nil {
		return TestResult{}, err
	}
	proxy, _ := url.Parse(values["https_proxy"])
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if p.CAFile != "" {
		data, e := os.ReadFile(p.CAFile)
		if e != nil || len(data) > 1<<20 {
			return TestResult{}, errors.New("cannot read proxy CA file")
		}
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(data) {
			return TestResult{}, errors.New("invalid proxy CA certificate")
		}
		tlsConfig.RootCAs = roots
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 8 * time.Second, MaxResponseHeaderBytes: 65536, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, destination, nil)
	if err != nil {
		return TestResult{}, errors.New("invalid test URL")
	}
	started := time.Now()
	response, err := client.Do(req)
	public := *u
	public.RawQuery = ""
	public.ForceQuery = false
	result := TestResult{Endpoint: p.HTTP, URL: public.String(), Scope: "local process through explicit proxy", Milliseconds: time.Since(started).Milliseconds()}
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, errors.New("proxy request failed; check endpoint, authentication and TLS certificates")
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	if response.StatusCode == http.StatusProxyAuthRequired {
		return result, errors.New("proxy authentication rejected")
	}
	return result, nil
}

func safeEndpoint(value string) string {
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" {
		return "<set; unrecognized>"
	}
	u.User = nil
	u.Path = ""
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	u.ForceQuery = false
	return u.String()
}
func EnvironmentStatus() map[string]any {
	vars := map[string]string{}
	for _, key := range Variables {
		if value := os.Getenv(key); value != "" {
			vars[key] = safeEndpoint(value)
		}
	}
	return map[string]any{"variables": vars, "no_proxy_set": os.Getenv("no_proxy") != "" || os.Getenv("NO_PROXY") != "", "interpretation": "Process environment only; applications may ignore proxy variables or apply NO_PROXY differently."}
}
func SystemProxy(ctx context.Context) map[string]string {
	result := map[string]string{}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.CommandContext(ctx, "scutil", "--proxy")
	} else if runtime.GOOS == "linux" {
		cmd = exec.CommandContext(ctx, "gsettings", "get", "org.gnome.system.proxy", "mode")
	} else {
		return result
	}
	var out cappedBuffer
	out.limit = 16384
	cmd.Stdout = &out
	if cmd.Run() != nil {
		return result
	}
	if runtime.GOOS == "linux" {
		result["gnome_mode"] = strings.TrimSpace(out.String())
		return result
	}
	allowed := map[string]bool{"HTTPEnable": true, "HTTPProxy": true, "HTTPPort": true, "HTTPSEnable": true, "HTTPSProxy": true, "HTTPSPort": true, "SOCKSEnable": true, "SOCKSProxy": true, "SOCKSPort": true, "ProxyAutoConfigEnable": true}
	for _, line := range strings.Split(out.String(), "\n") {
		key, value, ok := strings.Cut(line, ":")
		key = strings.TrimSpace(key)
		if ok && allowed[key] {
			value = strings.TrimSpace(value)
			if len(value) <= 256 && !strings.ContainsAny(value, "\x00\r\n") {
				result[key] = value
			}
		}
	}
	return result
}
