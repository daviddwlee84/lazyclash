package core

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

// DNSQuery uses the core's resolver. It may perform DNS I/O and fill its cache,
// so observe-only callers must not invoke it.
func (c *Client) DNSQuery(ctx context.Context, host, kind string) (Object, error) {
	if host == "" || strings.IndexFunc(host, unicode.IsControl) >= 0 || (kind != "A" && kind != "AAAA") {
		return nil, &Error{Kind: KindInvalid, Operation: "query core DNS"}
	}
	return c.object(ctx, http.MethodGet, []string{"dns", "query"}, url.Values{"name": {host}, "type": {kind}}, nil, true, "query core DNS")
}

// URLDelay probes one named outbound without changing any selector or mode.
// Like the native core URLTest API it can update outbound health/history.
func (c *Client) URLDelay(ctx context.Context, name, endpoint string, timeout time.Duration) (Object, error) {
	u, err := url.Parse(endpoint)
	if err != nil || name == "" || u.User != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Fragment != "" || strings.IndexFunc(endpoint, unicode.IsControl) >= 0 || timeout <= 0 || timeout > 30*time.Second {
		return nil, &Error{Kind: KindInvalid, Operation: "test outbound URL response"}
	}
	query := url.Values{"url": {endpoint}, "timeout": {fmt.Sprint(timeout.Milliseconds())}}
	return c.object(ctx, http.MethodGet, []string{"proxies", name, "delay"}, query, nil, true, "test outbound URL response")
}
