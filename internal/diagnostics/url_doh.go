package diagnostics

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

func referenceDNS(ctx context.Context, target config.Target, host string, opts URLOptions) []DNSResult {
	results := []DNSResult{}
	if net.ParseIP(host) != nil {
		return []DNSResult{{Source: "reference DoH via explicit proxy", Addresses: []string{}, Error: "literal IP does not need DNS"}}
	}
	p, err := newProbe(ctx, target, opts.Options)
	if err != nil {
		return []DNSResult{{Source: "reference DoH via explicit proxy", Addresses: []string{}, Error: "explicit proxy unavailable; reference DNS was not sent directly"}}
	}
	defer p.Close()
	for _, kind := range []string{"A", "AAAA"} {
		r := DNSResult{Source: "reference DoH via explicit proxy", Type: kind, Addresses: []string{}}
		u, _ := url.Parse(opts.ReferenceDoH)
		q := u.Query()
		q.Set("name", host)
		q.Set("type", kind)
		u.RawQuery = q.Encode()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		request.Header.Set("Accept", "application/dns-json")
		response, err := probeClient(p, 5*time.Second).Do(request)
		if err != nil {
			r.Error = "reference DoH request failed"
			results = append(results, r)
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
		response.Body.Close()
		var message struct {
			Status int `json:"Status"`
			Answer []struct {
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if readErr != nil || response.StatusCode != http.StatusOK || len(data) > 64*1024 || json.Unmarshal(data, &message) != nil || message.Status != 0 {
			r.Error = "reference DoH JSON response unavailable"
		} else {
			for _, answer := range message.Answer {
				if net.ParseIP(answer.Data) != nil {
					r.Addresses = append(r.Addresses, answer.Data)
				}
			}
		}
		results = append(results, r)
	}
	return results
}
