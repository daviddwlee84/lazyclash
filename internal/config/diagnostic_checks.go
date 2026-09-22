package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// DiagnosticCheck is a reusable public HTTP(S) connectivity probe. An empty
// ExpectedStatuses means 200 through 399; validation never writes defaults.
type DiagnosticCheck struct {
	ID               string `toml:"id" json:"id"`
	Name             string `toml:"name,omitempty" json:"name,omitempty"`
	URL              string `toml:"url" json:"url"`
	Via              string `toml:"via,omitempty" json:"via,omitempty"`
	ExpectedStatuses []int  `toml:"expected_statuses,omitempty" json:"expected_statuses,omitempty"`
}

func ValidateDiagnosticChecks(checks []DiagnosticCheck) error {
	if len(checks) > 64 {
		return errors.New("a target may contain at most 64 diagnostic checks")
	}
	seen := map[string]bool{}
	for _, check := range checks {
		if len(check.ID) > 64 || !idPattern.MatchString(check.ID) {
			return errors.New("diagnostic check ID must be 1–64 letters, numbers, '.', '_' or '-', beginning with a letter or number")
		}
		if seen[check.ID] {
			return fmt.Errorf("duplicate diagnostic check ID %q", check.ID)
		}
		seen[check.ID] = true
		for _, text := range []string{check.Name, check.Via} {
			if len(text) > 256 || strings.IndexFunc(text, unicode.IsControl) >= 0 {
				return errors.New("diagnostic check name and via must be at most 256 bytes without control characters")
			}
		}
		if !validDiagnosticCheckURL(check.URL) {
			return errors.New("diagnostic check URL must be an HTTP(S) URL of at most 8192 bytes with an ASCII host, a valid port, and no credentials, query or fragment")
		}
		statuses := map[int]bool{}
		for _, status := range check.ExpectedStatuses {
			if status < 100 || status > 599 || statuses[status] {
				return errors.New("diagnostic check expected_statuses must contain unique HTTP status codes from 100 to 599")
			}
			statuses[status] = true
		}
	}
	return nil
}

func validDiagnosticCheckURL(value string) bool {
	if len(value) == 0 || len(value) > 8192 || strings.IndexFunc(value, unicode.IsControl) >= 0 || strings.Contains(value, "#") {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.IndexFunc(u.Path, unicode.IsControl) >= 0 {
		return false
	}
	host := u.Hostname()
	if host == "" || strings.HasSuffix(u.Host, ":") {
		return false
	}
	if strings.HasPrefix(u.Host, "[") && !strings.Contains(host, ":") {
		return false
	}
	for _, ch := range host {
		if ch > unicode.MaxASCII || unicode.IsControl(ch) {
			return false
		}
	}
	if ip := net.ParseIP(host); ip == nil {
		if strings.ContainsAny(u.Host, "[]") || len(host) > 253 {
			return false
		}
		for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') && !(ch >= '0' && ch <= '9') && ch != '-' {
					return false
				}
			}
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}
