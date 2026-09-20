package networkcheck

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/daviddwlee84/lazyclash/internal/connection"
)

// SystemProxyScript is fixed, caller-owned host code. A privileged executor may
// exec it with __name__='lazyclash_system_proxy' and call apply_plan(plan,restore).
// The plan contains typed states, never arbitrary commands.
//
//go:embed system_proxy.py
var SystemProxyScript string

type ProxyListener struct {
	Enabled       bool   `json:"enabled"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Authenticated bool   `json:"authenticated"`
}
type SystemProxyState struct {
	Service    string        `json:"service"`
	HTTP       ProxyListener `json:"http"`
	HTTPS      ProxyListener `json:"https"`
	SOCKS      ProxyListener `json:"socks"`
	PACEnabled bool          `json:"pac_enabled"`
	PACURL     string        `json:"pac_url"`
	Discovery  bool          `json:"discovery"`
	Exceptions []string      `json:"exceptions"`
	Mode       string        `json:"mode,omitempty"`
}
type SystemProxySnapshot struct {
	Protocol          int                `json:"protocol"`
	OS                string             `json:"os"`
	Backend           string             `json:"backend"`
	SelectionExplicit bool               `json:"selection_explicit"`
	Services          []SystemProxyState `json:"services"`
	Unavailable       string             `json:"unavailable,omitempty"`
}
type SystemProxyChange struct {
	Service string           `json:"service"`
	Before  SystemProxyState `json:"before"`
	After   SystemProxyState `json:"after"`
}
type SystemProxyPlan struct {
	OS      string              `json:"os"`
	Backend string              `json:"backend"`
	Changes []SystemProxyChange `json:"changes"`
}

func ReadSystemProxy(ctx context.Context, sshHost string, services []string) (SystemProxySnapshot, error) {
	for _, service := range services {
		if !safeService(service) {
			return SystemProxySnapshot{}, errors.New("invalid system proxy network service")
		}
	}
	request, _ := json.Marshal(map[string]any{"op": "read", "services": services})
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	data, err := connection.ExecutePython(ctx, sshHost, SystemProxyScript, request, 256<<10)
	if err != nil {
		return SystemProxySnapshot{}, err
	}
	var snapshot SystemProxySnapshot
	if json.Unmarshal(data, &snapshot) != nil || snapshot.Protocol != 1 {
		return snapshot, errors.New("system proxy reader returned an unsupported response")
	}
	return snapshot, nil
}
func PlanSystemProxy(snapshot SystemProxySnapshot, endpoint string, exceptions []string) (SystemProxyPlan, error) {
	return PlanSystemProxyWithSOCKS(snapshot, endpoint, "", exceptions)
}
func PlanSystemProxyWithSOCKS(snapshot SystemProxySnapshot, endpoint, socks string, exceptions []string) (SystemProxyPlan, error) {
	plan := SystemProxyPlan{OS: snapshot.OS, Backend: snapshot.Backend}
	if snapshot.Unavailable != "" || len(snapshot.Services) == 0 {
		return plan, errors.New("system proxy settings are unavailable in this host/session")
	}
	if snapshot.Backend != "macos-networksetup" && snapshot.Backend != "gnome-gsettings" {
		return plan, errors.New("unsupported system proxy backend")
	}
	if snapshot.Backend == "macos-networksetup" && !snapshot.SelectionExplicit {
		return plan, errors.New("select explicit macOS Network services before changing system proxy")
	}
	listener := func(value string, schemes ...string) (ProxyListener, error) {
		u, err := url.Parse(value)
		if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return ProxyListener{}, errors.New("system proxy requires a credential-free host URL with an explicit port")
		}
		found := false
		for _, scheme := range schemes {
			found = found || u.Scheme == scheme
		}
		port, err := strconv.Atoi(u.Port())
		if !found || err != nil || port < 1 || port > 65535 {
			return ProxyListener{}, errors.New("system proxy listener scheme or port is unsupported")
		}
		return ProxyListener{Enabled: true, Host: u.Hostname(), Port: port}, nil
	}
	http, err := listener(endpoint, "http")
	if err != nil {
		return plan, err
	}
	var socksListener ProxyListener
	if socks != "" {
		socksListener, err = listener(socks, "socks5", "socks5h")
		if err != nil {
			return plan, err
		}
	}
	for _, exception := range exceptions {
		if exception == "" || len(exception) > 253 || strings.IndexFunc(exception, unicode.IsControl) >= 0 {
			return plan, errors.New("invalid system proxy bypass entry")
		}
	}
	for _, before := range snapshot.Services {
		if before.Exceptions == nil {
			before.Exceptions = []string{}
		}
		if !safeService(before.Service) {
			return plan, errors.New("invalid system proxy network service")
		}
		if before.HTTP.Authenticated || before.HTTPS.Authenticated || before.SOCKS.Authenticated {
			return plan, errors.New("an existing authenticated system proxy cannot be safely snapshotted; manage it through its native owner")
		}
		after := before
		after.HTTP, after.HTTPS, after.SOCKS = http, http, socksListener
		after.PACEnabled, after.Discovery = false, false
		after.Mode = "manual"
		after.Exceptions = appendUnique(append([]string{}, before.Exceptions...), exceptions...)
		plan.Changes = append(plan.Changes, SystemProxyChange{before.Service, before, after})
	}
	return plan, nil
}

// Redacted is for review/JSON. The private plan is needed to preserve and
// restore a PAC URL, which can contain subscription credentials.
func (p SystemProxyPlan) Redacted() SystemProxyPlan {
	copy := p
	copy.Changes = append([]SystemProxyChange(nil), p.Changes...)
	for i := range copy.Changes {
		if copy.Changes[i].Before.PACURL != "" {
			copy.Changes[i].Before.PACURL = "<configured PAC URL>"
		}
		if copy.Changes[i].After.PACURL != "" {
			copy.Changes[i].After.PACURL = "<preserved PAC URL>"
		}
	}
	return copy
}
func safeService(service string) bool {
	return service != "" && len(service) <= 256 && !strings.HasPrefix(service, "-") && strings.IndexFunc(service, unicode.IsControl) < 0
}
