package proxyenv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func ValidateEndpoint(value string) error {
	return config.ValidateProbe(config.Target{ProbeProxy: value})
}

func Resolve(ctx context.Context, cfg config.Config, request Request, opts Options) (Plan, error) {
	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	if request.Endpoint != "" {
		if request.TargetID != "" {
			return Plan{}, errors.New("use either --endpoint or --target")
		}
		return explicitPlan(request.Endpoint, request.SocksEndpoint, "explicit endpoint")
	}
	if request.SocksEndpoint != "" {
		return Plan{}, errors.New("--socks-endpoint requires --endpoint")
	}
	if request.TargetID != "" {
		for _, target := range cfg.Targets {
			if target.ID == request.TargetID {
				return resolveTarget(ctx, target, opts)
			}
		}
		return Plan{}, errors.New("proxy target is not registered; use targets list")
	}
	if value := getenv("LOCAL_PROXY_URL"); value != "" {
		return explicitPlan(value, getenv("LOCAL_PROXY_SOCKS_URL"), "LOCAL_PROXY_URL")
	}
	var local []config.Target
	for _, target := range cfg.Targets {
		if IsLocalTarget(target) {
			local = append(local, target)
		}
	}
	for _, target := range local {
		if target.ID == cfg.DefaultTarget {
			return resolveTarget(ctx, target, opts)
		}
	}
	if len(local) == 0 {
		discover := opts.Discover
		if discover == nil {
			discover = connection.Discover
		}
		var err error
		local, err = discover(ctx, "")
		if err != nil {
			return Plan{}, err
		}
	}
	if len(local) == 0 {
		return Plan{}, ErrNoProxyConfigured
	}
	if len(local) > 1 {
		return Plan{}, &AmbiguousError{Targets: local}
	}
	return resolveTarget(ctx, local[0], opts)
}

func IsLocalTarget(target config.Target) bool {
	if target.SSHHost != "" {
		return false
	}
	u, err := url.Parse(target.Controller)
	if err != nil {
		return false
	}
	return u.Scheme == "unix" || loopback(u.Hostname())
}
func loopback(host string) bool {
	ip := net.ParseIP(host)
	return strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
}

func explicitPlan(endpoint, socks, source string) (Plan, error) {
	if endpoint == "" {
		return Plan{}, errors.New("a data proxy endpoint is required")
	}
	if err := ValidateEndpoint(endpoint); err != nil {
		return Plan{}, err
	}
	if socks != "" {
		if err := ValidateEndpoint(socks); err != nil {
			return Plan{}, err
		}
		u, _ := url.Parse(socks)
		if u.Scheme != "socks5" && u.Scheme != "socks5h" {
			return Plan{}, errors.New("SOCKS endpoint must use socks5 or socks5h")
		}
	} else {
		socks = endpoint
	}
	return Plan{HTTP: endpoint, All: socks, Source: source}, nil
}

func resolveTarget(ctx context.Context, target config.Target, opts Options) (Plan, error) {
	var plan Plan
	var err error
	if target.ProbeProxy != "" {
		plan, err = explicitPlan(target.ProbeProxy, "", "registered data proxy")
	} else {
		// A remote controller may be behind a reverse proxy. Its hostname is not
		// evidence that data ports are accessible on that same host.
		if target.SSHHost == "" && !IsLocalTarget(target) {
			return plan, errors.New("remote target needs an explicit --probe-proxy endpoint in targets edit")
		}
		open := opts.Open
		if open == nil {
			open = connection.Open
		}
		queryCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		client, closer, e := open(queryCtx, target, true)
		if closer != nil {
			defer closer.Close()
		}
		if client != nil {
			defer client.Close()
		}
		if e != nil {
			return plan, e
		}
		if client == nil {
			return plan, errors.New("controller client unavailable")
		}
		runtime, e := client.Config(queryCtx)
		if e != nil {
			return plan, e
		}
		host := "127.0.0.1"
		u, _ := url.Parse(target.Controller)
		if u.Scheme != "unix" && u.Hostname() == "::1" {
			host = "::1"
		}
		port := runtimePort(runtime["mixed-port"])
		socks := port
		if port == 0 {
			port = runtimePort(runtime["port"])
			socks = runtimePort(runtime["socks-port"])
		}
		if port == 0 && socks == 0 {
			return plan, errors.New("core reports no HTTP/mixed/SOCKS port; configure --probe-proxy explicitly")
		}
		endpoint := ""
		all := ""
		if port > 0 {
			endpoint = "http://" + net.JoinHostPort(host, strconv.Itoa(port))
		}
		if socks > 0 {
			all = "socks5h://" + net.JoinHostPort(host, strconv.Itoa(socks))
		}
		if endpoint == "" {
			endpoint = all
		}
		plan, err = explicitPlan(endpoint, all, "core runtime ports")
	}
	if err != nil {
		return plan, err
	}
	plan.TargetID, plan.SSHHost = target.ID, target.SSHHost
	plan.Username, plan.PasswordEnv, plan.PasswordFile, plan.CAFile = target.ProbeUsername, target.ProbePasswordEnv, target.ProbePasswordFile, target.ProbeCAFile
	return plan, nil
}
func runtimePort(value any) int {
	var n int
	switch v := value.(type) {
	case float64:
		if v != float64(int(v)) {
			return 0
		}
		n = int(v)
	case int:
		n = v
	case json.Number:
		n, _ = strconv.Atoi(string(v))
	case string:
		n, _ = strconv.Atoi(v)
	}
	if n < 1 || n > 65535 {
		return 0
	}
	return n
}

func (p Plan) Validate() error {
	if _, err := explicitPlan(p.HTTP, p.socks(), p.Source); err != nil {
		return err
	}
	if p.SSHHost != "" {
		if err := config.ValidateTarget(config.Target{Controller: "http://127.0.0.1:9090", SSHHost: p.SSHHost}); err != nil {
			return err
		}
	}
	if err := config.ValidateProbe(config.Target{ProbeProxy: p.HTTP, ProbeUsername: p.Username, ProbePasswordEnv: p.PasswordEnv, ProbePasswordFile: p.PasswordFile, ProbeCAFile: p.CAFile}); err != nil {
		return fmt.Errorf("proxy credentials: %w", err)
	}
	return nil
}
func (p Plan) socks() string {
	if p.All == p.HTTP {
		return ""
	}
	return p.All
}
