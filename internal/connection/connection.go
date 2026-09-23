// Package connection resolves target credentials and owns the transports it opens.
package connection

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/managedrpi"
)

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// Open never falls back to a different target. Secrets are resolved only from
// references on this target, and are never passed to SSH or another process.
func Open(ctx context.Context, target config.Target, readOnly bool) (*core.Client, io.Closer, error) {
	if err := config.ValidateTarget(target); err != nil {
		return nil, nil, err
	}
	if target.ManagedRPi != nil {
		if err := managedrpi.ValidateTransport(ctx, target, nil); err != nil {
			return nil, nil, err
		}
	}
	secret, err := resolveSecret(ctx, target)
	if err != nil {
		return nil, nil, err
	}
	opts := core.Options{Endpoint: target.Controller, Secret: secret, CAFile: target.CAFile, ReadOnly: readOnly}
	if target.ManagedRPi != nil {
		opts.ManagedRPi = true
		opts.SelectOwner = func(ctx context.Context, group, member string) error {
			out, err := managedrpi.Call(ctx, target, managedrpi.Request{Operation: "select", Group: group, Member: member}, nil)
			if err != nil {
				return err
			}
			if out.State != "selected" || out.Group != group || out.Member != member || !managedrpi.ValidIdentity(out.Identity) {
				return errors.New("managed RPi selector result is unconfirmed; inspect the owner before retrying")
			}
			return nil
		}
	}
	var closer io.Closer = closerFunc(func() error { return nil })
	if target.SSHHost != "" {
		u, _ := url.Parse(target.Controller)
		if u.Scheme == "unix" {
			return nil, nil, errors.New("remote Unix controller sockets are not supported; expose a loopback HTTP(S) controller on the SSH host")
		}
		tunnel, err := openTunnel(ctx, target.SSHHost, u)
		if err != nil {
			return nil, nil, err
		}
		closer = tunnel
		opts.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", tunnel.address)
		}
	}
	client, err := core.New(opts)
	if err != nil {
		_ = closer.Close()
		return nil, nil, err
	}
	version, err := client.Version(ctx)
	if err == nil {
		if v, ok := version["version"].(string); !ok || v == "" {
			err = &core.Error{Kind: core.KindInvalid, Operation: "identify controller"}
		}
	}
	if err != nil {
		_ = client.Close()
		_ = closer.Close()
		return nil, nil, err
	}
	transportCloser := closer
	return client, closerFunc(func() error { _ = client.Close(); return transportCloser.Close() }), nil
}

func resolveSecret(ctx context.Context, t config.Target) (string, error) {
	if t.SecretEnv != "" {
		secret, ok := os.LookupEnv(t.SecretEnv)
		if !ok {
			return "", fmt.Errorf("secret environment variable %s is not set", t.SecretEnv)
		}
		return cleanSecret(secret)
	}
	if t.SecretFile != "" {
		data, err := readLimitedFile(t.SecretFile, 64*1024)
		if err != nil {
			return "", errors.New("cannot read configured local secret file")
		}
		return cleanSecret(strings.TrimRight(string(data), "\r\n"))
	}
	if t.SourceConfig != "" {
		var data []byte
		var err error
		if t.SSHHost != "" {
			data, err = remoteRead(ctx, t.SSHHost, t.SourceConfig)
		} else {
			data, err = readLimitedFile(t.SourceConfig, maxConfigBytes)
		}
		if err != nil {
			if IsAuthRequired(err) {
				return "", err
			}
			return "", errors.New("cannot read this target's source_config; fix its path or configure secret_env/secret_file")
		}
		runtime, err := parseRuntime(data)
		if err != nil {
			return "", errors.New("invalid YAML in this target's source_config")
		}
		if !runtime.matches(t.Controller) {
			return "", errors.New("source_config controller no longer matches this target; rediscover or configure an explicit secret reference")
		}
		return cleanSecret(runtime.Secret)
	}
	return cleanSecret(t.Secret)
}

func cleanSecret(s string) (string, error) {
	if strings.ContainsAny(s, "\r\n\x00") {
		return "", errors.New("controller secret contains invalid control characters")
	}
	return s, nil
}

func readLimitedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("expected a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds size limit")
	}
	return data, nil
}
