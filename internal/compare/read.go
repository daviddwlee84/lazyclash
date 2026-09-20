package compare

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

func invalid(format string, args ...any) error {
	return &ValidationError{Message: fmt.Sprintf(format, args...)}
}

func validatePair(source, destination config.Target) error {
	if source.ID == "" || destination.ID == "" || source.Transient || destination.Transient {
		return invalid("comparison and copying require two saved targets")
	}
	if err := config.Validate(config.Config{Targets: []config.Target{source, destination}}); err != nil {
		return invalid("targets: %s", err)
	}
	if source.SSHHost == destination.SSHHost && normalizedController(source.Controller) == normalizedController(destination.Controller) {
		return invalid("source and destination resolve to the same configured controller and SSH host")
	}
	return nil
}

func normalizedController(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	if u.Scheme == "unix" {
		return "unix://" + filepath.Clean(u.Path)
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port) + strings.TrimRight(u.EscapedPath(), "/")
}

func targetRef(t config.Target) TargetRef {
	return TargetRef{ID: t.ID, Name: t.Label(), Controller: t.Controller, SSHHost: t.SSHHost}
}

type opened struct {
	client *core.Client
	closer io.Closer
}

func (o opened) close() {
	if o.client != nil {
		_ = o.client.Close()
	}
	if o.closer != nil {
		_ = o.closer.Close()
	}
}

func open(ctx context.Context, t config.Target, readOnly bool, opts Options) (opened, error) {
	fn := opts.Open
	if fn == nil {
		fn = connection.Open
	}
	client, closer, err := fn(ctx, t, readOnly)
	o := opened{client: client, closer: closer}
	if err != nil {
		o.close()
		return opened{}, fmt.Errorf("target %q: %w", t.ID, err)
	}
	if client == nil {
		o.close()
		return opened{}, fmt.Errorf("target %q: controller client is unavailable", t.ID)
	}
	return o, nil
}

func read(ctx context.Context, client *core.Client, target config.Target) (Snapshot, error) {
	result := Snapshot{Target: targetRef(target), Groups: []Group{}, RedactedFields: []string{}}
	version, err := client.Version(ctx)
	if err != nil {
		return result, fmt.Errorf("target %q: %w", target.ID, err)
	}
	result.Version, _ = version["version"].(string)
	result.Version = strings.Join(strings.Fields(core.Sanitize(result.Version)), " ")
	if result.Version == "" {
		return result, &core.Error{Kind: core.KindInvalid, Operation: "read comparison core version"}
	}
	general, err := client.Config(ctx)
	if err != nil {
		return result, fmt.Errorf("target %q: %w", target.ID, err)
	}
	// Redact before retaining or comparing values, including nested credentials.
	redacted, ok := core.Redact(general).(map[string]any)
	if !ok {
		return result, &core.Error{Kind: core.KindInvalid, Operation: "redact comparison settings"}
	}
	result.General = core.Object(redacted)
	collectRedacted(redacted, "", &result.RedactedFields)
	proxies, err := client.Proxies(ctx)
	if err != nil {
		return result, fmt.Errorf("target %q: %w", target.ID, err)
	}
	for name, proxy := range proxies {
		if len(proxy.All) == 0 && !groupType(proxy.Type) {
			continue
		}
		group := Group{Name: name, Type: proxy.Type, Members: uniqueSorted(proxy.All)}
		if strings.EqualFold(proxy.Type, "Selector") {
			group.Selected = proxy.Now
		}
		result.Groups = append(result.Groups, group)
	}
	sort.Slice(result.Groups, func(i, j int) bool { return result.Groups[i].Name < result.Groups[j].Name })
	sort.Strings(result.RedactedFields)
	return result, nil
}

func groupType(kind string) bool {
	switch strings.ToLower(kind) {
	case "selector", "urltest", "url-test", "fallback", "loadbalance", "load-balance", "relay":
		return true
	}
	return false
}

func uniqueSorted(values []string) []string {
	copy := append([]string{}, values...)
	sort.Strings(copy)
	return slices.Compact(copy)
}

func pointer(path, key string) string {
	return path + "/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
}

func collectRedacted(value any, path string, paths *[]string) {
	if text, ok := value.(string); ok && text == "[redacted]" {
		*paths = append(*paths, path)
		return
	}
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			collectRedacted(child, pointer(path, key), paths)
		}
	case []any:
		for index, child := range value {
			collectRedacted(child, pointer(path, fmt.Sprint(index)), paths)
		}
	}
}

func equalJSON(a, b any) bool {
	aJSON, aErr := json.Marshal(a)
	bJSON, bErr := json.Marshal(b)
	return aErr == nil && bErr == nil && string(aJSON) == string(bJSON)
}
