package configwork

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ParseImport never fetches URLs and never returns credentials in diagnostics.
// Unsupported URI parameters are rejected; raw YAML remains the lossless path.
func ParseImport(data []byte) ([]Definition, []ImportDiagnostic, error) {
	if len(data) > MaxDocument {
		return nil, nil, errors.New("import exceeds 8 MiB")
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return nil, nil, errors.New("empty node input")
	}
	if !strings.Contains(text, "://") {
		if decoded, err := b64(text); err == nil && strings.Contains(string(decoded), "://") {
			return ParseImport(decoded)
		}
	}
	lines := strings.Split(text, "\n")
	links := strings.Contains(strings.TrimSpace(lines[0]), "://") && !strings.HasPrefix(text, "{")
	if links {
		var out []Definition
		var diagnostics []ImportDiagnostic
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			n, err := ParseURI(line)
			if err != nil {
				diagnostics = append(diagnostics, ImportDiagnostic{i + 1, err.Error()})
				continue
			}
			d, err := definition(n, "proxy", "import")
			if err != nil {
				diagnostics = append(diagnostics, ImportDiagnostic{i + 1, err.Error()})
			} else {
				out = append(out, d)
			}
		}
		if len(out) == 0 {
			return nil, diagnostics, errors.New("no supported valid node links")
		}
		return out, diagnostics, nil
	}
	n, err := decode(data)
	if err != nil {
		return nil, nil, err
	}
	var nodes []*yaml.Node
	switch n.Kind {
	case yaml.SequenceNode:
		nodes = n.Content
	case yaml.MappingNode:
		if p := get(n, "proxies"); p != nil {
			if p.Kind != yaml.SequenceNode {
				return nil, nil, errors.New("proxies must be a sequence")
			}
			nodes = p.Content
		} else {
			nodes = []*yaml.Node{n}
		}
	default:
		return nil, nil, errors.New("node input must be a mapping or sequence")
	}
	var out []Definition
	for _, node := range nodes {
		d, e := definition(clone(node), "proxy", "import")
		if e != nil {
			return nil, nil, e
		}
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, nil, errors.New("input contains no concrete proxy nodes")
	}
	return out, nil, nil
}
func b64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if v, e := enc.DecodeString(s); e == nil {
			return v, nil
		}
	}
	return nil, errors.New("invalid base64 node data")
}
func ParseURI(raw string) (*yaml.Node, error) {
	if len(raw) > 128<<10 {
		return nil, errors.New("node link exceeds 128 KiB")
	}
	scheme, body, ok := strings.Cut(raw, "://")
	if !ok {
		return nil, errors.New("expected a node share link")
	}
	scheme = strings.ToLower(scheme)
	raw = scheme + "://" + body
	if scheme == "vmess" {
		body := strings.TrimPrefix(raw, "vmess://")
		if !strings.Contains(body, "@") {
			return parseVMess(body)
		}
		return nil, errors.New("VMess AEAD URI variant is not supported; use legacy VMess JSON or Mihomo YAML")
	}
	if scheme == "ss" {
		beforeFragment, fragment, _ := strings.Cut(strings.TrimPrefix(raw, "ss://"), "#")
		encoded, query, hasQuery := strings.Cut(beforeFragment, "?")
		if !strings.Contains(encoded, "@") {
			decoded, e := b64(encoded)
			if e != nil {
				return nil, e
			}
			raw = "ss://" + string(decoded)
			if hasQuery {
				raw += "?" + query
			}
			if fragment != "" {
				raw += "#" + fragment
			}
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.Opaque != "" {
		return nil, errors.New("invalid node URI")
	}
	port := u.Port()
	if port == "" && (scheme == "trojan" || scheme == "hy2" || scheme == "hysteria2") {
		port = "443"
	}
	p, e := strconv.Atoi(port)
	if e != nil || p < 1 || p > 65535 {
		return nil, errors.New("node port must be between 1 and 65535")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("invalid node query escaping")
	}
	for _, values := range q {
		if len(values) != 1 {
			return nil, errors.New("duplicate node URI parameter")
		}
	}
	name := u.Fragment
	if name == "" {
		name = q.Get("remarks")
	}
	if name == "" {
		name = scheme + "-" + net.JoinHostPort(u.Hostname(), port)
	}
	node := map[string]any{"name": name, "server": u.Hostname(), "port": p}
	allowed := map[string]bool{"remarks": true}
	allow := func(keys ...string) {
		for _, k := range keys {
			allowed[k] = true
		}
	}
	switch scheme {
	case "ss":
		node["type"] = "ss"
		if u.User == nil {
			return nil, errors.New("SS link is missing credentials")
		}
		cipher := u.User.Username()
		password, plain := u.User.Password()
		if !plain {
			v, e := b64(cipher)
			if e != nil {
				return nil, e
			}
			cipher, password, plain = strings.Cut(string(v), ":")
		}
		if !plain || cipher == "" || password == "" {
			return nil, errors.New("invalid SS credentials")
		}
		node["cipher"], node["password"] = cipher, password
		allow("plugin")
		if plugin := q.Get("plugin"); plugin != "" {
			parts, e := splitEscaped(plugin)
			if e != nil {
				return nil, e
			}
			node["plugin"] = parts[0]
			opts := map[string]any{}
			for _, part := range parts[1:] {
				k, v, has := strings.Cut(part, "=")
				if k == "" {
					return nil, errors.New("invalid SS plugin option")
				}
				if has {
					opts[k] = v
				} else {
					opts[k] = true
				}
			}
			node["plugin-opts"] = opts
		}
	case "vless", "trojan":
		node["type"] = scheme
		if u.User == nil || u.User.Username() == "" {
			return nil, errors.New("node authentication is missing")
		}
		if _, has := u.User.Password(); has {
			return nil, errors.New("unexpected password separator in node URI; percent-encode credentials")
		}
		if scheme == "vless" {
			node["uuid"] = u.User.Username()
			allow("encryption", "flow")
			if x := q.Get("encryption"); x != "" && x != "none" {
				return nil, errors.New("VLESS encryption variant requires raw YAML")
			}
			if x := q.Get("flow"); x != "" {
				node["flow"] = x
			}
		} else {
			node["password"] = u.User.Username()
		}
		allow("security", "sni", "peer", "fp", "alpn", "allowInsecure", "insecure", "type", "host", "path", "serviceName", "mode", "pbk", "sid", "spx")
		if err := uriTransport(node, q, scheme == "trojan"); err != nil {
			return nil, err
		}
	case "hy2", "hysteria2":
		node["type"] = "hysteria2"
		if u.User != nil {
			auth := u.User.Username()
			if pw, has := u.User.Password(); has {
				auth += ":" + pw
			}
			node["password"] = auth
		}
		allow("sni", "insecure", "obfs", "obfs-password", "pinSHA256")
		for query, key := range map[string]string{"sni": "sni", "obfs": "obfs", "obfs-password": "obfs-password", "pinSHA256": "fingerprint"} {
			if v := q.Get(query); v != "" {
				node[key] = v
			}
		}
		if q.Has("insecure") {
			v, e := uriBool(q.Get("insecure"))
			if e != nil {
				return nil, e
			}
			node["skip-cert-verify"] = v
		}
	default:
		return nil, errors.New("supported node links: ss, vmess, vless, trojan, hysteria2/hy2; HTTP URLs are subscription inputs, not node links")
	}
	for key := range q {
		if !allowed[key] {
			return nil, fmt.Errorf("unsupported URI parameter %q; use raw Mihomo YAML to preserve it", safeKey(key))
		}
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("unexpected URI path; encode transport path in its query parameter")
	}
	n := mapNode(node)
	if _, e := definition(n, "proxy", "import"); e != nil {
		return nil, e
	}
	return n, nil
}
func safeKey(s string) string {
	if len(s) > 40 {
		return "(unknown)"
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return "(unknown)"
		}
	}
	return s
}
func uriBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "1", "true":
		return true, nil
	case "0", "false":
		return false, nil
	}
	return false, errors.New("invalid URI boolean")
}
func uriTransport(m map[string]any, q url.Values, trojan bool) error {
	security := q.Get("security")
	if security == "" && trojan {
		security = "tls"
	}
	switch security {
	case "", "none":
	case "tls":
		m["tls"] = true
	case "reality":
		m["tls"] = true
		if q.Get("pbk") == "" {
			return errors.New("REALITY requires a public key")
		}
		r := map[string]any{"public-key": q.Get("pbk")}
		if q.Has("sid") {
			r["short-id"] = q.Get("sid")
		}
		if q.Has("spx") {
			r["spider-x"] = q.Get("spx")
		}
		m["reality-opts"] = r
	default:
		return errors.New("unsupported transport security")
	}
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	if sni != "" {
		key := "servername"
		if trojan {
			key = "sni"
		}
		m[key] = sni
	}
	if q.Get("fp") != "" {
		m["client-fingerprint"] = q.Get("fp")
	}
	if q.Get("alpn") != "" {
		m["alpn"] = strings.Split(q.Get("alpn"), ",")
	}
	for _, key := range []string{"allowInsecure", "insecure"} {
		if q.Has(key) {
			b, e := uriBool(q.Get(key))
			if e != nil {
				return e
			}
			m["skip-cert-verify"] = b
		}
	}
	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}
	switch network {
	case "tcp":
	case "ws":
		m["network"] = "ws"
		opts := map[string]any{}
		if q.Has("path") {
			opts["path"] = q.Get("path")
		}
		if q.Has("host") {
			opts["headers"] = map[string]any{"Host": q.Get("host")}
		}
		m["ws-opts"] = opts
	case "grpc":
		m["network"] = "grpc"
		opts := map[string]any{}
		if q.Has("serviceName") {
			opts["grpc-service-name"] = q.Get("serviceName")
		}
		if q.Get("mode") != "" && q.Get("mode") != "gun" {
			return errors.New("gRPC mode is not representable; use raw YAML")
		}
		m["grpc-opts"] = opts
	default:
		return errors.New("unsupported URI transport; use raw YAML")
	}
	if network != "ws" && (q.Has("host") || q.Has("path")) {
		return errors.New("host/path parameters require supported WebSocket transport")
	}
	if network != "grpc" && (q.Has("serviceName") || q.Has("mode")) {
		return errors.New("gRPC parameters require gRPC transport")
	}
	return nil
}
func parseVMess(body string) (*yaml.Node, error) {
	raw, e := b64(body)
	if e != nil {
		return nil, e
	}
	if n, err := decode(raw); err != nil || n.Kind != yaml.MappingNode {
		return nil, errors.New("invalid or duplicate VMess JSON fields")
	}
	var v map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if dec.Decode(&v) != nil || v == nil {
		return nil, errors.New("invalid VMess JSON")
	}
	allowed := map[string]bool{}
	for _, k := range []string{"v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni", "alpn", "fp", "allowInsecure"} {
		allowed[k] = true
	}
	for k := range v {
		if !allowed[k] {
			return nil, fmt.Errorf("unsupported VMess field %q; use raw YAML", safeKey(k))
		}
	}
	text := func(k string) string {
		if v[k] == nil {
			return ""
		}
		return fmt.Sprint(v[k])
	}
	port, e := strconv.Atoi(text("port"))
	if e != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid VMess port")
	}
	if text("add") == "" || text("id") == "" {
		return nil, errors.New("VMess server and UUID are required")
	}
	name := text("ps")
	if name == "" {
		name = "vmess-" + net.JoinHostPort(text("add"), strconv.Itoa(port))
	}
	aid := 0
	if text("aid") != "" {
		aid, e = strconv.Atoi(text("aid"))
		if e != nil || aid < 0 {
			return nil, errors.New("invalid VMess alterId")
		}
	}
	cipher := text("scy")
	if cipher == "" {
		cipher = "auto"
	}
	m := map[string]any{"name": name, "type": "vmess", "server": text("add"), "port": port, "uuid": text("id"), "alterId": aid, "cipher": cipher}
	q := url.Values{}
	if text("tls") != "" {
		if text("tls") != "tls" {
			return nil, errors.New("unsupported VMess security")
		}
		q.Set("security", "tls")
	}
	for _, k := range []string{"sni", "alpn", "fp", "allowInsecure"} {
		if text(k) != "" {
			q.Set(k, text(k))
		}
	}
	network := text("net")
	if network == "" {
		network = "tcp"
	}
	q.Set("type", network)
	if text("type") != "" && text("type") != "none" {
		return nil, errors.New("unsupported VMess header type")
	}
	if network == "grpc" {
		if text("path") != "" {
			q.Set("serviceName", text("path"))
		}
		if text("host") != "" {
			return nil, errors.New("VMess gRPC host cannot be preserved in supported codec")
		}
	} else {
		for _, k := range []string{"host", "path"} {
			if text(k) != "" {
				q.Set(k, text(k))
			}
		}
	}
	if e = uriTransport(m, q, false); e != nil {
		return nil, e
	}
	return mapNode(m), nil
}
func splitEscaped(s string) ([]string, error) {
	var out []string
	var b strings.Builder
	esc := false
	for _, r := range s {
		if esc {
			b.WriteRune(r)
			esc = false
			continue
		}
		if r == '\\' {
			esc = true
		} else if r == ';' {
			out = append(out, b.String())
			b.Reset()
		} else {
			b.WriteRune(r)
		}
	}
	if esc {
		return nil, errors.New("invalid SS plugin escaping")
	}
	return append(out, b.String()), nil
}
func pluginEscape(s string) string {
	r := strings.NewReplacer("\\", "\\\\", ";", "\\;", ":", "\\:", "=", "\\=")
	return r.Replace(s)
}

// Export returns secrets only when explicitly invoked by a caller's export action.
func Export(d Definition, format string) ([]byte, error) {
	switch format {
	case "yaml":
		return d.Raw()
	case "json":
		return json.MarshalIndent(d.Map(), "", "  ")
	case "url", "uri":
		s, e := EncodeURI(d)
		return []byte(s), e
	default:
		return nil, errors.New("export format must be yaml, json or url")
	}
}
func EncodeURI(d Definition) (string, error) {
	uri, err := encodeURI(d)
	if err != nil {
		return "", err
	}
	round, err := ParseURI(uri)
	if err != nil {
		return "", errors.New("this configuration cannot be represented by the supported URI codec; use YAML/JSON")
	}
	var decoded map[string]any
	if err = round.Decode(&decoded); err != nil {
		return "", err
	}
	for key, value := range d.Map() {
		other, present := decoded[key]
		if !present {
			if key == "network" && value == "tcp" {
				continue
			}
			if key == "tls" && value == false {
				continue
			}
		}
		if (key == "port" || key == "alterId") && fmt.Sprint(value) == fmt.Sprint(other) {
			continue
		}
		a, _ := json.Marshal(value)
		b, _ := json.Marshal(other)
		if !present || string(a) != string(b) {
			return "", fmt.Errorf("URI cannot preserve the value of %s; use YAML/JSON", safeKey(key))
		}
	}
	return uri, nil
}

func encodeURI(d Definition) (string, error) {
	m := d.Map()
	if m == nil {
		return "", errors.New("raw node source is unavailable")
	}
	text := func(k string) string {
		if m[k] == nil {
			return ""
		}
		return fmt.Sprint(m[k])
	}
	typ := text("type")
	allowed := map[string]bool{}
	keys := []string{"name", "type", "server", "port"}
	switch typ {
	case "ss":
		keys = append(keys, "cipher", "password", "plugin", "plugin-opts")
	case "vmess", "vless", "trojan":
		keys = append(keys, "tls", "client-fingerprint", "alpn", "skip-cert-verify", "network", "ws-opts", "grpc-opts")
		if typ == "vmess" {
			keys = append(keys, "uuid", "cipher", "alterId", "servername")
		}
		if typ == "vless" {
			keys = append(keys, "uuid", "flow", "servername", "reality-opts")
		}
		if typ == "trojan" {
			keys = append(keys, "password", "sni")
		}
	case "hysteria2":
		keys = append(keys, "password", "sni", "skip-cert-verify", "obfs", "obfs-password", "fingerprint")
	default:
		return "", errors.New("this node type requires YAML/JSON export")
	}
	for _, k := range keys {
		allowed[k] = true
	}
	var unsupported []string
	for k := range m {
		if !allowed[k] {
			unsupported = append(unsupported, safeKey(k))
		}
	}
	sort.Strings(unsupported)
	if len(unsupported) > 0 {
		return "", fmt.Errorf("URI cannot preserve fields: %s; use YAML/JSON", strings.Join(unsupported, ", "))
	}
	port, e := strconv.Atoi(text("port"))
	if e != nil || port < 1 || port > 65535 {
		return "", errors.New("invalid node port")
	}
	u := &url.URL{Scheme: typ, Host: net.JoinHostPort(text("server"), strconv.Itoa(port)), Fragment: text("name")}
	q := url.Values{}
	if typ == "ss" {
		cipher, password := text("cipher"), text("password")
		if strings.HasPrefix(cipher, "2022-") {
			u.User = url.UserPassword(cipher, password)
		} else {
			u.User = url.User(base64.RawURLEncoding.EncodeToString([]byte(cipher + ":" + password)))
		}
		if plugin := text("plugin"); plugin != "" {
			parts := []string{plugin}
			if opts, ok := m["plugin-opts"].(map[string]any); ok {
				ks := make([]string, 0, len(opts))
				for k := range opts {
					ks = append(ks, k)
				}
				sort.Strings(ks)
				for _, k := range ks {
					v := opts[k]
					if b, ok := v.(bool); ok && b {
						parts = append(parts, pluginEscape(k))
					} else {
						parts = append(parts, pluginEscape(k)+"="+pluginEscape(fmt.Sprint(v)))
					}
				}
			}
			q.Set("plugin", strings.Join(parts, ";"))
			u.Path = "/"
		}
	} else if typ == "hysteria2" {
		if text("password") != "" {
			u.User = url.User(text("password"))
		}
		for key, query := range map[string]string{"sni": "sni", "obfs": "obfs", "obfs-password": "obfs-password", "fingerprint": "pinSHA256"} {
			if text(key) != "" {
				q.Set(query, text(key))
			}
		}
		if v, ok := m["skip-cert-verify"].(bool); ok {
			if v {
				q.Set("insecure", "1")
			} else {
				q.Set("insecure", "0")
			}
		}
	} else {
		auth := text("uuid")
		if typ == "trojan" {
			auth = text("password")
		}
		u.User = url.User(auth)
		if typ == "vless" {
			q.Set("encryption", "none")
			if text("flow") != "" {
				q.Set("flow", text("flow"))
			}
		}
		if tls, ok := m["tls"].(bool); ok && tls {
			q.Set("security", "tls")
		} else if typ == "trojan" {
			q.Set("security", "tls")
		} else {
			q.Set("security", "none")
		}
		if r, ok := m["reality-opts"].(map[string]any); ok {
			if typ != "vless" {
				return "", errors.New("REALITY export requires VLESS")
			}
			q.Set("security", "reality")
			for k, v := range r {
				key, known := map[string]string{"public-key": "pbk", "short-id": "sid", "spider-x": "spx"}[k]
				if !known {
					return "", errors.New("URI cannot preserve extra REALITY options")
				}
				q.Set(key, fmt.Sprint(v))
			}
		}
		sni := text("servername")
		if sni == "" {
			sni = text("sni")
		}
		if sni != "" {
			q.Set("sni", sni)
		}
		if text("client-fingerprint") != "" {
			q.Set("fp", text("client-fingerprint"))
		}
		if a, ok := m["alpn"].([]any); ok {
			var ss []string
			for _, v := range a {
				ss = append(ss, fmt.Sprint(v))
			}
			q.Set("alpn", strings.Join(ss, ","))
		}
		if b, ok := m["skip-cert-verify"].(bool); ok {
			q.Set("allowInsecure", strconv.FormatBool(b))
		}
		network := text("network")
		if network == "" {
			network = "tcp"
		}
		q.Set("type", network)
		switch network {
		case "tcp":
		case "ws":
			opts, _ := m["ws-opts"].(map[string]any)
			for k, v := range opts {
				switch k {
				case "path":
					q.Set("path", fmt.Sprint(v))
				case "headers":
					headers, ok := v.(map[string]any)
					if !ok {
						return "", errors.New("invalid WS headers")
					}
					for hk, hv := range headers {
						if hk != "Host" {
							return "", errors.New("URI cannot preserve non-Host WS headers")
						}
						s, ok := hv.(string)
						if !ok {
							return "", errors.New("URI requires a string WS Host header")
						}
						q.Set("host", s)
					}
				default:
					return "", errors.New("URI cannot preserve extra WebSocket options")
				}
			}
		case "grpc":
			opts, _ := m["grpc-opts"].(map[string]any)
			for k, v := range opts {
				if k != "grpc-service-name" {
					return "", errors.New("URI cannot preserve extra gRPC options")
				}
				q.Set("serviceName", fmt.Sprint(v))
			}
		default:
			return "", errors.New("transport requires YAML/JSON export")
		}
		if typ == "vmess" {
			if get(d.Node, "reality-opts") != nil || text("flow") != "" {
				return "", errors.New("VMess URI cannot preserve REALITY/flow")
			}
			v := map[string]any{"v": "2", "ps": text("name"), "add": text("server"), "port": strconv.Itoa(port), "id": text("uuid"), "aid": text("alterId"), "scy": text("cipher"), "net": network, "type": "none", "host": q.Get("host"), "path": q.Get("path")}
			if network == "grpc" {
				v["path"] = q.Get("serviceName")
			}
			if q.Get("security") == "tls" {
				v["tls"] = "tls"
			}
			for _, key := range []string{"sni", "alpn", "fp", "allowInsecure"} {
				if q.Has(key) {
					v[key] = q.Get(key)
				}
			}
			raw, _ := json.Marshal(v)
			return "vmess://" + base64.StdEncoding.EncodeToString(raw), nil
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
