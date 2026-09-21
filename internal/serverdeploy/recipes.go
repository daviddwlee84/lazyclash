package serverdeploy

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"regexp"
	"strconv"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
	"go.yaml.in/yaml/v3"
)

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`)
var dnsPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

func normalize(r Request, h serverstate.Host) (Request, error) {
	if !idPattern.MatchString(r.ID) {
		return r, errors.New("deployment ID must use 1–48 lowercase letters, digits or hyphens")
	}
	if r.Recipe == "" {
		r.Recipe = "vless-reality"
	}
	found := false
	for _, p := range Recipes() {
		if p.ID == r.Recipe {
			found = true
		}
	}
	if !found {
		return r, errors.New("unknown server recipe")
	}
	if r.Backend == "" {
		r.Backend = "native"
	}
	if r.Backend != "native" && r.Backend != "compose" {
		return r, errors.New("backend must be native or compose")
	}
	if h.SSHHost == "" {
		return r, errors.New("host has no SSH management address")
	}
	if r.PublicHost == "" {
		r.PublicHost = h.PublicHost
	}
	if !validHost(r.PublicHost) {
		return r, errors.New("public host must be an IP address or DNS hostname without a port")
	}
	if r.PublicPort == 0 {
		r.PublicPort = 443
	}
	if r.ListenPort == 0 {
		r.ListenPort = r.PublicPort
	}
	if r.PublicPort < 1 || r.PublicPort > 65535 || r.ListenPort < 1 || r.ListenPort > 65535 {
		return r, errors.New("server ports must be between 1 and 65535")
	}
	if r.Recipe == "vless-reality" {
		if r.RealityTarget == "" {
			r.RealityTarget = "www.cloudflare.com:443"
		}
		host, port, e := net.SplitHostPort(r.RealityTarget)
		p, _ := strconv.Atoi(port)
		if e != nil || !validHost(host) || p < 1 || p > 65535 {
			return r, errors.New("REALITY target must be hostname:port")
		}
		if r.ServerName == "" {
			r.ServerName = host
		}
		if !validDomain(r.ServerName) {
			return r, errors.New("REALITY server name must be a DNS hostname")
		}
		if r.Domain != "" || r.Email != "" {
			return r, errors.New("REALITY does not use ACME domain or email; use server-name for its target")
		}
	} else {
		if !validDomain(r.Domain) {
			return r, errors.New("this recipe requires a public DNS domain for trusted TLS")
		}
		if r.ListenPort == 80 {
			return r, errors.New("TCP port 80 is reserved for ACME HTTP validation")
		}
		if r.Email != "" {
			address, err := mail.ParseAddress(r.Email)
			if err != nil || address.Address != r.Email {
				return r, errors.New("ACME email is invalid")
			}
		}
	}
	v := strings.TrimPrefix(strings.TrimPrefix(r.Version, "app/"), "v")
	if v != "" && v != "latest" && !versionPattern.MatchString(v) {
		return r, errors.New("version must identify a published release")
	}
	return r, nil
}
func validHost(v string) bool { return net.ParseIP(v) != nil || validDomain(v) }

// ValidateDraft checks supplied wizard flags without SSH, network or writes.
// Missing required inputs are deliberately left for the wizard to collect.
func ValidateDraft(r Request) error {
	if r.ID != "" && !idPattern.MatchString(r.ID) {
		return errors.New("deployment ID must use 1–48 lowercase letters, digits or hyphens")
	}
	if r.PublicHost != "" && !validHost(r.PublicHost) {
		return errors.New("public host must be an IP address or DNS hostname without a port")
	}
	if r.Domain != "" && !validDomain(r.Domain) {
		return errors.New("certificate domain must be a DNS hostname")
	}
	if r.ServerName != "" && !validDomain(r.ServerName) {
		return errors.New("REALITY server name must be a DNS hostname")
	}
	if r.PublicPort < 0 || r.PublicPort > 65535 || r.ListenPort < 0 || r.ListenPort > 65535 {
		return errors.New("ports must be between 1 and 65535")
	}
	if r.Backend != "" && r.Backend != "native" && r.Backend != "compose" {
		return errors.New("backend must be native or compose")
	}
	if r.Recipe != "" {
		found := false
		for _, p := range Recipes() {
			found = found || p.ID == r.Recipe
		}
		if !found {
			return errors.New("unknown server recipe")
		}
	}
	if r.RealityTarget != "" {
		h, p, e := net.SplitHostPort(r.RealityTarget)
		n, _ := strconv.Atoi(p)
		if e != nil || !validHost(h) || n < 1 || n > 65535 {
			return errors.New("REALITY target must be hostname:port")
		}
	}
	if r.Email != "" {
		a, e := mail.ParseAddress(r.Email)
		if e != nil || a.Address != r.Email {
			return errors.New("ACME email is invalid")
		}
	}
	v := strings.TrimPrefix(strings.TrimPrefix(r.Version, "app/"), "v")
	if v != "" && v != "latest" && !versionPattern.MatchString(v) {
		return errors.New("version must identify a published release")
	}
	return nil
}
func validDomain(v string) bool {
	if !dnsPattern.MatchString(v) || !strings.Contains(v, ".") || strings.Contains(v, "..") || net.ParseIP(v) != nil {
		return false
	}
	for _, l := range strings.Split(v, ".") {
		if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return false
		}
	}
	return true
}

func generateCredentials() (credentials, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return credentials{}, err
	}
	u := make([]byte, 16)
	if _, err = rand.Read(u); err != nil {
		return credentials{}, err
	}
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	b := make([]byte, 40)
	if _, err = rand.Read(b); err != nil {
		return credentials{}, err
	}
	return credentials{UUID: fmt.Sprintf("%x-%x-%x-%x-%x", u[:4], u[4:6], u[6:8], u[8:10], u[10:]), Password: base64.RawURLEncoding.EncodeToString(b[:24]), PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), ShortID: hex.EncodeToString(b[24:32]), WSPath: "/" + hex.EncodeToString(b[32:])}, nil
}
func innerPort(id string) int {
	sum := sha256.Sum256([]byte(id))
	return 10000 + int(binary.BigEndian.Uint16(sum[:2]))%40000
}
func rootPath(id string) string { return "/var/lib/lazyclash/servers/" + id }
func unitName(id string) string { return "lazyclash-server-" + id + ".service" }
func certName(r Request) string { return "lazyclash-" + r.ID }

func render(r Request, c credentials, a Artifact) (map[string]string, error) {
	files := map[string]string{}
	root := rootPath(r.ID)
	configPath := root + "/config.json"
	binaryName := "xray"
	args := "run -config " + configPath
	if r.Recipe == "hysteria2" {
		binaryName = "hysteria"
		configPath = root + "/config.yaml"
		args = "server --config " + configPath
		tlsRoot := "/etc/letsencrypt/live/" + certName(r)
		body, e := yaml.Marshal(map[string]any{"listen": ":" + strconv.Itoa(r.ListenPort), "tls": map[string]any{"cert": tlsRoot + "/fullchain.pem", "key": tlsRoot + "/privkey.pem"}, "auth": map[string]any{"type": "password", "password": c.Password}, "masquerade": map[string]any{"type": "string", "string": map[string]any{"content": "Service ready", "statusCode": 200}}})
		if e != nil {
			return nil, e
		}
		files["config.yaml"] = string(body)
	} else {
		client := map[string]any{"id": c.UUID}
		stream := map[string]any{}
		settings := map[string]any{"clients": []any{client}}
		protocol, listen, port := "vless", "::", r.ListenPort
		if r.Recipe == "vless-reality" {
			client["flow"] = "xtls-rprx-vision"
			settings["decryption"] = "none"
			stream = map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"show": false, "target": r.RealityTarget, "xver": 0, "serverNames": []string{r.ServerName}, "privateKey": c.PrivateKey, "shortIds": []string{c.ShortID}}}
		} else {
			protocol, listen, port = "vmess", "127.0.0.1", innerPort(r.ID)
			stream = map[string]any{"network": "ws", "security": "none", "wsSettings": map[string]any{"path": c.WSPath}}
		}
		body, e := json.MarshalIndent(map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"listen": listen, "port": port, "protocol": protocol, "settings": settings, "streamSettings": stream}}, "outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}}}, "", "  ")
		if e != nil {
			return nil, e
		}
		files["config.json"] = string(body) + "\n"
	}
	if r.Recipe == "legacy-vmess-ws-tls" {
		files["nginx.conf"] = fmt.Sprintf("pid /tmp/lazyclash-nginx.pid;\nerror_log stderr warn;\nevents {}\nhttp {\n access_log off;\n client_body_temp_path /tmp/lazyclash-client;\n proxy_temp_path /tmp/lazyclash-proxy;\n fastcgi_temp_path /tmp/lazyclash-fastcgi;\n uwsgi_temp_path /tmp/lazyclash-uwsgi;\n scgi_temp_path /tmp/lazyclash-scgi;\n server {\n listen %d ssl;\n listen [::]:%d ssl;\n server_name %s;\n ssl_certificate /etc/letsencrypt/live/%s/fullchain.pem;\n ssl_certificate_key /etc/letsencrypt/live/%s/privkey.pem;\n ssl_protocols TLSv1.2 TLSv1.3;\n location %s {\n proxy_pass http://127.0.0.1:%d;\n proxy_http_version 1.1;\n proxy_set_header Upgrade $http_upgrade;\n proxy_set_header Connection \"upgrade\";\n proxy_set_header Host $host;\n proxy_read_timeout 300s;\n proxy_buffering off;\n }\n location / { return 200 'Service ready'; }\n }\n}\n", r.ListenPort, r.ListenPort, r.Domain, certName(r), certName(r), c.WSPath, innerPort(r.ID))
	}
	if r.Backend == "native" {
		files["service.unit"] = systemdUnit(r.ID, root+"/bin/"+binaryName+" "+args, root)
		if r.Recipe == "legacy-vmess-ws-tls" {
			files["nginx.unit"] = systemdUnit(r.ID+"-tls", "/usr/sbin/nginx -c "+root+"/nginx.conf -g 'daemon off;'", root)
			// nginx's master drops worker credentials before accepting requests.
			files["nginx.unit"] = strings.ReplaceAll(files["nginx.unit"], "CapabilityBoundingSet=CAP_NET_BIND_SERVICE", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_CHOWN")
		}
	} else {
		volumes := []string{configPath + ":" + configPath + ":ro"}
		if r.Recipe == "hysteria2" {
			volumes = append(volumes, certificateVolumes(r)...)
		}
		command := []string{"run", "-config", configPath}
		if r.Recipe == "hysteria2" {
			command = []string{"server", "--config", configPath}
		}
		core := map[string]any{"image": a.Image, "network_mode": "host", "restart": "unless-stopped", "user": "0:0", "read_only": true, "cap_drop": []string{"ALL"}, "cap_add": []string{"NET_BIND_SERVICE"}, "security_opt": []string{"no-new-privileges:true"}, "volumes": volumes, "command": command, "logging": map[string]any{"driver": "json-file", "options": map[string]string{"max-size": "10m", "max-file": "3"}}}
		services := map[string]any{"core": core}
		if r.Recipe == "legacy-vmess-ws-tls" {
			tlsVolumes := append([]string{root + "/nginx.conf:" + root + "/nginx.conf:ro"}, certificateVolumes(r)...)
			services["tls"] = map[string]any{"image": a.NginxImage, "network_mode": "host", "restart": "unless-stopped", "user": "0:0", "read_only": true, "tmpfs": []string{"/tmp:rw,nosuid,noexec,size=32m"}, "cap_drop": []string{"ALL"}, "cap_add": []string{"NET_BIND_SERVICE", "SETUID", "SETGID", "CHOWN"}, "security_opt": []string{"no-new-privileges:true"}, "volumes": tlsVolumes, "entrypoint": []string{"nginx"}, "command": []string{"-c", root + "/nginx.conf", "-g", "daemon off;"}, "logging": core["logging"]}
		}
		body, e := yaml.Marshal(map[string]any{"name": "lazyclash-" + r.ID, "services": services})
		if e != nil {
			return nil, e
		}
		files["compose.yaml"] = string(body)
	}
	return files, nil
}

func withOwnership(files map[string]string, token string, r Request) (map[string]string, error) {
	if r.Backend == "native" {
		for _, key := range []string{"service.unit", "nginx.unit"} {
			if data, ok := files[key]; ok {
				files[key] = "# lazyclash-owner=" + token + "\n" + data
			}
		}
		return files, nil
	}
	var compose map[string]any
	if err := yaml.Unmarshal([]byte(files["compose.yaml"]), &compose); err != nil {
		return nil, err
	}
	services, ok := compose["services"].(map[string]any)
	if !ok {
		return nil, errors.New("invalid generated Compose services")
	}
	for _, value := range services {
		service, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("invalid generated Compose service")
		}
		service["labels"] = map[string]string{"io.lazyclash.owner": token, "io.lazyclash.deployment": r.ID}
	}
	body, err := yaml.Marshal(compose)
	if err != nil {
		return nil, err
	}
	files["compose.yaml"] = string(body)
	return files, nil
}

func systemdUnit(id, command, root string) string {
	return fmt.Sprintf("[Unit]\nDescription=lazyclash proxy %s\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nExecStart=%s\nRestart=on-failure\nRestartSec=3\nUser=root\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nReadOnlyPaths=%s\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nLimitNOFILE=1048576\n[Install]\nWantedBy=multi-user.target\n", id, command, root)
}

func clientMap(j journal) map[string]any {
	r, c := j.Plan.Request, j.Credentials
	m := map[string]any{"name": r.ID, "server": r.PublicHost, "port": r.PublicPort}
	switch r.Recipe {
	case "vless-reality":
		m["type"] = "vless"
		m["uuid"] = c.UUID
		m["flow"] = "xtls-rprx-vision"
		m["tls"] = true
		m["network"] = "tcp"
		m["servername"] = r.ServerName
		m["client-fingerprint"] = "chrome"
		m["reality-opts"] = map[string]any{"public-key": c.PublicKey, "short-id": c.ShortID}
	case "hysteria2":
		m["type"] = "hysteria2"
		m["password"] = c.Password
		m["sni"] = r.Domain
	case "legacy-vmess-ws-tls":
		m["type"] = "vmess"
		m["uuid"] = c.UUID
		m["alterId"] = 0
		m["cipher"] = "auto"
		m["tls"] = true
		m["network"] = "ws"
		m["servername"] = r.Domain
		m["ws-opts"] = map[string]any{"path": c.WSPath, "headers": map[string]any{"Host": r.Domain}}
	}
	return m
}

func certificateVolumes(r Request) []string {
	name := certName(r)
	live := "/etc/letsencrypt/live/" + name
	archive := "/etc/letsencrypt/archive/" + name
	return []string{live + ":" + live + ":ro", archive + ":" + archive + ":ro"}
}
