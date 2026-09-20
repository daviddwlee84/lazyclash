package core

import (
	"bytes"
	"encoding/json"
	"strings"
)

const redactedValue = "[redacted]"

// Redact returns an independent JSON-shaped copy suitable for display or output.
// Credential-bearing fields are masked recursively. Credential references such
// as secret_env and secret_file stay visible, as do unrelated rule/log payloads.
// Numbers retain their JSON precision, and JSON struct tags remain authoritative.
// A value that cannot be represented as JSON is withheld rather than exposed.
func Redact(value any) any {
	encoded, err := json.Marshal(value)
	if err != nil {
		return redactedValue
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var copy any
	if err := decoder.Decode(&copy); err != nil {
		return redactedValue
	}
	return redactCopy(copy)
}

func redactCopy(value any) any {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			if credentialKey(key) {
				item[key] = redactedValue
			} else {
				item[key] = redactCopy(child)
			}
		}
	case []any:
		for i, child := range item {
			item[i] = redactCopy(child)
		}
	}
	return value
}

func credentialKey(key string) bool {
	// Match complete names only: e.g. rule payloads, token counts and secret
	// file/environment references must not disappear through substring matches.
	key = strings.ReplaceAll(strings.ToLower(key), "_", "-")
	switch key {
	case "authentication", "ss-config", "ssconfig", "vmess-config", "vmessconfig", "tuic-server", "tuicserver",
		"secret", "password", "passwd", "passphrase", "token", "auth-token", "authtoken",
		"access-token", "accesstoken", "refresh-token", "refreshtoken", "id-token", "idtoken",
		"api-key", "apikey", "private-key", "privatekey", "client-key", "clientkey",
		"client-secret", "clientsecret", "authorization", "proxy-authorization", "proxyauthorization",
		"credential", "credentials", "psk", "pre-shared-key", "presharedkey":
		return true
	}
	return false
}
