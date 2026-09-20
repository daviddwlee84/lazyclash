package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactMasksCredentialsWithoutChangingOriginal(t *testing.T) {
	original := Object{
		"authentication": []string{"username:listener-password"},
		"ss-config":      "ss-password",
		"vmess-config":   "vmess-credential",
		"tuic-server":    Object{"token": "tuic-token", "enable": true},
		"nested":         []any{Object{"password": "nested-password", "PRIVATE_KEY": "private-key-bytes", "mode": "rule"}},
		"secret_env":     "MY_TOKEN_ENV", "secret_file": "/private/secret-file", "secretEnv": "TOKEN_REFERENCE",
		"payload": "DOMAIN-SUFFIX,token.example,private-key-group", "token-count": 4,
	}
	result := Redact(original).(map[string]any)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"listener-password", "ss-password", "vmess-credential", "tuic-token", "nested-password", "private-key-bytes"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("credential exposed: %s", secret)
		}
	}
	for _, reference := range []string{"MY_TOKEN_ENV", "/private/secret-file", "TOKEN_REFERENCE", "DOMAIN-SUFFIX,token.example,private-key-group"} {
		if !strings.Contains(string(encoded), reference) {
			t.Errorf("ordinary data/reference lost: %s", reference)
		}
	}
	if original["authentication"].([]string)[0] != "username:listener-password" {
		t.Fatal("redaction changed source credentials")
	}
	result["nested"].([]any)[0].(map[string]any)["mode"] = "direct"
	if original["nested"].([]any)[0].(Object)["mode"] != "rule" {
		t.Fatal("returned copy shares nested source state")
	}
}

func TestRedactCredentialKeyVariants(t *testing.T) {
	for _, key := range []string{
		"secret", "Password", "passwd", "passphrase", "token", "auth_token", "authToken",
		"access_token", "accessToken", "refresh-token", "refreshToken", "id_token", "idToken",
		"api-key", "apiKey", "private-key", "privateKey", "client_key", "clientKey",
		"client-secret", "clientSecret", "Authorization", "proxy-authorization", "proxyAuthorization",
		"credential", "credentials", "psk", "pre_shared_key", "preSharedKey", "tuicServer", "ssConfig", "vmessConfig",
	} {
		t.Run(key, func(t *testing.T) {
			result := Redact(map[string]any{key: "sensitive"}).(map[string]any)
			if result[key] != redactedValue {
				t.Errorf("field %q was not masked", key)
			}
		})
	}
}

func TestRedactPreservesJSONTagsAndNumericPrecision(t *testing.T) {
	value := struct {
		Secret     string `json:"-"`
		Password   string `json:"password"`
		Count      int64  `json:"count"`
		SecretFile string `json:"secret_file"`
	}{Secret: "excluded", Password: "private", Count: 9007199254740993, SecretFile: "/reference"}
	encoded, err := json.Marshal(Redact(value))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(encoded); got != `{"count":9007199254740993,"password":"[redacted]","secret_file":"/reference"}` {
		t.Fatalf("incorrect JSON representation: %s", got)
	}
	if Redact(nil) != nil {
		t.Fatal("nil was not preserved")
	}
	if Redact(func() {}) != redactedValue {
		t.Fatal("non-JSON value should be withheld")
	}
}
