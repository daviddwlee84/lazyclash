package serverdeploy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type artifactTransport func(*http.Request) (*http.Response, error)

func (f artifactTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPinnedRecipeReleaseSelectionAndExplicitLatest(t *testing.T) {
	previous := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = previous })
	for _, tc := range []struct{ recipe, version, endpoint, tag, asset string }{
		{"vless-reality", "", "XTLS/Xray-core/releases/tags/v26.10.29", DefaultXrayVersion, "Xray-linux-64.zip"},
		{"legacy-vmess-ws-tls", "", "XTLS/Xray-core/releases/tags/v26.10.29", DefaultXrayVersion, "Xray-linux-64.zip"},
		{"hysteria2", "", "HyNetworks/hysteria/releases/tags/app%2Fv2.13.0", DefaultHysteriaVersion, "hysteria-linux-amd64"},
		{"vless-reality", "latest", "XTLS/Xray-core/releases/latest", "v26.11.1", "Xray-linux-64.zip"},
		{"hysteria2", "2.12.0", "HyNetworks/hysteria/releases/tags/app%2Fv2.12.0", "app/v2.12.0", "hysteria-linux-amd64"},
	} {
		t.Run(tc.recipe+"/"+tc.version, func(t *testing.T) {
			calls := 0
			http.DefaultClient = &http.Client{Transport: artifactTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != "https://api.github.com/repos/"+tc.endpoint {
					t.Fatalf("unexpected release query: %s", r.URL)
				}
				repo := "XTLS/Xray-core"
				if tc.recipe == "hysteria2" {
					repo = "HyNetworks/hysteria"
				}
				body, _ := json.Marshal(map[string]any{"tag_name": tc.tag, "assets": []any{map[string]any{"name": tc.asset, "browser_download_url": "https://github.com/" + repo + "/releases/download/" + tc.tag + "/" + tc.asset, "digest": "sha256:" + strings.Repeat("a", 64)}}})
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			})}
			artifact, err := resolveArtifact(context.Background(), Request{Recipe: tc.recipe, Backend: "native", Version: tc.version}, "amd64")
			if err != nil || artifact.Version != tc.tag || calls != 1 {
				t.Fatal(artifact, err, calls)
			}
			if tc.recipe == "hysteria2" && artifact.URL != "https://download.hysteria.network/"+tc.tag+"/"+tc.asset {
				t.Fatal("incorrect fixed binary URL")
			}
		})
	}
}
