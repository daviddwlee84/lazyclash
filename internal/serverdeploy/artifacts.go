package serverdeploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var versionPattern = regexp.MustCompile(`^[v]?[0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9]+)*$`)

// resolveArtifact resolves immutable upstream artifacts at review time. GitHub
// asset digests and OCI manifests are pinned before any remote mutation.
func resolveArtifact(ctx context.Context, r Request, arch string) (Artifact, error) {
	if arch != "amd64" && arch != "arm64" {
		return Artifact{}, errors.New("server architecture must be amd64 or arm64")
	}
	repo, tag, asset := "XTLS/Xray-core", r.Version, "Xray-linux-64.zip"
	if arch == "arm64" {
		asset = "Xray-linux-arm64-v8a.zip"
	}
	if r.Recipe == "hysteria2" {
		repo, asset = "HyNetworks/hysteria", "hysteria-linux-"+arch
		if tag != "" && tag != "latest" {
			tag = "app/v" + strings.TrimPrefix(strings.TrimPrefix(tag, "app/"), "v")
		}
	} else if tag != "" && tag != "latest" {
		tag = "v" + strings.TrimPrefix(tag, "v")
	}
	endpoint := "https://api.github.com/repos/" + repo + "/releases/latest"
	if tag != "" && tag != "latest" {
		endpoint = "https://api.github.com/repos/" + repo + "/releases/tags/" + url.PathEscape(tag)
	}
	var release struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name   string `json:"name"`
			URL    string `json:"browser_download_url"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	body, _, err := getArtifact(ctx, endpoint, nil, 4<<20)
	if err != nil {
		return Artifact{}, errors.New("cannot resolve the official release; retry or specify a published version")
	}
	if json.Unmarshal(body, &release) != nil || release.Tag == "" {
		return Artifact{}, errors.New("official release response is invalid")
	}
	a := Artifact{Version: release.Tag, Arch: arch, Source: endpoint}
	for _, v := range release.Assets {
		if v.Name == asset {
			a.URL, a.SHA256 = v.URL, strings.TrimPrefix(v.Digest, "sha256:")
			break
		}
	}
	if !shaPattern.MatchString(a.SHA256) || !strings.HasPrefix(a.URL, "https://github.com/"+repo+"/releases/download/") {
		return Artifact{}, errors.New("official release is missing a SHA256-pinned architecture asset")
	}
	if r.Recipe == "hysteria2" {
		// The project's official download service serves versioned binaries;
		// verify against the same GitHub release digest at installation time.
		a.URL = "https://download.hysteria.network/" + a.Version + "/" + asset
	}
	if r.Backend == "compose" {
		registry, imageRepo, tag := "ghcr.io", "xtls/xray-core", strings.TrimPrefix(a.Version, "v")
		if r.Recipe == "hysteria2" {
			registry, imageRepo, tag = "registry-1.docker.io", "tobyxdd/hysteria", strings.TrimPrefix(a.Version, "app/")
		}
		a.Image, err = resolveImage(ctx, registry, imageRepo, tag)
		if err != nil {
			return Artifact{}, err
		}
		if r.Recipe == "legacy-vmess-ws-tls" {
			a.NginxImage, err = resolveImage(ctx, "registry-1.docker.io", "library/nginx", "stable-alpine")
			if err != nil {
				return Artifact{}, err
			}
		}
	}
	return a, nil
}

func resolveImage(ctx context.Context, registry, repo, tag string) (string, error) {
	authURL := "https://ghcr.io/token?service=ghcr.io&scope=" + url.QueryEscape("repository:"+repo+":pull")
	if registry == "registry-1.docker.io" {
		authURL = "https://auth.docker.io/token?service=registry.docker.io&scope=" + url.QueryEscape("repository:"+repo+":pull")
	}
	body, _, err := getArtifact(ctx, authURL, nil, 1<<20)
	if err != nil {
		return "", errors.New("cannot obtain public registry download token")
	}
	var token struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(body, &token) != nil || token.Token == "" {
		return "", errors.New("invalid registry response")
	}
	headers := map[string]string{"Authorization": "Bearer " + token.Token, "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"}
	body, h, err := getArtifact(ctx, "https://"+registry+"/v2/"+repo+"/manifests/"+url.PathEscape(tag), headers, 4<<20)
	if err != nil {
		return "", errors.New("cannot resolve the official container image tag to an immutable digest")
	}
	digest := strings.TrimPrefix(h.Get("Docker-Content-Digest"), "sha256:")
	sum := sha256.Sum256(body)
	if !shaPattern.MatchString(digest) || digest != hex.EncodeToString(sum[:]) {
		return "", errors.New("container manifest digest verification failed")
	}
	if registry == "registry-1.docker.io" {
		registry = "docker.io"
	}
	return registry + "/" + repo + "@sha256:" + digest, nil
}

func getArtifact(ctx context.Context, address string, headers map[string]string, limit int64) ([]byte, http.Header, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "lazyclash-serverdeploy")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, errors.New("upstream request failed")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > limit {
		return nil, nil, errors.New("upstream response exceeds limit")
	}
	return data, resp.Header, nil
}
