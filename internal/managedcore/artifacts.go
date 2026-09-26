package managedcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var stableVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Official release asset metadata pinned when this release was prepared. These
// are compressed download hashes, not hashes of an arbitrary local executable.
var defaultAssets = map[string]Artifact{
	"darwin/arm64": {Name: "mihomo-darwin-arm64-v1.19.31.gz", SHA256: "d131f44b3deb2a8356f7ac75048ad67a10d53243323951c4f3cda7b672922963", Size: 20701178},
	"darwin/amd64": {Name: "mihomo-darwin-amd64-compatible-v1.19.31.gz", SHA256: "fb6fca0e105b4310a21eaacd3a8d3853d3d8b87fa4c69737bea52a30a435aac7", Size: 22244332},
	"linux/arm64":  {Name: "mihomo-linux-arm64-v1.19.31.gz", SHA256: "9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4", Size: 20757911},
	"linux/amd64":  {Name: "mihomo-linux-amd64-compatible-v1.19.31.gz", SHA256: "04cf9f09671704f839ddbee2e93069dc831a4123a75281e725d1d96ab9ac1afc", Size: 22821836},
}

func resolveOfficialArtifact(ctx context.Context, request Request, host HostFacts) (Artifact, error) {
	if !stableVersion.MatchString(request.Version) {
		return Artifact{}, errors.New("choose an exact stable Mihomo version (vMAJOR.MINOR.PATCH)")
	}
	if request.Backend == "docker" {
		return resolveDockerImage(ctx, request.Version, host.DockerArch)
	}
	platform := host.OS + "/" + host.Arch
	asset, ok := defaultAssets[platform]
	if !ok {
		return Artifact{}, errors.New("managed native cores support macOS/Linux amd64 and arm64")
	}
	asset.Kind, asset.Version, asset.Platform = "gzip", request.Version, platform
	if request.Version != DefaultVersion {
		asset.Name = strings.ReplaceAll(asset.Name, DefaultVersion, request.Version)
		endpoint := "https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/" + request.Version
		data, _, err := download(ctx, endpoint, nil, 2<<20)
		if err != nil {
			return Artifact{}, err
		}
		var release struct {
			Tag        string `json:"tag_name"`
			Draft      bool   `json:"draft"`
			Prerelease bool   `json:"prerelease"`
			Assets     []struct {
				Name, Digest string
				Size         int64
				URL          string `json:"browser_download_url"`
			} `json:"assets"`
		}
		if json.Unmarshal(data, &release) != nil || release.Tag != request.Version || release.Draft || release.Prerelease {
			return Artifact{}, errors.New("official release metadata is not the requested stable version")
		}
		found := false
		for _, candidate := range release.Assets {
			if candidate.Name == asset.Name {
				asset.SHA256 = strings.TrimPrefix(candidate.Digest, "sha256:")
				asset.Size = candidate.Size
				found = true
				break
			}
		}
		if !found || !digestPattern.MatchString(asset.SHA256) || asset.Size <= 0 || asset.Size > 64<<20 {
			return Artifact{}, errors.New("official platform asset is missing a usable SHA-256 digest or size")
		}
	}
	asset.URL = "https://github.com/MetaCubeX/mihomo/releases/download/" + request.Version + "/" + asset.Name
	if request.ArtifactSHA256 != "" && request.ArtifactSHA256 != asset.SHA256 {
		return Artifact{}, errors.New("provided artifact hash does not match official release metadata")
	}
	return asset, nil
}

func fetchOfficialArtifact(ctx context.Context, artifact Artifact) ([]byte, error) {
	if artifact.Kind != "gzip" || !digestPattern.MatchString(artifact.SHA256) {
		return nil, errors.New("invalid downloadable artifact")
	}
	data, _, err := download(ctx, artifact.URL, nil, 64<<20)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != artifact.Size || hashBytes(data) != artifact.SHA256 {
		return nil, errors.New("downloaded Mihomo artifact failed size/SHA-256 verification")
	}
	return data, nil
}

func resolveDockerImage(ctx context.Context, version, arch string) (Artifact, error) {
	if arch == "x86_64" {
		arch = "amd64"
	}
	if arch == "aarch64" {
		arch = "arm64"
	}
	if arch != "amd64" && arch != "arm64" {
		return Artifact{}, errors.New("managed Docker cores require Linux amd64 or arm64 images")
	}
	if version == DefaultVersion {
		configHash := map[string]string{"amd64": "ab5d4cf7e192b941f7a238bdb2450d7437d3499b51da1c13669945ba1a138529", "arm64": "339420029f245efd9e92e5df60c4a87922c9b09dbb5ba24b7f22f25af85056ad"}[arch]
		digest := "739edd73a352d6beb82fad6790ef9d417a4d6f061584cc3cab1bd4536d1c60e5"
		return Artifact{Kind: "image", Version: version, Name: "metacubex/mihomo:" + version, Image: "metacubex/mihomo@sha256:" + digest, SHA256: digest, ConfigSHA256: configHash, Platform: "linux/" + arch}, nil
	}
	q := url.Values{"service": {"registry.docker.io"}, "scope": {"repository:metacubex/mihomo:pull"}}
	data, _, err := download(ctx, "https://auth.docker.io/token?"+q.Encode(), nil, 64<<10)
	if err != nil {
		return Artifact{}, err
	}
	var token struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(data, &token) != nil || token.Token == "" {
		return Artifact{}, errors.New("Docker registry authentication response is invalid")
	}
	headers := http.Header{"Authorization": {"Bearer " + token.Token}, "Accept": {"application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"}}
	data, response, err := download(ctx, "https://registry-1.docker.io/v2/metacubex/mihomo/manifests/"+version, headers, 4<<20)
	if err != nil {
		return Artifact{}, err
	}
	digest := strings.TrimPrefix(response.Get("Docker-Content-Digest"), "sha256:")
	if !digestPattern.MatchString(digest) || hashBytes(data) != digest {
		return Artifact{}, errors.New("Docker manifest failed digest verification")
	}
	var manifest struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Manifests []struct {
			Digest   string                            `json:"digest"`
			Platform struct{ OS, Architecture string } `json:"platform"`
		} `json:"manifests"`
	}
	if json.Unmarshal(data, &manifest) != nil {
		return Artifact{}, errors.New("Docker manifest is invalid")
	}
	if len(manifest.Manifests) > 0 {
		found := false
		for _, m := range manifest.Manifests {
			if m.Platform.OS == "linux" && m.Platform.Architecture == arch {
				found = true
				child, _, e := download(ctx, "https://registry-1.docker.io/v2/metacubex/mihomo/manifests/"+m.Digest, headers, 4<<20)
				if e != nil {
					return Artifact{}, e
				}
				if hashBytes(child) != strings.TrimPrefix(m.Digest, "sha256:") {
					return Artifact{}, errors.New("Docker platform manifest digest mismatch")
				}
				var platformManifest struct {
					Config struct {
						Digest string `json:"digest"`
					} `json:"config"`
				}
				if json.Unmarshal(child, &platformManifest) != nil {
					return Artifact{}, errors.New("invalid Docker platform manifest")
				}
				manifest.Config = platformManifest.Config
			}
		}
		if !found {
			return Artifact{}, errors.New("official Docker image does not provide the requested platform")
		}
	}
	if !digestPattern.MatchString(strings.TrimPrefix(manifest.Config.Digest, "sha256:")) {
		return Artifact{}, errors.New("Docker platform config lacks a verified digest")
	}
	return Artifact{ConfigSHA256: strings.TrimPrefix(manifest.Config.Digest, "sha256:"), Kind: "image", Version: version, Name: "metacubex/mihomo:" + version, Image: "metacubex/mihomo@sha256:" + digest, SHA256: digest, Platform: "linux/" + arch}, nil
}

func download(ctx context.Context, endpoint string, headers http.Header, limit int64) ([]byte, http.Header, error) {
	return downloadTimeout(ctx, endpoint, headers, limit, 45*time.Second)
}

func downloadTimeout(ctx context.Context, endpoint string, headers http.Header, limit int64, timeout time.Duration) ([]byte, http.Header, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, errors.New("invalid official artifact request")
	}
	request.Header.Set("User-Agent", "lazyclash-managed-core")
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	client := *downloadHTTPClient(ctx)
	// Large release assets (a Verge dmg) need longer than the default client's
	// whole-request limit; the context deadline still bounds the transfer.
	if client.Timeout != 0 && client.Timeout < timeout {
		client.Timeout = timeout
	}
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, errors.New("official artifact request failed; inspect connectivity or use a verified offline artifact")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("official artifact request returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "Client.Timeout") {
			return nil, nil, errors.New("official artifact download timed out before completion; retry or pass a verified --artifact file")
		}
		return nil, nil, errors.New("official artifact response could not be read (connection interrupted); retry or pass a verified --artifact file")
	}
	if int64(len(data)) > limit {
		return nil, nil, errors.New("official artifact response exceeded its size limit")
	}
	return data, response.Header, nil
}

func hashBytes(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
