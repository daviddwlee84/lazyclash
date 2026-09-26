package managedcore

import (
	"context"
	"errors"
	"time"
)

const darwinVergeArtifactLimit = 96 << 20

// Official Clash Verge Rev v2.5.2 macOS arm64 disk image, pinned from the
// release metadata. The controller downloads it; the host never needs GitHub.
var darwinVergeArtifact = Artifact{Kind: "dmg", Version: WindowsVergeVersion, Name: "Clash.Verge_2.5.2_aarch64.dmg", URL: "https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v2.5.2/Clash.Verge_2.5.2_aarch64.dmg", SHA256: "94d29405980b5d1d3419dd1de485db3a234d35cef058f79dcce595e01b697219", Size: 60935420, Platform: "darwin/arm64"}

func resolveDarwinVergeArtifact(_ context.Context, r Request, h HostFacts) (Artifact, error) {
	if h.Arch != "arm64" {
		return Artifact{}, errors.New("managed macOS Verge currently supports Apple silicon (arm64)")
	}
	if r.ClientVersion != WindowsVergeVersion {
		return Artifact{}, errors.New("native Verge source ownership requires reviewed version " + WindowsVergeVersion)
	}
	if r.ArtifactSHA256 != "" && r.ArtifactSHA256 != darwinVergeArtifact.SHA256 {
		return Artifact{}, errors.New("offline artifact hash differs from the reviewed macOS Verge release")
	}
	return darwinVergeArtifact, nil
}

func fetchDarwinVergeArtifact(ctx context.Context, a Artifact) ([]byte, error) {
	if a.Kind != "dmg" || !digestPattern.MatchString(a.SHA256) || a.Size <= 0 || a.Size > darwinVergeArtifactLimit {
		return nil, errors.New("invalid macOS Verge release artifact")
	}
	data, _, err := downloadTimeout(ctx, a.URL, nil, darwinVergeArtifactLimit, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != a.Size || hashBytes(data) != a.SHA256 {
		return nil, errors.New("macOS Verge artifact size or SHA256 verification failed")
	}
	return data, nil
}
