package managedcore

import (
	"context"
	"errors"
)

var windowsPinnedAssets = map[string]Artifact{
	"mihomo": {Kind: "zip", Version: DefaultVersion, Name: "mihomo-windows-amd64-compatible-v1.19.31.zip", URL: "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.31/mihomo-windows-amd64-compatible-v1.19.31.zip", SHA256: "93d14e9a13b49b2f2d256202d02cc8d14a7c4695edf084cae0f941986bc9c218", Size: 22460803, Platform: "windows/amd64"},
	"verge":  {Kind: "nsis", Version: WindowsVergeVersion, Name: "Clash.Verge_2.5.2_x64-setup.exe", URL: "https://github.com/clash-verge-rev/clash-verge-rev/releases/download/v2.5.2/Clash.Verge_2.5.2_x64-setup.exe", SHA256: "ba42f00b1082e352352080170fe86ae411bcc854cb13f1b8bebc9025e8a7cbf4", Size: 46964366, Platform: "windows/amd64"},
}

func resolveWindowsArtifact(_ context.Context, r Request, h HostFacts) (Artifact, error) {
	if h.Arch != "amd64" {
		return Artifact{}, errors.New("Windows managed client artifacts currently support amd64")
	}
	if r.Client == "mihomo" && r.Version != DefaultVersion {
		return Artifact{}, errors.New("choose the reviewed Windows Mihomo version " + DefaultVersion)
	}
	if r.Client == "verge" && r.ClientVersion != WindowsVergeVersion {
		return Artifact{}, errors.New("native Verge source ownership requires reviewed version " + WindowsVergeVersion)
	}
	a, ok := windowsPinnedAssets[r.Client]
	if !ok {
		return Artifact{}, errors.New("unsupported Windows client artifact")
	}
	if r.ArtifactSHA256 != "" && r.ArtifactSHA256 != a.SHA256 {
		return Artifact{}, errors.New("offline artifact hash differs from the reviewed Windows release")
	}
	return a, nil
}
func fetchWindowsArtifact(ctx context.Context, a Artifact) ([]byte, error) {
	if (a.Kind != "zip" && a.Kind != "nsis") || !digestPattern.MatchString(a.SHA256) || a.Size <= 0 || a.Size > 64<<20 {
		return nil, errors.New("invalid Windows release artifact")
	}
	data, _, err := download(ctx, a.URL, nil, 64<<20)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != a.Size || hashBytes(data) != a.SHA256 {
		return nil, errors.New("Windows artifact size or SHA256 verification failed")
	}
	return data, nil
}
