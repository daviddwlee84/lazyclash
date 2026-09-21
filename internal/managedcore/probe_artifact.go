package managedcore

import "context"

// DownloadProbeArtifact reuses setup's pinned official artifact verification for
// an isolated, temporary client. It neither installs nor registers a service.
func DownloadProbeArtifact(ctx context.Context, os, arch string) (Artifact, []byte, error) {
	a, err := resolveOfficialArtifact(ctx, Request{Backend: "native", Version: DefaultVersion}, HostFacts{OS: os, Arch: arch})
	if err != nil {
		return a, nil, err
	}
	data, err := fetchOfficialArtifact(ctx, a)
	return a, data, err
}
