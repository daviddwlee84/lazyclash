package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

// The stamp records the selected release channel, not package ownership or an
// authenticity signature. Downloads are separately verified before execution.
func archiveVersion(info *debug.BuildInfo) string {
	if info == nil || info.Main.Replace != nil {
		return ""
	}
	for _, dep := range info.Deps {
		if dep != nil && dep.Replace != nil {
			return ""
		}
	}
	stamp := ""
	prefix := ModulePath + "/internal/selfupdate.ReleaseStamp=archive-v1:"
	for _, setting := range info.Settings {
		if setting.Key == "vcs.modified" && setting.Value != "false" {
			return ""
		}
		if setting.Key != "-ldflags" {
			continue
		}
		fields := strings.Fields(setting.Value)
		for i, field := range fields {
			value := ""
			if field == "-X" && i+1 < len(fields) {
				value = fields[i+1]
			}
			if strings.HasPrefix(field, "-X=") {
				value = strings.TrimPrefix(field, "-X=")
			}
			if strings.HasPrefix(value, prefix) {
				if stamp != "" {
					return ""
				}
				stamp = strings.TrimPrefix(value, prefix)
			}
		}
	}
	if !StableVersion(stamp) {
		return ""
	}
	return stamp
}

func releaseAsset(release Release, goos, goarch string) (string, error) {
	if !StableVersion(release.Version) || (goos != "darwin" && goos != "linux") || (goarch != "amd64" && goarch != "arm64") {
		return "", errors.New("no supported release archive for this platform")
	}
	name := "lazyclash_" + strings.TrimPrefix(release.Version, "v") + "_" + goos + "_" + goarch + ".tar.gz"
	seen := map[string]bool{}
	for _, asset := range release.Assets {
		if asset == "" || seen[asset] {
			return "", errors.New("invalid or duplicate release asset inventory")
		}
		seen[asset] = true
	}
	if !seen[name] || !seen["checksums.txt"] {
		return "", errors.New("release is missing the exact platform archive or checksums.txt; no source fallback")
	}
	return name, nil
}

func downloadRelease(ctx context.Context, release Release, stage string) error {
	name, err := releaseAsset(release, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	base := "https://github.com/daviddwlee84/lazyclash/releases/download/" + release.Version + "/"
	return fetchArchive(ctx, &http.Client{Timeout: 2 * time.Minute}, base, name, stage)
}

func readDownload(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.New("invalid release download request")
	}
	response, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("release download failed; existing executable retained")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release download returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, errors.New("release download failed or exceeded size limit")
	}
	return body, nil
}

func fetchArchive(ctx context.Context, client *http.Client, base, name, stage string) error {
	sums, err := readDownload(ctx, client, base+"checksums.txt", 1<<20)
	if err != nil {
		return err
	}
	expected := ""
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != name {
			continue
		}
		decoded, err := hex.DecodeString(fields[0])
		if expected != "" || err != nil || len(decoded) != sha256.Size {
			return errors.New("invalid or duplicate archive checksum")
		}
		expected = strings.ToLower(fields[0])
	}
	if expected == "" {
		return errors.New("checksums.txt has no exact archive entry")
	}
	archive, err := readDownload(ctx, client, base+name, 128<<20)
	if err != nil {
		return err
	}
	actual := fmt.Sprintf("%x", sha256.Sum256(archive))
	if actual != expected {
		return errors.New("release archive checksum mismatch; existing executable retained")
	}
	return extractArchive(archive, stage)
}

func extractArchive(archive []byte, stage string) error {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return errors.New("invalid release archive")
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, 256<<20))
	found := false
	for count := 0; ; count++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil || count >= 32 {
			return errors.New("invalid or excessive archive entries")
		}
		if h.Name != path.Clean(h.Name) || path.IsAbs(h.Name) || strings.Contains(h.Name, "\\") || h.Name == ".." || strings.HasPrefix(h.Name, "../") {
			return errors.New("unsafe archive path")
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return errors.New("release archive must contain regular files only")
		}
		if h.Name != "lazyclash" {
			if h.Name != "LICENSE" && h.Name != "completions/lazyclash.bash" && h.Name != "completions/lazyclash.zsh" {
				return errors.New("unexpected release archive payload")
			}
			continue
		}
		if found || h.Size <= 0 || h.Size > 128<<20 || h.Mode&0111 == 0 {
			return errors.New("invalid release executable")
		}
		found = true
		f, err := os.OpenFile(filepath.Join(stage, "lazyclash"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(f, tr, h.Size)
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil {
			return errors.New("could not stage release executable")
		}
	}
	if !found {
		return errors.New("release archive has no executable")
	}
	return nil
}
