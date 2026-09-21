package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func fixtureArchive(t *testing.T, name string, kind byte) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	body := []byte("verified replacement")
	h := &tar.Header{Name: name, Mode: 0755, Size: int64(len(body)), Typeflag: kind}
	if kind == tar.TypeSymlink {
		h.Size = 0
		h.Linkname = "outside"
	}
	if err := tw.WriteHeader(h); err != nil {
		t.Fatal(err)
	}
	if h.Size > 0 {
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestArchiveSelection(t *testing.T) {
	for _, osname := range []string{"darwin", "linux"} {
		for _, arch := range []string{"amd64", "arm64"} {
			want := "lazyclash_0.1.2_" + osname + "_" + arch + ".tar.gz"
			r := Release{Version: "v0.1.2", Assets: []string{want, "checksums.txt"}}
			got, err := releaseAsset(r, osname, arch)
			if err != nil || got != want {
				t.Fatal(got, err)
			}
			r.Assets = append(r.Assets, want)
			if _, err := releaseAsset(r, osname, arch); err == nil {
				t.Fatal("duplicate accepted")
			}
		}
	}
	for _, r := range []Release{{Version: "v0.1.2"}, {Version: "v0.1.2", Assets: []string{"checksums.txt"}}, {Version: "v0.1.2-beta"}} {
		if _, err := releaseAsset(r, "linux", "amd64"); err == nil {
			t.Fatal("incomplete release accepted")
		}
	}
	if _, err := releaseAsset(Release{Version: "v0.1.2"}, "windows", "amd64"); err == nil {
		t.Fatal("unsupported OS accepted")
	}
	if _, err := releaseAsset(Release{Version: "v0.1.2"}, "linux", "386"); err == nil {
		t.Fatal("unsupported arch accepted")
	}
}

func TestArchiveUpdateAndFailurePreservation(t *testing.T) {
	for _, failure := range []string{"", "download", "checksum", "missing checksum", "duplicate checksum", "unsafe path", "symlink", "wrong version", "wrong arch", "missing assets", "check"} {
		t.Run(failure, func(t *testing.T) {
			installation, opts := updateFixture(t)
			installation.Method = "release-asset"
			opts.inspect = func() (Installation, error) { return installation, nil }
			name := "lazyclash_0.1.2_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
			release := Release{Version: "v0.1.2", Assets: []string{name, "checksums.txt"}}
			if failure == "missing assets" {
				release.Assets = nil
			}
			opts.latest = func(context.Context) (Release, error) { return release, nil }
			opts.lookPath = func(string) (string, error) { t.Fatal("archive update requested Go"); return "", nil }
			opts.build = func(context.Context, string, string, string) error {
				t.Fatal("archive fell back to source")
				return nil
			}
			archiveName, kind := "lazyclash", byte(tar.TypeReg)
			if failure == "unsafe path" {
				archiveName = "../lazyclash"
			}
			if failure == "symlink" {
				kind = tar.TypeSymlink
			}
			archive := fixtureArchive(t, archiveName, kind)
			checksum := fmt.Sprintf("%x  %s\n", sha256.Sum256(archive), name)
			if failure == "checksum" {
				checksum = strings.Repeat("0", 64) + "  " + name
			}
			if failure == "missing checksum" {
				checksum = ""
			}
			if failure == "duplicate checksum" {
				checksum += checksum
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if failure == "check" {
					t.Error("check downloaded payload")
				}
				if r.URL.Path == "/checksums.txt" {
					io.WriteString(w, checksum)
					return
				}
				if failure == "download" {
					w.WriteHeader(502)
					return
				}
				w.Write(archive)
			}))
			defer server.Close()
			opts.download = func(ctx context.Context, r Release, stage string) error {
				return fetchArchive(ctx, server.Client(), server.URL+"/", name, stage)
			}
			opts.inspectCandidate = func(string) (Installation, error) {
				return Installation{IdentityValid: true, BuildKind: "release", Method: "release-asset", Version: "v0.1.2", GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}, nil
			}
			if failure == "wrong version" {
				opts.version = func(context.Context, string) (string, error) { return "lazyclash version v9.0.0", nil }
			}
			if failure == "wrong arch" {
				opts.inspectCandidate = func(string) (Installation, error) {
					return Installation{IdentityValid: true, BuildKind: "release", Method: "release-asset", Version: "v0.1.2", GOOS: runtime.GOOS, GOARCH: "wrong"}, nil
				}
			}
			result, err := run(context.Background(), Request{Check: failure == "check"}, nil, opts)
			if failure == "" {
				if err != nil || result.Status != "updated" {
					t.Fatal(result, err)
				}
			} else if failure == "check" {
				if err != nil || !result.CanUpgrade {
					t.Fatal(result, err)
				}
				requireOriginal(t, installation)
			} else {
				if err == nil {
					t.Fatal("failure accepted")
				}
				requireOriginal(t, installation)
			}
		})
	}
}

func TestArchiveBuildProvenance(t *testing.T) {
	for _, change := range []string{"", "dirty", "dependency", "unstable", "duplicate"} {
		info := releaseBuildInfo()
		info.Main.Version = "(devel)"
		info.Main.Sum = ""
		stamp := "v0.1.2"
		if change == "unstable" {
			stamp = "v0.1.2-beta"
		}
		flags := "-s -w -X " + ModulePath + "/internal/selfupdate.ReleaseStamp=archive-v1:" + stamp
		if change == "duplicate" {
			flags += " " + flags
		}
		info.Settings = []debug.BuildSetting{{Key: "-ldflags", Value: flags}, {Key: "vcs.modified", Value: "false"}}
		if change == "dirty" {
			info.Settings[1].Value = "true"
		}
		if change == "dependency" {
			info.Deps = []*debug.Module{{Replace: &debug.Module{Path: "../local"}}}
		}
		got := classifyBuild("/binary", "/binary", info)
		if change == "" {
			if got.Method != "release-asset" || got.Version != "v0.1.2" || got.BuildKind != "release" {
				t.Fatal(got)
			}
		} else if got.BuildKind != "development" {
			t.Fatal(change, got)
		}
	}
}

func TestRealLinkedArchiveMetadata(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "internal", "selfupdate")
	if err := os.MkdirAll(pkg, 0700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "go.mod"), []byte("module "+ModulePath+"\n\ngo 1.25.0\n"), 0600)
	os.WriteFile(filepath.Join(pkg, "stamp.go"), []byte("package selfupdate\nvar ReleaseStamp string\n"), 0600)
	mainDir := filepath.Join(root, "cmd", "lazyclash")
	os.MkdirAll(mainDir, 0700)
	os.WriteFile(filepath.Join(mainDir, "main.go"), []byte("package main\nimport (\"fmt\"; \""+ModulePath+"/internal/selfupdate\")\nfunc main(){fmt.Println(selfupdate.ReleaseStamp)}\n"), 0600)
	bin := filepath.Join(t.TempDir(), "lazyclash")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-ldflags", "-X "+ModulePath+"/internal/selfupdate.ReleaseStamp=archive-v1:v0.1.2", "-o", bin, "./cmd/lazyclash")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=", "CGO_ENABLED=0", "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, output)
	}
	got, err := InspectPath(bin)
	if err != nil || got.Method != "release-asset" || got.Version != "v0.1.2" || got.BuildKind != "release" {
		t.Fatal(got, err)
	}
}

func TestPublishedAssetInventory(t *testing.T) {
	name := "lazyclash_0.1.2_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":"v0.1.2","assets":[{"name":%q},{"name":"checksums.txt"}]}`, name)
	}))
	defer server.Close()
	release, err := fetchLatestRelease(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	got, err := releaseAsset(release, runtime.GOOS, runtime.GOARCH)
	if err != nil || got != name {
		t.Fatal(got, err)
	}
}

func TestReleaseArtifact(t *testing.T) {
	binary := os.Getenv("RELEASE_BINARY")
	if binary == "" {
		t.Skip("set RELEASE_BINARY to inspect a built native release archive executable")
	}
	version := os.Getenv("RELEASE_VERSION")
	info, err := InspectPath(binary)
	if err != nil || info.Method != "release-asset" || info.BuildKind != "release" || info.Version != version || info.GOOS != runtime.GOOS || info.GOARCH != runtime.GOARCH {
		t.Fatal(info, err)
	}
	output, err := candidateVersion(context.Background(), binary)
	if err != nil || strings.TrimSpace(output) != "lazyclash version "+version {
		t.Fatal(output, err)
	}
}
