package managedcore

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Opt-in real-artifact validation never starts a service or touches live state.
func TestOfficialNativeArtifactIsolatedValidation(t *testing.T) {
	artifactPath := os.Getenv("LAZYCLASH_TEST_NATIVE_ARTIFACT")
	if artifactPath == "" {
		t.Skip("set verified native release artifact for an isolated real-core smoke test")
	}
	artifact, err := resolveOfficialArtifact(context.Background(), Request{Backend: "native", Version: DefaultVersion}, HostFacts{OS: runtime.GOOS, Arch: runtime.GOARCH})
	if err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(artifactPath)
	if err != nil || hashBytes(archive) != artifact.SHA256 {
		t.Fatal("native artifact checksum mismatch", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	binary, err := io.ReadAll(io.LimitReader(reader, 128<<20))
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	stage, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(stage, "home")
	os.Mkdir(home, 0700)
	bin := filepath.Join(stage, "mihomo")
	if err = os.WriteFile(bin, binary, 0755); err != nil {
		t.Fatal(err)
	}
	req := Request{ID: "smoke", Backend: "native", InputKind: "links", Input: []byte("vless://123e4567-e89b-12d3-a456-426614174000@example.test:443?security=tls#fixture"), Preset: "cn-split", ControllerPort: 19090, MixedPort: 17890}
	profile, resources, _, _, err := buildProfile(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range resources {
		path := filepath.Join(home, name)
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.WriteFile(filepath.Join(home, "config.yaml"), profile, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{bin, "-t", "-d", home, "-f", filepath.Join(home, "config.yaml")}
	sandbox := ""
	switch runtime.GOOS {
	case "darwin":
		sandbox = "/usr/bin/sandbox-exec"
		policy := fmt.Sprintf("(version 1)(allow default)(deny network*)(deny file-write*)(allow file-write* (subpath %q))", stage)
		args = append([]string{"-p", policy}, args...)
	case "linux":
		sandbox, err = exec.LookPath("bwrap")
		if err != nil {
			t.Skip("bubblewrap unavailable")
		}
		args = append([]string{"--die-with-parent", "--unshare-net", "--unshare-pid", "--ro-bind", "/", "/", "--bind", stage, stage, "--dev", "/dev", "--proc", "/proc", "--"}, args...)
	default:
		t.Skip("unsupported native platform")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sandbox, args...)
	cmd.Dir = stage
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + stage}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated official core validation: %v\n%s", err, out)
	}
	if !strings.Contains(strings.ToLower(string(out)), "successful") {
		t.Logf("core accepted candidate: %s", out)
	}
}
