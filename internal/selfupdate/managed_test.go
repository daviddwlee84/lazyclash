package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/brewupgrade"
)

func managedFixture(t *testing.T, mode string) (Installation, runOptions, *int) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cellarName := "Cellar"
	if mode == "custom-cellar" {
		cellarName = "custom-packages"
	}
	rack := filepath.Join(root, cellarName, "lazyclash")
	stable := filepath.Join(root, "opt", "lazyclash")
	writeKeg := func(version string) string {
		keg := filepath.Join(rack, version)
		if err := os.MkdirAll(filepath.Join(keg, "bin"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keg, "INSTALL_RECEIPT.json"), []byte(`{"source":{"tap":"daviddwlee84/tap"}}`), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keg, "bin", "lazyclash"), []byte(version), 0755); err != nil {
			t.Fatal(err)
		}
		return keg
	}
	old := writeKeg("v0.1.1")
	if err := os.MkdirAll(filepath.Dir(stable), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(old, stable); err != nil {
		t.Fatal(err)
	}
	brew := filepath.Join(root, "brew")
	if err := os.WriteFile(brew, []byte("fake manager"), 0755); err != nil {
		t.Fatal(err)
	}
	installation := Installation{
		Executable: filepath.Join(stable, "bin", "lazyclash"), ResolvedPath: filepath.Join(old, "bin", "lazyclash"),
		Version: "v0.1.1", BuildKind: "release", IdentityValid: true, Manager: "homebrew", Method: "package-manager",
	}
	upgrades := new(int)
	opts := runOptions{
		inspect: func() (Installation, error) { return installation, nil },
		latest: func(context.Context) (Release, error) {
			t.Fatal("Homebrew route contacted GitHub")
			return Release{}, nil
		},
		build: func(context.Context, string, string, string) error {
			t.Fatal("manager route built a standalone copy")
			return nil
		},
		download: func(context.Context, Release, string) error {
			t.Fatal("manager route downloaded an archive")
			return nil
		},
		inspectCandidate: func(path string) (Installation, error) {
			data, err := os.ReadFile(path)
			return Installation{IdentityValid: true, BuildKind: "release", Version: string(data), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}, err
		},
		version: func(_ context.Context, path string) (string, error) {
			data, err := os.ReadFile(path)
			return "lazyclash version " + string(data) + "\n", err
		},
		brew: brewupgrade.Options{
			LookPath: func(name string) (string, error) {
				if name != "brew" {
					t.Fatalf("looked up %q", name)
				}
				return brew, nil
			},
			Run: func(_ context.Context, program string, args []string, progress io.Writer) (string, error) {
				if program != brew || len(args) != 2 || args[1] != "daviddwlee84/tap/lazyclash" {
					t.Fatalf("wrong manager invocation: %q %q", program, args)
				}
				switch args[0] {
				case "--cellar":
					return rack + "\n", nil
				case "--prefix":
					return stable + "\n", nil
				case "upgrade":
					*upgrades++
					if mode == "failure" {
						return "", errors.New("manager failed")
					}
					if mode == "cancel" {
						return "", context.Canceled
					}
					if mode != "noop" {
						newKeg := writeKeg("v0.1.2")
						if err := os.Remove(stable); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(newKeg, stable); err != nil {
							t.Fatal(err)
						}
						// Homebrew may remove the old keg while the old process runs.
						if err := os.RemoveAll(old); err != nil {
							t.Fatal(err)
						}
					}
					io.WriteString(progress, "manager progress\n")
					return "", nil
				default:
					t.Fatalf("unexpected manager verb %q", args[0])
					return "", nil
				}
			},
		},
	}
	return installation, opts, upgrades
}

func TestHomebrewCheckIsOfflineAndDoesNotUpgrade(t *testing.T) {
	installation, opts, upgrades := managedFixture(t, "updated")
	result, err := run(t.Context(), Request{Check: true, Force: true}, io.Discard, opts)
	if err != nil || result.Status != "checked" || !result.CanUpgrade || *upgrades != 0 {
		t.Fatalf("result=%+v err=%v calls=%d", result, err, *upgrades)
	}
	if result.UpdateAvailableKnown || result.LatestVersion != "" || result.InstalledVersion != "" {
		t.Fatalf("check invented a manager update result: %+v", result)
	}
	if len(result.Command) != 3 || !reflect.DeepEqual(result.Command[1:], []string{"upgrade", "daviddwlee84/tap/lazyclash"}) {
		t.Fatalf("wrong preview: %q", result.Command)
	}
	data, err := os.ReadFile(installation.ResolvedPath)
	if err != nil || string(data) != "v0.1.1" {
		t.Fatalf("check mutated binary: %q %v", data, err)
	}
	requireNoStage(t, installation)
}

func TestHomebrewApplyReportsStableInstalledTargetAndNoop(t *testing.T) {
	for _, mode := range []string{"updated", "noop"} {
		t.Run(mode, func(t *testing.T) {
			installation, opts, upgrades := managedFixture(t, mode)
			var progress bytes.Buffer
			result, err := run(t.Context(), Request{Force: true}, &progress, opts)
			if err != nil || *upgrades != 1 || !strings.Contains(progress.String(), "manager progress") {
				t.Fatalf("result=%+v err=%v calls=%d progress=%q", result, err, *upgrades, progress.String())
			}
			wantStatus, wantVersion := "updated", "v0.1.2"
			if mode == "noop" {
				wantStatus, wantVersion = "up-to-date", "v0.1.1"
			}
			if result.Status != wantStatus || result.InstalledVersion != wantVersion || result.InstalledPath != installation.Executable || result.LatestVersion != "" || result.UpdateAvailableKnown {
				t.Fatalf("incorrect effective installation: %+v", result)
			}
			if mode == "updated" {
				if _, err := os.Stat(installation.ResolvedPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("fixture did not remove old keg: %v", err)
				}
			}
		})
	}
}

func TestHomebrewFailureDoesNotFallBack(t *testing.T) {
	for _, mode := range []string{"failure", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			installation, opts, upgrades := managedFixture(t, mode)
			result, err := run(t.Context(), Request{}, io.Discard, opts)
			if err == nil || *upgrades != 1 || result.Status != "failed" {
				t.Fatalf("result=%+v err=%v calls=%d", result, err, *upgrades)
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
			data, readErr := os.ReadFile(installation.ResolvedPath)
			if readErr != nil || string(data) != "v0.1.1" {
				t.Fatalf("unexpected fallback: %q %v", data, readErr)
			}
			requireNoStage(t, installation)
		})
	}
}

func TestCustomHomebrewReceiptPrecedesStandaloneFallback(t *testing.T) {
	installation, opts, upgrades := managedFixture(t, "custom-cellar")
	installation.Manager, installation.Method = "", "go-install"
	opts.inspect = func() (Installation, error) { return installation, nil }
	result, err := run(t.Context(), Request{}, io.Discard, opts)
	if err != nil || result.Installation.Manager != "homebrew" || result.Status != "updated" || *upgrades != 1 {
		t.Fatalf("custom Cellar was not delegated: result=%+v err=%v calls=%d", result, err, *upgrades)
	}
}

func TestHomebrewProductVerificationBlocksMutation(t *testing.T) {
	for _, failure := range []string{"identity", "platform", "version", "control in development label"} {
		t.Run(failure, func(t *testing.T) {
			_, opts, upgrades := managedFixture(t, "updated")
			inspect := opts.inspectCandidate
			opts.inspectCandidate = func(path string) (Installation, error) {
				info, err := inspect(path)
				if failure == "identity" {
					info.IdentityValid = false
				}
				if failure == "platform" {
					info.GOARCH = "foreign"
				}
				if failure == "control in development label" {
					info.BuildKind, info.Version = "development", "dev"
				}
				return info, err
			}
			if failure == "version" {
				opts.version = func(context.Context, string) (string, error) { return "lazyclash version v9.0.0", nil }
			}
			if failure == "control in development label" {
				opts.version = func(context.Context, string) (string, error) { return "lazyclash version HEAD\tunsafe", nil }
			}
			result, err := run(t.Context(), Request{Force: true}, io.Discard, opts)
			if err == nil || result.CanUpgrade || *upgrades != 0 {
				t.Fatalf("unsafe manager apply: %+v %v calls=%d", result, err, *upgrades)
			}
		})
	}
}
