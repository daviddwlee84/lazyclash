package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/daviddwlee84/lazyclash/internal/brewupgrade"
)

func runHomebrew(ctx context.Context, req Request, progress io.Writer, result Result, opts runOptions) (Result, error) {
	manager := opts.brew
	if manager.LookPath == nil {
		manager.LookPath = opts.lookPath
	}
	manager.Inspect = func(ctx context.Context, path string) (string, error) {
		inspect := opts.inspectCandidate
		if inspect == nil {
			inspect = InspectPath
		}
		info, err := inspect(path)
		if err != nil || !info.IdentityValid || info.GOOS != runtime.GOOS || info.GOARCH != runtime.GOARCH {
			return "", errors.New("cannot verify the Homebrew executable's lazyclash identity and platform")
		}
		version := opts.version
		if version == nil {
			version = candidateVersion
		}
		output, err := version(ctx, path)
		if err != nil {
			return "", fmt.Errorf("inspect installed lazyclash version: %w", err)
		}
		printed := strings.TrimSpace(output)
		const prefix = "lazyclash version "
		if !strings.HasPrefix(printed, prefix) {
			return "", errors.New("Homebrew executable did not identify itself as lazyclash")
		}
		printed = strings.TrimPrefix(printed, prefix)
		if !utf8.ValidString(printed) || printed == "" || len(printed) > 128 || strings.IndexFunc(printed, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 || (info.BuildKind == "release" && printed != info.Version) {
			return "", errors.New("Homebrew executable reported an unexpected lazyclash version")
		}
		return printed, nil
	}
	plan, err := brewupgrade.Prepare(ctx, result.Installation.Executable, "lazyclash", manager)
	if err != nil {
		if result.Installation.Manager == "" && errors.Is(err, brewupgrade.ErrNotManaged) {
			return result, err
		}
		result.Status, result.Reason = "unsupported", err.Error()
		if req.Check && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			return result, nil
		}
		return result, err
	}
	result.Installation.Manager, result.Installation.Method = "homebrew", "package-manager"
	result.Installation.Reason = managerInstruction("homebrew")
	result.Installation.Evidence = append(result.Installation.Evidence, "Installed keg receipt and owning brew agree on formula "+plan.Formula)
	result.CurrentVersion = plan.CurrentVersion
	result.CanUpgrade = true
	result.Command = plan.Command()
	result.Reason = "Homebrew determines the available formula version; --check does not run brew upgrade"
	if req.Check {
		return result, nil
	}
	// --force never becomes brew reinstall or bypasses Homebrew pin policy.
	outcome, err := plan.Apply(ctx, progress)
	if err != nil {
		result.Status = "failed"
		return result, err
	}
	result.InstalledVersion, result.InstalledPath = outcome.Version, outcome.Path
	result.Reason = ""
	if outcome.Changed {
		result.Status = "updated"
	} else {
		result.Status = "up-to-date"
		result.Reason = "Homebrew kept the installed version unchanged; its formula may already be current or pinned"
	}
	return result, nil
}
