package rulework

import (
	"context"
	"errors"
	"github.com/daviddwlee84/lazyclash/internal/config"
)

// Shared host primitives retain the rule workbench's bounded private file I/O
// and OS-isolated validation; ownership is established by each caller separately.
type HostFile = hostFile
type FileGuard = fileGuard

// SourceHostScript is fixed application code, never supplied by a user request.
// Managed owners may run it after enforcing ownership within their privileged
// host protocol; request fields remain data on stdin.
func SourceHostScript() string { return hostScript }

func ReadHostFile(ctx context.Context, host, path string) (HostFile, error) {
	return readHost(ctx, host, path)
}
func CheckHostFiles(ctx context.Context, host string, guards []FileGuard) error {
	_, e := hostCall(ctx, host, hostRequest{Op: "check", Guards: guards})
	return e
}
func WriteHostFile(ctx context.Context, host, path string, data []byte, guards []FileGuard) (HostFile, error) {
	return hostCall(ctx, host, hostRequest{Op: "write", Path: path, Data: data, Guards: guards})
}

// ValidationSandbox selects an explicitly bound existing Docker image when native
// OS namespaces are unavailable. Empty fields retain native OS isolation.
type ValidationSandbox struct {
	DockerHost string
	Image      string
}

func ValidateSourceCandidate(ctx context.Context, t config.Target, data []byte, version string) error {
	return ValidateSourceCandidateWithSandbox(ctx, t, data, version, ValidationSandbox{})
}

func ValidateSourceCandidateWithSandbox(ctx context.Context, t config.Target, data []byte, version string, sandbox ValidationSandbox) error {
	if t.RuleSource == nil || t.RuleSource.Kind != "mihomo" {
		return errors.New("standalone validation requires a bound Mihomo binary and home")
	}
	return validateCandidateWithSandbox(ctx, t, data, version, sandbox)
}
