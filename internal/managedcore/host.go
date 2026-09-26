package managedcore

import (
	"bytes"
	"compress/zlib"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/sourceowner"
	"strconv"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/networkcheck"
)

//go:embed host.py
var hostScript string

type hostRequest struct {
	DockerArchive       string                        `json:"docker_archive,omitempty"`
	DockerArchiveSHA256 string                        `json:"docker_archive_sha256,omitempty"`
	ConfigSHA256        string                        `json:"config_sha256,omitempty"`
	Source              *configwork.HostRequest       `json:"source,omitempty"`
	Op                  string                        `json:"op"`
	ID                  string                        `json:"id"`
	Root                string                        `json:"root,omitempty"`
	Backend             string                        `json:"backend"`
	Version             string                        `json:"version,omitempty"`
	ServiceScope        string                        `json:"service_scope"`
	DockerContext       string                        `json:"docker_context,omitempty"`
	DockerEndpoint      string                        `json:"docker_endpoint,omitempty"`
	Ports               []int                         `json:"ports,omitempty"`
	ProxyListen         string                        `json:"proxy_listen,omitempty"`
	ProxyUDP            bool                          `json:"proxy_udp,omitempty"`
	OwnerToken          string                        `json:"owner_token,omitempty"`
	Expected            string                        `json:"expected,omitempty"`
	Profile             []byte                        `json:"profile,omitempty"`
	ProfileSHA256       string                        `json:"profile_sha256,omitempty"`
	Resources           map[string][]byte             `json:"resources,omitempty"`
	Artifact            []byte                        `json:"artifact,omitempty"`
	ArtifactSHA256      string                        `json:"artifact_sha256,omitempty"`
	Image               string                        `json:"image,omitempty"`
	Platform            string                        `json:"platform,omitempty"`
	Network             NetworkOptions                `json:"network"`
	SystemProxy         *networkcheck.SystemProxyPlan `json:"system_proxy,omitempty"`
	Boot                bool                          `json:"boot"`
	GuardRef            string                        `json:"guard_ref,omitempty"`
	PreviousGuardRef    string                        `json:"previous_guard_ref,omitempty"`
	AckToken            string                        `json:"ack_token,omitempty"`
	FixtureRoot         string                        `json:"fixture_root,omitempty"`
}
type hostResponse struct {
	Profile   []byte                        `json:"profile,omitempty"`
	Resources map[string][]byte             `json:"resources,omitempty"`
	Source    configwork.HostResponse       `json:"source,omitempty"`
	ProxyPlan *networkcheck.SystemProxyPlan `json:"-"`
	Facts     HostFacts                     `json:"facts"`
	Manifest  map[string]any                `json:"manifest"`
	Digest    string                        `json:"digest"`
	Status    string                        `json:"status"`
	Running   bool                          `json:"running"`
	Error     string                        `json:"error"`
	ErrorKind string                        `json:"error_kind,omitempty"`
	AckToken  string                        `json:"ack_token,omitempty"`
	GuardRef  string                        `json:"guard_ref,omitempty"`
	Deadline  int64                         `json:"deadline,omitempty"`
}

func fullHostScript() string {
	defs, _, ok := strings.Cut(configwork.SourceHostScript(), "\ntry:\n    request=json.load(sys.stdin)")
	if !ok {
		panic("source helper entrypoint changed")
	}
	resourceDefs, _, ok := strings.Cut(configwork.ResourceHostScript(), "# RESOURCE_ENTRYPOINT")
	if !ok {
		panic("resource helper entrypoint changed")
	}
	return compactHostScript("source_api={}\nexec(" + strconv.Quote(defs) + ",source_api)\nresource_api={}\nexec(" + strconv.Quote(resourceDefs) + ",resource_api)\n" + networkGuardPrelude(hostScript) + hostScript)
}

func callHost(ctx context.Context, host string, privileged bool, request hostRequest, opts Options) (hostResponse, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return hostResponse{}, errors.New("cannot encode managed request")
	}
	if len(data) > 32<<20 {
		response := hostResponse{}
		if request.Op == "install" {
			response.Status = "not_installed"
		}
		return response, errors.New("managed transfer exceeds 32 MiB; use a smaller cached profile/resource bundle")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	var output []byte
	if opts.Execute != nil {
		output, err = opts.Execute(ctx, host, privileged, data)
	} else if privileged {
		output, err = runPrivileged(ctx, host, data, opts)
	} else {
		output, err = connection.ExecutePython(ctx, host, fullHostScript(), data, 32<<20)
	}
	if err != nil {
		return hostResponse{}, err
	}
	var response hostResponse
	marker := "LAZYCLASH_MANAGED_RESULT="
	found := false
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if at := strings.Index(line, marker); at >= 0 {
			raw, e := base64.StdEncoding.DecodeString(strings.TrimSpace(line[at+len(marker):]))
			if e == nil && json.Unmarshal(raw, &response) == nil {
				found = true
			}
		}
	}
	if !found && json.Unmarshal(output, &response) != nil {
		return response, errors.New("managed host returned an invalid response")
	}
	if response.Error != "" {
		if response.ErrorKind == "unavailable" {
			return response, fmt.Errorf("%w: %s", sourceowner.ErrUnavailable, response.Error)
		}
		return response, fmt.Errorf("managed core: %s", response.Error)
	}
	return response, nil
}

const stagePrivilegedScript = `import hashlib,json,os,pathlib,sys,tempfile
data=sys.stdin.buffer.read(32*1024*1024+1)
if len(data)>32*1024*1024: raise RuntimeError('request too large')
root=pathlib.Path.home()/'.cache/lazyclash/managed-requests'
root.mkdir(parents=True,exist_ok=True,mode=0o700)
if root.is_symlink() or root.stat().st_uid!=os.getuid(): raise RuntimeError('unsafe staging root')
fd,path=tempfile.mkstemp(prefix='request-',suffix='.json',dir=root)
with os.fdopen(fd,'wb') as output: output.write(data)
os.chmod(path,0o600)
json.dump({'path':path,'sha256':hashlib.sha256(data).hexdigest()},sys.stdout)
`
const cleanPrivilegedScript = `import json,os,pathlib,stat,sys
request=json.load(sys.stdin);path=pathlib.Path(request['path'])
root=pathlib.Path.home()/'.cache/lazyclash/managed-requests'
if path.parent==root and path.name.startswith('request-'):
 try:
  info=path.lstat()
  if stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid():path.unlink()
 except FileNotFoundError:pass
`

// ErrSudoRefused reports that native sudo declined noninteractive use and no
// terminal was available. The staged request was never executed.
var ErrSudoRefused = errors.New("administrator authorization requires a native terminal or existing noninteractive sudo policy")

func runPrivileged(ctx context.Context, host string, data []byte, opts Options) ([]byte, error) {
	return runPrivilegedScript(ctx, host, fullHostScript(), data, opts)
}

func runPrivilegedScript(ctx context.Context, host, script string, data []byte, opts Options) ([]byte, error) {
	output, err := connection.ExecutePython(ctx, host, stagePrivilegedScript, data, 8192)
	if err != nil {
		return nil, err
	}
	var staged struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}
	if json.Unmarshal(output, &staged) != nil || staged.SHA256 != hashBytes(data) {
		return nil, errors.New("privileged request staging failed verification")
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		body, _ := json.Marshal(map[string]string{"path": staged.Path})
		_, _ = connection.ExecutePython(cleanupCtx, host, cleanPrivilegedScript, body, 1024)
	}()
	batch, err := connection.ManagedPrivilegedBatchCommand(ctx, host, script, staged.Path, staged.SHA256)
	if err != nil {
		return nil, err
	}
	var batchOutput boundedOutput
	batchOutput.limit = 32 << 20
	batch.Stdout = &batchOutput
	var batchError boundedOutput
	batchError.limit = 8192
	batch.Stderr = &batchError
	if err = batch.Run(); err == nil {
		return batchOutput.Bytes(), nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// The protocol prints a result even when the operation fails. A result means
	// it was executed and must never be silently retried as an auth failure.
	if strings.Contains(batchOutput.String(), "LAZYCLASH_MANAGED_RESULT=") {
		return batchOutput.Bytes(), nil
	}
	message := strings.ToLower(batchError.String())
	if !strings.Contains(message, "a password is required") && !strings.Contains(message, "a terminal is required") && !strings.Contains(message, "no tty present") {
		return nil, errors.New("privileged host result is unconfirmed; inspect before retrying")
	}
	if opts.Foreground == nil {
		return nil, ErrSudoRefused
	}

	cmd, err := connection.ManagedPrivilegedCommand(ctx, host, script, staged.Path, staged.SHA256)
	if err != nil {
		return nil, err
	}
	var captured boundedOutput
	captured.limit = 32 << 20
	cmd.Stdout = &captured
	if err = opts.Foreground(cmd); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("privileged operation was canceled or failed; inspect the receipt and host state")
	}
	if captured.Len() > 32<<20 {
		return nil, errors.New("privileged response exceeded its output limit")
	}
	return captured.Bytes(), nil
}

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("managed host output limit exceeded")
	}
	return b.Buffer.Write(p)
}

// Constant helpers are compressed only to stay below Linux's single-argument
// limit. Request data remains separate and is never evaluated as code.
func compactHostScript(script string) string {
	var data bytes.Buffer
	writer := zlib.NewWriter(&data)
	_, _ = writer.Write([]byte(script))
	_ = writer.Close()
	command := "import base64,zlib;exec(zlib.decompress(base64.b64decode(" + strconv.Quote(base64.StdEncoding.EncodeToString(data.Bytes())) + ")))"
	if len(command) > 60<<10 {
		panic("constant managed helper exceeds portable command limit")
	}
	return command
}
