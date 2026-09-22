package managedcore

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/connection"
)

const WindowsVergeVersion = "v2.5.2"

//go:embed windows_host.ps1
var windowsHostScript string

type WindowsProxyState struct {
	Flags         uint32 `json:"flags"`
	PACConfigured bool   `json:"pac_configured,omitempty"`
	Enabled       int    `json:"enabled"`
	Server        string `json:"server"`
	Override      string `json:"override"`
	AutoConfigURL string `json:"auto_config_url"`
}
type WindowsProcess struct {
	PID     int    `json:"pid"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Created string `json:"created"`
	UserSID string `json:"user_sid"`
	Session int    `json:"session"`
}
type windowsRequest struct {
	VerifyGenerated   bool                    `json:"verify_generated,omitempty"`
	TransferOperation string                  `json:"transfer_operation,omitempty"`
	TransferID        string                  `json:"transfer_id,omitempty"`
	TransferSHA256    string                  `json:"transfer_sha256,omitempty"`
	TransferSize      int64                   `json:"transfer_size,omitempty"`
	TransferPath      string                  `json:"transfer_path,omitempty"`
	AppliedBypass     string                  `json:"applied_bypass"`
	HostOS            string                  `json:"host_os"`
	Op                string                  `json:"op"`
	ID                string                  `json:"id"`
	Client            string                  `json:"client"`
	ClientVersion     string                  `json:"client_version,omitempty"`
	Root              string                  `json:"root,omitempty"`
	AppRoot           string                  `json:"app_root,omitempty"`
	UserSID           string                  `json:"user_sid,omitempty"`
	OwnerToken        string                  `json:"owner_token,omitempty"`
	Expected          string                  `json:"expected,omitempty"`
	ProfileUID        string                  `json:"profile_uid,omitempty"`
	ControllerPort    int                     `json:"controller_port"`
	MixedPort         int                     `json:"mixed_port"`
	Boot              bool                    `json:"boot"`
	SystemProxy       bool                    `json:"system_proxy"`
	ProfileDocument   map[string]any          `json:"profile_document,omitempty"`
	Profile           []byte                  `json:"profile,omitempty"`
	Resources         map[string][]byte       `json:"resources,omitempty"`
	Files             map[string][]byte       `json:"files,omitempty"`
	Selections        map[string]string       `json:"selections,omitempty"`
	Artifact          []byte                  `json:"artifact,omitempty"`
	ArtifactSHA256    string                  `json:"artifact_sha256,omitempty"`
	ArtifactKind      string                  `json:"artifact_kind,omitempty"`
	CoreVersion       string                  `json:"core_version,omitempty"`
	Source            *configwork.HostRequest `json:"source,omitempty"`
	BeforeProxy       *WindowsProxyState      `json:"before_proxy,omitempty"`
	BeforeCFW         []WindowsProcess        `json:"before_cfw,omitempty"`
	Helper            []byte                  `json:"helper,omitempty"`
}
type windowsResponse struct {
	TransferPath     string                  `json:"transfer_path,omitempty"`
	TransferVerified bool                    `json:"transfer_verified,omitempty"`
	Facts            HostFacts               `json:"facts"`
	Status           string                  `json:"status"`
	Digest           string                  `json:"digest"`
	Running          bool                    `json:"running"`
	CoreVersion      string                  `json:"core_version,omitempty"`
	CorePath         string                  `json:"core_path,omitempty"`
	AppPath          string                  `json:"app_path,omitempty"`
	Source           configwork.HostResponse `json:"source"`
	Manifest         map[string]any          `json:"manifest,omitempty"`
	Error            string                  `json:"error,omitempty"`
}

func callWindows(ctx context.Context, host string, r windowsRequest, opts Options) (windowsResponse, error) {
	r.HostOS = "windows"
	raw, err := json.Marshal(r)
	if err != nil {
		return windowsResponse{}, err
	}
	if len(raw) > 256<<10 && r.TransferID == "" {
		return transferWindowsRequest(ctx, host, r, raw, opts)
	}
	timeout := 45 * time.Second
	if r.Op == "install" || r.Op == "dispatch-transfer" || r.Op == "verify-transfer" {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var out []byte
	if opts.Execute != nil {
		out, err = opts.Execute(ctx, host, false, raw)
	} else {
		limit := 32 << 20
		if r.Op == "source" && r.Source != nil && r.Source.Op == "read" {
			limit = 48 << 20
		}
		out, err = connection.ExecutePowerShell(ctx, host, windowsHostScript, raw, limit)
	}
	if err != nil {
		return windowsResponse{}, err
	}
	var response windowsResponse
	if json.Unmarshal(out, &response) != nil {
		return response, errors.New("Windows managed helper returned an invalid response")
	}
	if response.Error != "" {
		return response, fmt.Errorf("Windows managed core: %s", response.Error)
	}
	return response, nil
}
func winJoin(base string, parts ...string) string {
	return strings.TrimRight(strings.ReplaceAll(base, `\`, "/"), "/") + "/" + strings.Join(parts, "/")
}
func windowsHostRequest(instance Instance, request Request, op string) windowsRequest {
	return windowsRequest{Op: op, ID: instance.ID, Client: instance.Client, ClientVersion: instance.ClientVersion, Root: instance.Root, AppRoot: instance.AppRoot, UserSID: instance.UserSID, OwnerToken: instance.OwnerToken, Expected: instance.Digest, ProfileUID: instance.ProfileUID, ControllerPort: request.ControllerPort, MixedPort: request.MixedPort, Boot: instance.Boot, SystemProxy: instance.Network.SystemProxy, CoreVersion: instance.Version}
}

// Only a simple loopback proxy endpoint is suitable for a public preview. PAC
// URLs and arbitrary registry strings remain exclusively in the private plan.
func windowsPublicProxy(before *WindowsProxyState) *WindowsProxyState {
	if before == nil {
		return nil
	}
	result := &WindowsProxyState{Enabled: before.Enabled, Flags: before.Flags, PACConfigured: before.AutoConfigURL != ""}
	if before.Server != "" {
		result.Server = "[configured; private]"
	}
	host, port, err := net.SplitHostPort(before.Server)
	n, parseErr := strconv.Atoi(port)
	ip := net.ParseIP(host)
	if err == nil && parseErr == nil && n > 0 && n <= 65535 && (host == "localhost" || ip != nil && ip.IsLoopback()) {
		result.Server = before.Server
	}
	return result
}

// Pinned v2.5.2 core/sysopt.rs fallback when the reviewed prior bypass is empty.
const windowsVergeDefaultBypass = "localhost;127.*;192.168.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;<local>"

func windowsAppliedBypass(client string, before *WindowsProxyState) string {
	if before != nil && before.Override != "" {
		return before.Override
	}
	if client == "verge" {
		return windowsVergeDefaultBypass
	}
	return ""
}
