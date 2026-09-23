// Package managedrpi delegates mutations to the RPi-ImmortalWrt transaction owner.
package managedrpi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

const Kind = "rpi-immortalwrt"
const Profile = "rpi-immortalwrt:profile"

type Identity struct {
	ProfileSHA256       string `json:"profile_sha256"`
	NetworkBundleSHA256 string `json:"network_bundle_sha256"`
	BootID              string `json:"boot_id"`
	CoreIdentity        string `json:"core_identity"`
}
type Request struct {
	Operation    string    `json:"operation"`
	Candidate    []byte    `json:"candidate_base64,omitempty"`
	BaseIdentity *Identity `json:"base_identity,omitempty"`
	ReceiptPath  string    `json:"receipt_path,omitempty"`
	Group        string    `json:"group,omitempty"`
	Member       string    `json:"member,omitempty"`
}
type Response struct {
	Schema                    int              `json:"schema"`
	ProfilePath               string           `json:"profile_path,omitempty"`
	Identity                  Identity         `json:"identity,omitempty"`
	BaseIdentity              Identity         `json:"base_identity,omitempty"`
	Controller                string           `json:"controller,omitempty"`
	CACert                    string           `json:"ca_cert,omitempty"`
	SSHJump                   string           `json:"ssh_jump,omitempty"`
	Group                     string           `json:"group,omitempty"`
	Member                    string           `json:"member,omitempty"`
	ReceiptPath               string           `json:"receipt_path,omitempty"`
	ProfileSHA256             string           `json:"profile_sha256,omitempty"`
	State                     string           `json:"state,omitempty"`
	RequiresProxyInterruption bool             `json:"requires_proxy_interruption,omitempty"`
	NoChange                  bool             `json:"no_change,omitempty"`
	Complete                  bool             `json:"complete,omitempty"`
	LAN                       map[string]any   `json:"lan,omitempty"`
	Devices                   []map[string]any `json:"devices,omitempty"`
}

// Runner is an explicit fixture injection point. Production always executes the
// saved local broker using an argument vector and bounded JSON stdin/stdout.
type Runner func(context.Context, config.Target, Request) (Response, error)
type limitedOutput struct{ bytes.Buffer }

func (w *limitedOutput) Write(p []byte) (int, error) {
	if w.Len()+len(p) > 2<<20 {
		return 0, errors.New("broker output exceeds limit")
	}
	return w.Buffer.Write(p)
}
func Call(ctx context.Context, t config.Target, req Request, runner Runner) (Response, error) {
	if t.ManagedRPi == nil {
		return Response{}, errors.New("target has no managed RPi owner")
	}
	if err := config.ValidateManagedRPi(t); err != nil {
		return Response{}, err
	}
	switch req.Operation {
	case "inspect", "preview", "apply", "verify", "restore", "select", "inventory":
	default:
		return Response{}, errors.New("unsupported managed RPi operation")
	}
	if req.ReceiptPath != "" {
		if err := privatePath(t, req.ReceiptPath); err != nil {
			return Response{}, err
		}
	}
	var out Response
	var err error
	if runner != nil {
		out, err = runner(ctx, t, req)
	} else {
		if err := privatePath(t, t.ManagedRPi.ConnectionFile); err != nil {
			return out, errors.New("managed RPi connection must be a private regular file below project private/")
		}
		raw, e := json.Marshal(req)
		if e != nil {
			return out, e
		}
		ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
		defer cancel()
		command := exec.CommandContext(ctx, "python3", filepath.Join(t.ManagedRPi.ProjectDir, "scripts", "device", "proxy_manage.py"), "--connection", t.ManagedRPi.ConnectionFile, "bridge")
		command.Stdin = bytes.NewReader(raw)
		var stdout limitedOutput
		command.Stdout = &stdout
		// Never propagate arbitrary subprocess diagnostics: profiles contain secrets.
		command.Stderr = io.Discard
		if e = command.Run(); e != nil {
			return out, errors.New("managed RPi broker failed; mutation result may be unknown, inspect the saved receipt before retrying")
		}
		if json.Unmarshal(stdout.Bytes(), &out) != nil {
			return out, errors.New("invalid managed RPi broker response")
		}
	}
	if err != nil {
		return out, err
	}
	if out.Schema != 1 {
		return out, errors.New("unsupported managed RPi broker schema")
	}
	if out.ReceiptPath != "" {
		if err = privatePath(t, out.ReceiptPath); err != nil {
			return out, err
		}
	}
	return out, nil
}
func privatePath(t config.Target, p string) error {
	root := filepath.Join(t.ManagedRPi.ProjectDir, "private")
	rel, err := filepath.Rel(root, p)
	if err != nil || !filepath.IsAbs(p) || filepath.Clean(p) != p || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("broker file must remain below project private/")
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil || resolved != p {
		return errors.New("broker file is missing or uses a symlink")
	}
	info, err := os.Lstat(p)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !singleLink(info) {
		return errors.New("broker file must be a single-link private regular file with mode 0600")
	}
	return nil
}

func singleLink(info os.FileInfo) bool {
	v := reflect.Indirect(reflect.ValueOf(info.Sys()))
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return false
	}
	n := v.FieldByName("Nlink")
	return n.IsValid() && n.CanUint() && n.Uint() == 1
}

// ValidateTransport runs before resolving credentials or opening the API. The
// saved owner, rather than editable target transport fields, supplies authority.
func ValidateTransport(ctx context.Context, t config.Target, runner Runner) error {
	r, err := Call(ctx, t, Request{Operation: "inspect"}, runner)
	if err != nil {
		return err
	}
	return MatchTransport(t, r)
}

func MatchTransport(t config.Target, r Response) error {
	if !ValidIdentity(r.Identity) || r.Controller != t.Controller || r.CACert != t.CAFile || r.SSHJump != t.SSHHost {
		return errors.New("managed RPi target endpoint, private CA or SSH transport differs from its broker")
	}
	return nil
}

func ReadProfile(t config.Target, r Response) ([]byte, error) {
	if err := MatchTransport(t, r); err != nil {
		return nil, err
	}
	if err := privatePath(t, r.ProfilePath); err != nil {
		return nil, err
	}
	before, err := os.Lstat(r.ProfilePath)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 {
		return nil, errors.New("broker profile must be a private regular file with mode 0600")
	}
	f, err := os.Open(r.ProfilePath)
	if err != nil {
		return nil, errors.New("cannot open broker private profile")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) || info.Size() > 8<<20 || info.Mode().Perm() != 0600 {
		return nil, errors.New("broker profile changed while opening")
	}
	if !singleLink(info) {
		return nil, errors.New("broker profile must have one link")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if err != nil || len(raw) > 8<<20 {
		return nil, errors.New("cannot read bounded broker profile")
	}
	if Digest(raw) != r.Identity.ProfileSHA256 || !ValidIdentity(r.Identity) {
		return nil, errors.New("broker profile identity mismatch")
	}
	return raw, nil
}
func Digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func ValidIdentity(i Identity) bool {
	for _, s := range []string{i.ProfileSHA256, i.NetworkBundleSHA256} {
		if len(s) != 64 {
			return false
		}
		if _, e := hex.DecodeString(s); e != nil {
			return false
		}
	}
	return i.BootID != "" && i.CoreIdentity != ""
}
