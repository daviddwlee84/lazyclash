package serverdeploy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/serverprobe"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
	"go.yaml.in/yaml/v3"
)

//go:embed helper.py
var helper string

func execute(ctx context.Context, host string, r RemoteRequest, o Options) (RemoteResponse, error) {
	if o.Execute != nil {
		return o.Execute(ctx, host, r)
	}
	if host == "" {
		return RemoteResponse{}, errors.New("server operations require an explicit SSH host")
	}
	input, err := json.Marshal(r)
	if err != nil {
		return RemoteResponse{}, err
	}
	// Only this fixed helper is elevated; request data remains on stdin.
	bootstrap := "import os,sys,base64,json,subprocess\nbody=base64.b64decode('" + base64.StdEncoding.EncodeToString([]byte(helper)) + "').decode()\nif os.geteuid()==0:\n exec(compile(body,'lazyclash-server-helper','exec'))\nelse:\n data=sys.stdin.buffer.read()\n p=subprocess.run(['sudo','-n','python3','-c',body],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE)\n if p.returncode: print(json.dumps({'ok':False,'error':'server management needs root SSH or non-interactive sudo for Python 3'}))\n else: sys.stdout.buffer.write(p.stdout)\n"
	data, err := connection.ExecutePython(ctx, host, bootstrap, input, 1<<20)
	if err != nil {
		return RemoteResponse{}, err
	}
	var out RemoteResponse
	if json.Unmarshal(data, &out) != nil {
		return out, errors.New("server helper returned an invalid response")
	}
	if !out.OK {
		if out.Error == "" {
			out.Error = "server helper failed"
		}
		return out, errors.New(out.Error)
	}
	return out, nil
}

func Preview(ctx context.Context, request Request, o Options) (Plan, error) {
	i, err := o.Store.Load()
	if err != nil {
		return Plan{}, err
	}
	host, err := i.Host(request.HostID)
	if err != nil {
		return Plan{}, err
	}
	r, err := normalize(request, host)
	if err != nil {
		return Plan{}, err
	}
	path, err := journalPath(o, r.ID)
	if err != nil {
		return Plan{}, err
	}
	if previous, e := readJournal(path); e == nil {
		if reflect.DeepEqual(previous.Plan.Request, r) && sameHost(previous.Host, host) && previous.Phase != "removed" {
			if _, err = execute(ctx, host.SSHHost, remote(previous, "inspect"), o); err != nil {
				return Plan{}, err
			}
			return previous.Plan, nil
		}
		return Plan{}, errors.New("deployment ID already has a saved operation; resume it or choose a new ID")
	} else if !errors.Is(e, os.ErrNotExist) {
		return Plan{}, e
	}
	for _, d := range i.Deployments {
		if d.ID == r.ID {
			return Plan{}, errors.New("deployment ID already exists in inventory")
		}
		if d.HostID == r.HostID && d.Status != "removed" {
			if d.ListenPort == r.ListenPort {
				return Plan{}, errors.New("another managed deployment uses this listen port")
			}
			if r.Domain != "" && d.Domain == r.Domain {
				return Plan{}, errors.New("this certificate domain already belongs to another managed deployment")
			}
		}
	}
	token := make([]byte, 32)
	if _, err = rand.Read(token); err != nil {
		return Plan{}, err
	}
	j := journal{Host: host, Token: hex.EncodeToString(token)}
	observation, err := execute(ctx, host.SSHHost, RemoteRequest{Op: "inspect", ID: r.ID, Token: j.Token, Request: r, AllowInstall: host.Owned}, o)
	if err != nil {
		return Plan{}, err
	}
	resolver := o.Resolve
	if resolver == nil {
		resolver = resolveArtifact
	}
	artifact, err := resolver(ctx, r, observation.Arch)
	if err != nil {
		return Plan{}, err
	}
	if err = validateArtifact(artifact, r); err != nil {
		return Plan{}, err
	}
	j.Plan = Plan{ID: r.ID, HostID: r.HostID, Action: "deploy", Recipe: r.Recipe, Backend: r.Backend, PublicHost: r.PublicHost, Domain: r.Domain, PublicPort: r.PublicPort, ListenPort: r.ListenPort, Request: r, Artifact: artifact, Summary: fmt.Sprintf("Deploy %s on %s using %s, public %s:%d", r.Recipe, host.Name, r.Backend, r.PublicHost, r.PublicPort), Steps: []string{"Verify Ubuntu 24.04, architecture, ownership and port availability", "Install required Ubuntu packages and pinned core artifact", "Write private service configuration and validate it", "Start the owned service and verify an authenticated HTTPS proxy request"}, Warnings: observation.Warnings}
	if r.Recipe != "vless-reality" {
		j.Plan.Steps = append(j.Plan.Steps, "Issue a Let's Encrypt certificate using TCP 80 and enable certbot renewal")
	}
	if r.Backend == "compose" {
		j.Plan.Warnings = append(j.Plan.Warnings, "Containers use host networking. Only newly managed VPS instances may bootstrap Docker; existing SSH hosts must provide Docker and Compose.")
	}
	j.Plan.Warnings = append(j.Plan.Warnings, "Cloud firewall, host firewall and router port forwarding must allow the public endpoint; this deployment does not rewrite their existing rules.")
	if r.Recipe == "hysteria2" {
		j.Plan.Warnings = append(j.Plan.Warnings, "UDP must be reachable; this protocol has no TCP fallback.")
	}
	j.Plan.Digest = deploymentDigest(j)
	return j.Plan, nil
}

func validateArtifact(a Artifact, r Request) error {
	if a.Arch != "amd64" && a.Arch != "arm64" {
		return errors.New("unsupported artifact architecture")
	}
	if !shaPattern.MatchString(a.SHA256) || !(strings.HasPrefix(a.URL, "https://github.com/XTLS/Xray-core/releases/download/") || strings.HasPrefix(a.URL, "https://download.hysteria.network/app/v")) {
		return errors.New("artifact must have an official download and SHA256 digest")
	}
	if r.Backend == "compose" && (!strings.Contains(a.Image, "@sha256:") || len(strings.Split(a.Image, "@sha256:")[1]) != 64) {
		return errors.New("container image must be pinned to a SHA256 digest")
	}
	return nil
}

func Apply(ctx context.Context, p Plan, expected string, o Options) (Result, error) {
	if o.ReadOnly {
		return Result{}, errors.New("server deployment is disabled in read-only mode")
	}
	path, err := journalPath(o, p.ID)
	if err != nil {
		return Result{}, err
	}
	unlock, err := serverstate.Lock(path + ".lock")
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	inventory, err := o.Store.Load()
	if err != nil {
		return Result{}, err
	}
	host, err := inventory.Host(p.HostID)
	if err != nil {
		return Result{}, err
	}
	normalized, err := normalize(p.Request, host)
	if err != nil {
		return Result{}, err
	}
	candidate := journal{Plan: p, Host: host}
	if expected == "" || p.Action != "deploy" || p.ID != p.Request.ID || !reflect.DeepEqual(normalized, p.Request) || expected != p.Digest || deploymentDigest(candidate) != p.Digest {
		return Result{}, errors.New("deployment preview digest does not match; review the current preview")
	}
	if err = validateArtifact(p.Artifact, p.Request); err != nil {
		return Result{}, err
	}
	j, err := readJournal(path)
	if errors.Is(err, os.ErrNotExist) {
		c, e := generateCredentials()
		if e != nil {
			return Result{}, e
		}
		token := make([]byte, 32)
		if _, e = rand.Read(token); e != nil {
			return Result{}, e
		}
		files, e := render(p.Request, c, p.Artifact)
		if e != nil {
			return Result{}, e
		}
		j = journal{Plan: p, Host: host, Token: hex.EncodeToString(token), Credentials: c, Files: files, CreatedAt: time.Now().UTC(), Phase: "approved", Approved: true}
		j.Files, e = withOwnership(j.Files, j.Token, p.Request)
		if e != nil {
			return Result{}, e
		}
		if e = saveJournal(path, &j); e != nil {
			return Result{}, e
		}
	} else if err != nil {
		return Result{}, err
	}
	if j.Plan.Digest != p.Digest {
		return Result{}, errors.New("saved deployment differs from this preview")
	}
	if j.Phase == "removed" {
		return Result{}, errors.New("this deployment was removed; use a new deployment ID")
	}
	if err = checkHost(j, o); err != nil {
		return Result{}, err
	}
	return deploy(ctx, path, &j, o)
}

func Resume(ctx context.Context, id string, o Options) (Result, error) {
	if o.ReadOnly {
		return Result{}, errors.New("server deployment is disabled in read-only mode")
	}
	path, err := journalPath(o, id)
	if err != nil {
		return Result{}, err
	}
	unlock, err := serverstate.Lock(path + ".lock")
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	j, err := readJournal(path)
	if err != nil {
		return Result{}, err
	}
	if !j.Approved {
		return Result{}, errors.New("saved preview has not been approved; review deploy or resume preview first")
	}
	if j.Phase == "removed" {
		return Result{}, errors.New("removed deployments cannot be resumed")
	}
	if err = checkHost(j, o); err != nil {
		return Result{}, err
	}
	return deploy(ctx, path, &j, o)
}

func deploy(ctx context.Context, path string, j *journal, o Options) (Result, error) {
	if j.Phase == "ready" || j.Phase == "installed-unverified" {
		observed, err := execute(ctx, j.Host.SSHHost, remote(*j, "status"), o)
		if err != nil {
			return Result{}, err
		}
		if observed.Service == "running" {
			return verify(ctx, path, j, o)
		}
	}
	j.Phase = "deploying"
	if err := saveJournal(path, j); err != nil {
		return Result{}, err
	}
	if err := saveDeployment(*j, o); err != nil {
		return Result{}, err
	}
	_, err := execute(ctx, j.Host.SSHHost, remote(*j, "deploy"), o)
	if err != nil {
		j.Phase = "failed"
		_ = saveJournal(path, j)
		_ = saveDeployment(*j, o)
		return result(*j, "Deployment interrupted; resume uses the existing ownership token and credentials"), err
	}
	j.Phase = "installed-unverified"
	if err = saveJournal(path, j); err != nil {
		return Result{}, err
	}
	if err = saveDeployment(*j, o); err != nil {
		return Result{}, err
	}
	return verify(ctx, path, j, o)
}

func verify(ctx context.Context, path string, j *journal, o Options) (Result, error) {
	data, err := yaml.Marshal(clientMap(*j))
	if err != nil {
		return Result{}, err
	}
	probe := o.Probe
	if probe == nil {
		probe = func(ctx context.Context, data []byte) (string, error) {
			return serverprobe.ProbeWithOptions(ctx, data, serverprobe.Options{InterfaceName: o.VerifyInterface})
		}
	}
	ip, err := probe(ctx, data)
	if err != nil {
		out := result(*j, "Service installed; authenticated proxy verification has not passed")
		out.Warnings = []string{"Check public reachability, firewalls, router forwarding and the local verification core, then run resume.", "An existing TUN with TLS destination overrides can intercept REALITY. After diagnosis, --verify-interface can explicitly bind only the temporary verification client to a chosen local interface."}
		return out, nil
	}
	j.Phase = "ready"
	j.ObservedExitIP = ip
	j.VerifiedAt = time.Now().UTC()
	j.VerificationInterface = o.VerifyInterface
	if err = saveJournal(path, j); err != nil {
		return Result{}, err
	}
	if err = saveDeployment(*j, o); err != nil {
		return Result{}, err
	}
	return result(*j, "Authenticated HTTPS proxy request succeeded; observed exit IP "+ip), nil
}

func GetStatus(ctx context.Context, id string, o Options) (Status, error) {
	j, err := loadJournal(o, id)
	if err != nil {
		return Status{}, err
	}
	i, err := o.Store.Load()
	if err != nil {
		return Status{}, err
	}
	h, err := i.Host(j.Host.ID)
	if err != nil {
		return Status{}, err
	}
	s := Status{ID: id, HostID: h.ID, PublicHost: j.Plan.PublicHost, PublicPort: j.Plan.PublicPort, SSH: "unknown", Service: j.Phase, ObservedExitIP: j.ObservedExitIP, VerifiedAt: j.VerifiedAt, VerificationInterface: j.VerificationInterface, ClientUpdateRequired: h.PublicHost != "" && h.PublicHost != j.Host.PublicHost}
	if !sameManagementHost(j.Host, h) {
		s.Message = "Host binding changed; review the new host before further service operations"
		return s, nil
	}
	r, err := execute(ctx, h.SSHHost, remote(j, "status"), o)
	if err != nil {
		s.SSH = "unreachable"
		s.Message = "Cannot read service status over the recorded SSH host"
		return s, err
	}
	s.SSH = "reachable"
	s.Service = r.Service
	s.Message = "Service state and the last authenticated proxy verification are reported separately"
	return s, nil
}

func PreviewAction(ctx context.Context, id, action string, o Options) (Plan, error) {
	if action != "start" && action != "stop" && action != "restart" && action != "remove" && action != "resume" {
		return Plan{}, errors.New("server action must be start, stop, restart, remove or resume")
	}
	j, err := loadJournal(o, id)
	if err != nil {
		return Plan{}, err
	}
	if err = checkActionHost(j, action, o); err != nil {
		return Plan{}, err
	}
	if j.Phase == "removed" && action != "remove" {
		return Plan{}, errors.New("deployment is removed")
	}
	p := j.Plan
	p.Action = action
	p.Summary = fmt.Sprintf("%s owned proxy service %s on %s", action, id, j.Host.Name)
	p.Steps = []string{p.Summary}
	p.Digest = actionDigest(j, action)
	if action == "remove" {
		p.Warnings = []string{"Remove only this deployment's service, files and certificate; the VPS and installed OS packages are retained."}
	}
	return p, nil
}

func ApplyAction(ctx context.Context, p Plan, expected string, o Options) (Result, error) {
	if o.ReadOnly {
		return Result{}, errors.New("server mutations are disabled in read-only mode")
	}
	path, err := journalPath(o, p.ID)
	if err != nil {
		return Result{}, err
	}
	unlock, err := serverstate.Lock(path + ".lock")
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	j, err := readJournal(path)
	if err != nil {
		return Result{}, err
	}
	if err = checkActionHost(j, p.Action, o); err != nil {
		return Result{}, err
	}
	current, err := PreviewAction(ctx, p.ID, p.Action, o)
	if err != nil {
		return Result{}, err
	}
	if expected == "" || expected != current.Digest || !reflect.DeepEqual(p, current) {
		return Result{}, errors.New("server action preview digest does not match")
	}
	if p.Action == "resume" {
		j.Approved = true
		if err = saveJournal(path, &j); err != nil {
			return Result{}, err
		}
		return deploy(ctx, path, &j, o)
	}
	if !j.Approved {
		return Result{}, errors.New("service has never been deployed")
	}
	_, err = execute(ctx, j.Host.SSHHost, remote(j, p.Action), o)
	if err != nil {
		return Result{}, err
	}
	switch p.Action {
	case "remove":
		j.Phase = "removed"
	case "stop":
		j.Phase = "stopped"
	default:
		j.Phase = "installed-unverified"
	}
	if err = saveJournal(path, &j); err != nil {
		return Result{}, err
	}
	if err = saveDeployment(j, o); err != nil {
		return Result{}, err
	}
	if p.Action == "start" || p.Action == "restart" {
		return verify(ctx, path, &j, o)
	}
	return result(j, "Owned service "+p.Action+" completed"), nil
}

func remote(j journal, op string) RemoteRequest {
	return RemoteRequest{Op: op, ID: j.Plan.ID, Token: j.Token, Request: j.Plan.Request, Artifact: j.Plan.Artifact, Files: j.Files, AllowInstall: j.Host.Owned}
}
func result(j journal, message string) Result {
	return Result{ID: j.Plan.ID, HostID: j.Host.ID, Status: j.Phase, Message: message}
}
func sameHost(a, b serverstate.Host) bool {
	return sameManagementHost(a, b) && a.PublicHost == b.PublicHost
}
func sameManagementHost(a, b serverstate.Host) bool {
	return a.ID == b.ID && a.SSHHost == b.SSHHost && a.ResourceID == b.ResourceID && a.Provider == b.Provider && a.Profile == b.Profile
}
func checkActionHost(j journal, action string, o Options) error {
	if action != "stop" && action != "remove" {
		return checkHost(j, o)
	}
	i, err := o.Store.Load()
	if err != nil {
		return err
	}
	h, err := i.Host(j.Host.ID)
	if err != nil {
		return err
	}
	if !sameManagementHost(j.Host, h) {
		return errors.New("SSH or provider resource identity changed; use a newly reviewed deployment")
	}
	return nil
}
func checkHost(j journal, o Options) error {
	i, err := o.Store.Load()
	if err != nil {
		return err
	}
	h, err := i.Host(j.Host.ID)
	if err != nil {
		return err
	}
	if !sameHost(j.Host, h) {
		return errors.New("host binding or public endpoint changed after the preview; existing client configuration is not changed")
	}
	return nil
}
func journalPath(o Options, id string) (string, error) {
	if !idPattern.MatchString(id) {
		return "", errors.New("invalid deployment ID")
	}
	root, err := o.Store.StateRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "deployments", id+".json"), nil
}
func loadJournal(o Options, id string) (journal, error) {
	path, err := journalPath(o, id)
	if err != nil {
		return journal{}, err
	}
	return readJournal(path)
}
func readJournal(path string) (journal, error) {
	var j journal
	info, err := os.Lstat(path)
	if err != nil {
		return j, err
	}
	if !info.Mode().IsRegular() || info.Size() > 8<<20 {
		return j, errors.New("invalid private deployment journal")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return j, err
	}
	if json.Unmarshal(data, &j) != nil {
		return j, errors.New("cannot parse private deployment journal")
	}
	if j.Plan.ID != j.Plan.Request.ID || j.Plan.Digest != deploymentDigest(j) || j.Integrity != journalIntegrity(j) {
		return j, errors.New("private deployment journal no longer matches its reviewed digest")
	}
	return j, nil
}
func saveJournal(path string, j *journal) error {
	j.UpdatedAt = time.Now().UTC()
	if j.Integrity == "" {
		j.Integrity = journalIntegrity(*j)
	}
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	return serverstate.WritePrivate(path, data)
}
func deploymentDigest(j journal) string {
	raw, _ := json.Marshal(struct {
		Request  Request
		Host     string
		Artifact Artifact
	}{j.Plan.Request, hostBinding(j.Host), j.Plan.Artifact})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func journalIntegrity(j journal) string {
	raw, _ := json.Marshal(struct {
		Digest, Token string
		Credentials   credentials
		Files         map[string]string
	}{j.Plan.Digest, j.Token, j.Credentials, j.Files})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func hostBinding(h serverstate.Host) string {
	raw, _ := json.Marshal([]string{h.ID, h.SSHHost, h.ResourceID, h.Provider, h.Profile, h.PublicHost})
	return string(raw)
}
func actionDigest(j journal, action string) string {
	sum := sha256.Sum256([]byte(j.Plan.Digest + "\x00" + action + "\x00" + j.Phase + "\x00" + hostBinding(j.Host)))
	return hex.EncodeToString(sum[:])
}
func saveDeployment(j journal, o Options) error {
	return o.Store.Update(func(i *serverstate.Inventory) error {
		r := j.Plan.Request
		return i.UpsertDeployment(serverstate.Deployment{ID: r.ID, HostID: r.HostID, Recipe: r.Recipe, Backend: r.Backend, PublicHost: r.PublicHost, Domain: r.Domain, Status: j.Phase, Version: j.Plan.Artifact.Version, PublicPort: r.PublicPort, ListenPort: r.ListenPort, CreatedAt: j.CreatedAt, UpdatedAt: j.UpdatedAt})
	})
}
