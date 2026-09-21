package tailnetproxy

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/tailnet"
)

//go:embed helper.py
var helper string

func (s Service) execute(ctx context.Context, host string, r RemoteRequest) (RemoteResponse, error) {
	if s.Options.Execute != nil {
		return s.Options.Execute(ctx, host, r)
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	input, err := json.Marshal(r)
	if err != nil {
		return RemoteResponse{}, err
	}
	privileged := r.Op != "inspect" && (r.Op != "audit" || r.HostOS == "darwin")
	data, err := tailnet.ExecuteHelper(ctx, host, helper, input, privileged, s.Options.Core.Foreground)
	if err != nil {
		return RemoteResponse{}, err
	}
	var out RemoteResponse
	if json.Unmarshal(data, &out) != nil {
		return out, errors.New("invalid tailnet proxy helper response")
	}
	if !out.OK {
		if out.Error == "" {
			out.Error = "tailnet proxy helper failed"
		}
		return out, errors.New(out.Error)
	}
	return out, nil
}
func remote(j journal, op string) RemoteRequest {
	r := RemoteRequest{Op: op, ID: j.Request.ID, PeerID: j.PeerID, Token: j.Token, Port: j.Request.Port, TargetPort: j.Request.LocalPort, ListenIP: j.ListenIP, Mode: j.Request.Mode, UDP: j.Request.UDP, HostOS: j.HostOS, DockerEndpoint: j.DockerEndpoint}
	if j.Request.Egress != "existing" {
		r.CoreID = j.CoreID
		r.Backend = j.Request.Backend
		r.ControllerPort = j.Request.ControllerPort
		r.Protocol = "mixed"
	} else if u, e := upstreamURL(j.Request.Upstream); e == nil {
		r.Protocol = u.Scheme
	}
	if j.Request.Egress == "upstream" {
		if u, e := upstreamURL(j.Request.Upstream); e == nil {
			r.UpstreamHost = u.Hostname()
			r.UpstreamPort, _ = strconv.Atoi(u.Port())
		}
	}
	return r
}
