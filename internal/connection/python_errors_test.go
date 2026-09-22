package connection

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestExecutePythonClassifiesSSHAndHelperFailuresWithoutStderr(t *testing.T) {
	cases := []struct {
		name     string
		reply    muxReply
		kind     string
		sentinel error
		auth     bool
	}{
		{name: "timeout", reply: muxReply{Code: 255, Err: "ssh: connect to host PRIVATE port 22: Operation timed out"}, kind: "timeout"},
		{name: "banner-timeout", reply: muxReply{Code: 255, Err: "Connection timed out during banner exchange\nConnection to PRIVATE port 22 timed out"}, kind: "timeout"},
		{name: "refused", reply: muxReply{Code: 255, Err: "ssh: connect to host PRIVATE port 22: Connection refused"}, kind: "refused"},
		{name: "route", reply: muxReply{Code: 255, Err: "ssh: connect to host PRIVATE port 22: No route to host"}, kind: "unreachable"},
		{name: "dns", reply: muxReply{Code: 255, Err: "ssh: Could not resolve hostname PRIVATE: Name or service not known"}, kind: "resolve"},
		{name: "closed", reply: muxReply{Code: 255, Err: "kex_exchange_identification: Connection closed by PRIVATE"}, kind: "closed"},
		{name: "auth", reply: muxReply{Code: 255, Err: "PRIVATE: Permission denied (publickey)."}, auth: true},
		{name: "stdout-limit", reply: muxReply{Out: strings.Repeat("PRIVATE", 512)}, sentinel: ErrHelperOutputLimit},
		{name: "stderr-limit", reply: muxReply{Err: strings.Repeat("PRIVATE", 2048)}, sentinel: ErrHelperOutputLimit},
		{name: "python", reply: muxReply{Code: 127, Err: "bash: python3: command not found PRIVATE"}, sentinel: ErrPythonUnavailable},
		{name: "helper", reply: muxReply{Code: 1, Err: "PRIVATE helper exception"}, sentinel: ErrHelperFailed},
		{name: "helper-not-ssh", reply: muxReply{Code: 1, Err: "ssh: connect to host PRIVATE port 22: Connection refused"}, sentinel: ErrHelperFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearMultiplexPolicies()
			old := commandContext
			calls := 0
			defer func() { commandContext = old; clearMultiplexPolicies() }()
			commandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
				reply := tc.reply
				if len(args) > 0 && args[0] == "-G" {
					reply = muxReply{Out: "controlmaster no\ncontrolpersist no\ncontrolpath none\n"}
				} else {
					calls++
				}
				raw, _ := json.Marshal(reply)
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestMuxReplyProcess")
				cmd.Env = append(os.Environ(), "LAZYCLASH_MUX_REPLY="+base64.StdEncoding.EncodeToString(raw))
				return cmd
			}
			out, err := ExecutePython(context.Background(), "fixture-ssh", "print('safe')", nil, 128)
			if err == nil || len(out) != 0 || strings.Contains(err.Error(), "PRIVATE") || calls != 1 {
				t.Fatalf("unsafe or retried helper: %q %v calls=%d", out, err, calls)
			}
			if tc.sentinel != nil && !errors.Is(err, tc.sentinel) {
				t.Fatalf("wrong error classification: %v", err)
			}
			if tc.auth && !IsAuthRequired(err) {
				t.Fatal("lost terminal authentication handoff", err)
			}
			if tc.kind != "" {
				var transport *SSHTransportError
				if !errors.As(err, &transport) || transport.Kind != tc.kind {
					t.Fatal("wrong transport error", err)
				}
			}
		})
	}
}
