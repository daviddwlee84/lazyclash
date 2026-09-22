package serverdeploy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

func readyStatusFixture(t *testing.T) (Options, string, journal) {
	t.Helper()
	o, _ := fixture(t)
	p, err := Preview(context.Background(), request("vless-reality", "native"), o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Apply(context.Background(), p, p.Digest, o); err != nil {
		t.Fatal(err)
	}
	path, err := journalPath(o, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	j, err := loadJournal(o, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	j.VerifiedAt = time.Date(2026, 9, 21, 21, 4, 32, 0, time.UTC)
	if err = saveJournal(path, &j); err != nil {
		t.Fatal(err)
	}
	o.Probe = func(context.Context, []byte) (string, error) {
		t.Fatal("status re-verified proxy instead of preserving historical evidence")
		return "", nil
	}
	return o, path, j
}

func TestStatusFailureNeverPromotesSavedReadyToLiveService(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		response  RemoteResponse
		ssh, kind string
	}{
		{"timeout", &connection.SSHTransportError{Kind: "timeout"}, RemoteResponse{}, "unreachable", "ssh-timeout"},
		{"refused", &connection.SSHTransportError{Kind: "refused"}, RemoteResponse{}, "unreachable", "ssh-refused"},
		{"auth", &connection.AuthRequiredError{Host: "fixture-alias"}, RemoteResponse{}, "authentication-required", "ssh-authentication"},
		{"output-limit", connection.ErrHelperOutputLimit, RemoteResponse{}, "unconfirmed", "helper-output-limit"},
		{"python", connection.ErrPythonUnavailable, RemoteResponse{}, "reachable", "python-unavailable"},
		{"helper", errors.New("PRIVATE helper detail"), RemoteResponse{}, "unconfirmed", "helper-failed"},
		{"sudo", errors.New("PRIVATE remote detail"), RemoteResponse{Error: "sudo unavailable"}, "reachable", "remote-helper"},
		{"deadline", context.DeadlineExceeded, RemoteResponse{}, "unconfirmed", "deadline"},
		{"canceled", context.Canceled, RemoteResponse{}, "unconfirmed", "canceled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, path, j := readyStatusFixture(t)
			before, _ := os.ReadFile(path)
			calls := 0
			o.Execute = func(_ context.Context, _ string, r RemoteRequest) (RemoteResponse, error) {
				calls++
				if r.Op != "status" {
					t.Fatal("unexpected action", r.Op)
				}
				return tc.response, tc.err
			}
			status, err := GetStatus(context.Background(), j.Plan.ID, o)
			after, _ := os.ReadFile(path)
			if !errors.Is(err, tc.err) || calls != 1 || status.Service != "unknown" || status.ServiceObserved || status.SSH != tc.ssh || status.FailureKind != tc.kind {
				t.Fatalf("status confused failure/cache/live state: %+v err=%v calls=%d", status, err, calls)
			}
			if status.LastKnownStatus != "ready" || !status.LastKnownAt.Equal(j.UpdatedAt) || !status.VerifiedAt.Equal(j.VerifiedAt) || status.ObservedExitIP != j.ObservedExitIP || status.CheckedAt.IsZero() {
				t.Fatal("historical state lost or refreshed", status)
			}
			raw, _ := json.Marshal(status)
			if strings.Contains(string(raw), "PRIVATE") || !strings.Contains(status.Message, "historical") {
				t.Fatal("unsafe or unclear status", string(raw))
			}
			if string(before) != string(after) {
				t.Fatal("status read modified deployment journal")
			}
		})
	}
}

func TestStatusSuccessDistinguishesCurrentStoppedFromSavedReady(t *testing.T) {
	o, _, j := readyStatusFixture(t)
	for _, state := range []string{"running", "stopped", "absent", "unknown", ""} {
		o.Execute = func(context.Context, string, RemoteRequest) (RemoteResponse, error) {
			return RemoteResponse{OK: true, Service: state}, nil
		}
		status, err := GetStatus(context.Background(), j.Plan.ID, o)
		wantObserved := state != "unknown" && state != ""
		if err != nil || status.SSH != "reachable" || status.ServiceObserved != wantObserved || status.LastKnownStatus != "ready" || !status.VerifiedAt.Equal(j.VerifiedAt) {
			t.Fatal(state, status, err)
		}
		if wantObserved && status.Service != state || !wantObserved && status.Service != "unknown" {
			t.Fatal("incorrect live service state", status)
		}
	}
}

func TestChangedHostStatusDoesNotReadOrClaimOldService(t *testing.T) {
	o, _, j := readyStatusFixture(t)
	if err := o.Store.Update(func(i *serverstate.Inventory) error {
		h, e := i.Host(j.Host.ID)
		if e != nil {
			return e
		}
		h.SSHHost = "replacement-host"
		return i.UpsertHost(h)
	}); err != nil {
		t.Fatal(err)
	}
	o.Execute = func(context.Context, string, RemoteRequest) (RemoteResponse, error) {
		t.Fatal("inspected an unreviewed replacement host")
		return RemoteResponse{}, nil
	}
	status, err := GetStatus(context.Background(), j.Plan.ID, o)
	if err != nil || status.Service != "unknown" || status.ServiceObserved || status.LastKnownStatus != "ready" || status.FailureKind != "host-binding-changed" {
		t.Fatal(status, err)
	}
}
