package tui

import (
	"bytes"
	"context"
	"errors"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestToolTargetKeepsCredentialReferencesWithoutTransportOrPlaintext(t *testing.T) {
	args := []string{"proxies", "export", "node", "--interactive"}
	target := config.Target{ID: "saved", Controller: "https://never-forward:9090", SSHHost: "never-forward-host", SecretEnv: "CURRENT_SECRET", CAFile: "/current/ca.pem", Secret: "PRIVATE_NEVER_ARGV"}
	got := toolTargetArgs(target, args)
	want := []string{"--target", "saved", "--secret-env", "CURRENT_SECRET", "--ca-cert", "/current/ca.pem", "proxies", "export", "node", "--interactive"}
	if !reflect.DeepEqual(got, want) || strings.Contains(strings.Join(got, " "), "PRIVATE") || !reflect.DeepEqual(args, []string{"proxies", "export", "node", "--interactive"}) {
		t.Fatalf("handoff args: %q", got)
	}
	target.SecretEnv = ""
	target.SecretFile = "/current/secret"
	got = toolTargetArgs(target, args)
	if !strings.Contains(strings.Join(got, " "), "--secret-file /current/secret") {
		t.Fatal("secret file reference lost")
	}
}

func toolModel(t *testing.T) *Model {
	m := testModel(t)
	m.options.RunCommand = func(context.Context, []string, io.Reader, io.Writer, io.Writer) error {
		t.Fatal("terminal command ran before handoff")
		return nil
	}
	return m
}

func TestAnalyticsPaletteQueryAndVisibleActionStayConsistent(t *testing.T) {
	m := toolModel(t)
	m.page = overview
	sendKey(m, ":")
	for _, letter := range "Historical analytics" {
		sendKey(m, string(letter))
	}
	actions := m.paletteActions()
	if m.input.Value() != "Historical analytics" || len(actions) != 2 || actions[0].id != "tool-analytics" {
		t.Fatalf("wrong filtered action for query %q: %+v", m.input.Value(), actions)
	}
	view := m.overlayView(120, 25)
	if !strings.Contains(view, "Historical analytics: sources") || strings.Contains(view, "Setup Mihomo client") {
		t.Fatalf("palette rendered unrelated action rows: %s", view)
	}
	if cmd := sendKey(m, "enter"); cmd == nil || m.overlay != "external-tool" || m.status != "Historical analytics" {
		t.Fatalf("filtered Enter did not hand off analytics: overlay=%s status=%s", m.overlay, m.status)
	}
}

func TestToolHandoffSingleOwnerAndStaleReturn(t *testing.T) {
	m := toolModel(t)
	cmd := m.runTool("Edit source", true, "proxies", "edit", "Alpha", "--interactive")
	if cmd == nil || !m.toolPending || m.overlay != "external-tool" {
		t.Fatal("missing handoff state")
	}
	if cmd := m.runTool("Second reader", false, "cores", "list"); cmd != nil {
		t.Fatal("second terminal reader started")
	}
	request := toolMsg{generation: m.generation, serial: m.toolSerial, label: "Edit source"}
	stale := request
	stale.serial--
	m.receiveTool(stale)
	if !m.toolPending {
		t.Fatal("old request cleared current task")
	}
	m.generation++
	if cmd := m.receiveTool(request); cmd != nil || m.toolPending || m.overlay != "" {
		t.Fatal("target change left terminal task pending or refreshed stale data")
	}
}

func TestToolGuardsDraftReadOnlyAndTransientTarget(t *testing.T) {
	for _, overlay := range []string{"form", "search", "work", "confirm", "ssh-auth"} {
		m := toolModel(t)
		m.overlay = overlay
		if cmd := m.runTool("steal reader", false, "cores", "list"); cmd != nil || m.toolPending {
			t.Fatalf("stole %s", overlay)
		}
	}
	for _, action := range []string{"tool-setup", "tool-proxy-add", "tool-proxy-import", "tool-proxy-edit", "tool-proxy-copy", "tool-proxy-duplicate", "tool-group-add", "tool-group-edit"} {
		m := toolModel(t)
		m.options.ReadOnly = true
		if cmd := m.toolAction(action); cmd != nil || m.toolPending {
			t.Fatalf("read-only action %s", action)
		}
	}
	for _, override := range []bool{false, true} {
		m := toolModel(t)
		m.target.Transient = !override
		m.target.TransportOverride = override
		if cmd := m.runTool("edit", true, "proxies", "add"); cmd != nil || m.toolPending {
			t.Fatal("temporary target write handoff")
		}
	}
}

func TestToolSettingsRefreshKeepsTargetIdentity(t *testing.T) {
	m := toolModel(t)
	m.toolSerial = 4
	m.generation = 7
	stale := toolSettingsMsg{toolMsg: toolMsg{generation: 6, serial: 4}, settings: config.Config{Targets: []config.Target{{ID: "wrong", Controller: "http://127.0.0.1:1"}}}}
	m.receiveToolSettings(stale)
	if m.target.ID != "test" || m.settings.Targets[0].ID != "test" {
		t.Fatal("stale settings replaced target")
	}
	fresh := stale
	fresh.generation = 7
	fresh.settings = config.Config{Targets: []config.Target{{ID: "test", Controller: "http://127.0.0.1:9999"}}}
	if cmd := m.receiveToolSettings(fresh); cmd == nil || m.target.Controller != "http://127.0.0.1:9999" || !m.opening {
		t.Fatal("transport change did not reconnect")
	}
}

func TestToolSettingsCloneAndLastTargetRemoval(t *testing.T) {
	cfg := config.Config{Targets: []config.Target{{ID: "a", ConfigSource: &config.ConfigSource{Kind: "native", ConfigID: "original"}}}}
	copy := cloneSettings(cfg)
	copy.Targets[0].ConfigSource.ConfigID = "draft"
	if cfg.Targets[0].ConfigSource.ConfigID != "original" {
		t.Fatal("source pointer shared with draft")
	}
	m := toolModel(t)
	m.toolSerial = 9
	m.generation = 4
	m.receiveToolSettings(toolSettingsMsg{toolMsg: toolMsg{generation: 4, serial: 9}, settings: config.Config{}})
	if m.target.ID != "" || m.client != nil || m.ctx.Err() != nil || m.opening {
		t.Fatal("removed target remained active or new setup context was canceled")
	}
}

func TestTerminalTaskPauseAndCancellation(t *testing.T) {
	for _, failure := range []error{nil, errors.New("fixture failure"), wizard.ErrCanceled, context.Canceled} {
		pauses, runs := 0, 0
		var out bytes.Buffer
		task := terminalTask{ctx: context.Background(), in: bytes.NewReader(nil), out: &out, errOut: &out, run: func(context.Context, []string, io.Reader, io.Writer, io.Writer) error { runs++; return failure }, pause: func(context.Context, string, io.Reader, io.Writer) error { pauses++; return nil }}
		err := task.Run()
		if !errors.Is(err, failure) || runs != 1 {
			t.Fatalf("run result: %v %v %d", err, failure, runs)
		}
		want := 1
		if errors.Is(failure, wizard.ErrCanceled) || errors.Is(failure, context.Canceled) {
			want = 0
		}
		if pauses != want {
			t.Fatalf("pause=%d for %v", pauses, failure)
		}
	}
}
