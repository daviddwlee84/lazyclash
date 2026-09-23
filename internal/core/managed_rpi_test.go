package core

import (
	"context"
	"net/http"
	"testing"
)

func TestManagedRPiBlocksGenericWritesAndDelegatesSelect(t *testing.T) {
	selected := false
	requests := 0
	c := fakeClient(t, func(w http.ResponseWriter, r *http.Request) { requests++; writeJSON(w, Object{"version": "fixture"}) }, Options{ManagedRPi: true, SelectOwner: func(_ context.Context, g, m string) error { selected = g == "G" && m == "N"; return nil }})
	ctx := context.Background()
	for _, patch := range []Object{{"mode": "global"}, {"tun": Object{"enable": true}}, {"allow-lan": true}, {"mixed-port": 7890}} {
		if _, e := c.SetConfig(ctx, patch); e == nil {
			t.Fatal("managed runtime patch accepted")
		}
	}
	if _, e := c.ApplyConfig(ctx, "/etc/nikki/config.yaml"); e == nil {
		t.Fatal("managed reload accepted")
	}
	if e := c.UpdateProvider(ctx, "proxies", "P"); e == nil {
		t.Fatal("managed provider update accepted")
	}
	if e := c.HealthcheckProvider(ctx, "P"); e == nil {
		t.Fatal("managed provider mutation accepted")
	}
	if requests != 0 {
		t.Fatalf("generic writes reached network: %d", requests)
	}
	if e := c.Select(ctx, "G", "N"); e != nil || !selected {
		t.Fatalf("select broker: %v", e)
	}
	if requests != 0 {
		t.Fatal("selector used generic controller PUT")
	}
	if _, e := c.Version(ctx); e != nil || requests != 1 {
		t.Fatalf("reads blocked: %v", e)
	}
}
func TestManagedRPiReadOnlyCannotUseSelectorBroker(t *testing.T) {
	c := fakeClient(t, func(http.ResponseWriter, *http.Request) { t.Fatal("network") }, Options{ManagedRPi: true, ReadOnly: true, SelectOwner: func(context.Context, string, string) error { t.Fatal("broker invoked"); return nil }})
	requireKind(t, c.Select(context.Background(), "G", "N"), KindReadOnly)
}
