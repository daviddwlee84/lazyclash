package testcore_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/testcore"
)

// This integration check ensures the fixture exercises the production client,
// including encoded proxy names and write read-back, without a live core.
func TestControllerSupportsStatefulClientAndStreams(t *testing.T) {
	handler := testcore.NewHandler()
	server := httptest.NewServer(handler)
	defer server.Close()
	client, err := core.New(core.Options{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()
	if err := client.Select(ctx, testcore.Selector, testcore.Tokyo); err != nil {
		t.Fatal(err)
	}
	if result, err := client.Delay(ctx, testcore.Tokyo); err != nil || result["delay"] != float64(62) {
		t.Fatalf("delay: %v %v", result, err)
	}
	if _, err := client.SetConfig(ctx, core.Object{"mode": "global", "tun": core.Object{"enable": true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ApplyConfig(ctx, "/remote/demo.yaml"); err != nil {
		t.Fatal(err)
	}
	if handler.LastApplied() != "/remote/demo.yaml" {
		t.Fatal("missing apply snapshot")
	}
	if err := client.CloseConnections(ctx, "conn-1"); err != nil {
		t.Fatal(err)
	}
	connections, err := client.Connections(ctx)
	if err != nil || len(connections["connections"].([]any)) != 1 {
		t.Fatalf("connections: %v %v", connections, err)
	}
	for kind, name := range map[string]string{"proxies": testcore.ProxyProvider, "rules": testcore.RuleProvider} {
		if _, err := client.Providers(ctx, kind); err != nil {
			t.Fatal(err)
		}
		if err := client.UpdateProvider(ctx, kind, name); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.HealthcheckProvider(ctx, testcore.ProxyProvider); err != nil {
		t.Fatal(err)
	}
	for _, resource := range []string{"logs", "traffic", "memory"} {
		streamCtx, cancel := context.WithCancel(ctx)
		count := 0
		err := client.Stream(streamCtx, resource, nil, func(core.Object) { count++; cancel() })
		cancel()
		if !errors.Is(err, context.Canceled) || count != 1 {
			t.Fatalf("%s stream: count=%d err=%v", resource, count, err)
		}
	}
	requests := handler.Requests()
	if len(requests) == 0 {
		t.Fatal("requests not recorded")
	}
	requests[0].Query.Set("mutated", "true")
	if handler.Requests()[0].Query.Get("mutated") != "" {
		t.Fatal("request snapshot shares mutable state")
	}
}
