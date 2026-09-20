package testcore_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/dashboard"
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

func TestControllerOverviewDistributionsAndTelemetry(t *testing.T) {
	server := testcore.NewServer()
	defer server.Close()
	client, err := core.New(core.Options{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	connections, err := client.Connections(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	summary := dashboard.SummarizeConnections(connections)
	if summary.Count != 2 || summary.Protocols[0].Count != 1 || summary.Protocols[1].Count != 1 || len(summary.Routes) != 2 || len(summary.Groups) != 2 {
		t.Fatalf("overview fixture lost protocol/route variety: %+v", summary)
	}
	for _, resource := range []string{"traffic", "memory"} {
		t.Run(resource, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var events []core.Object
			err := client.StreamWithOptions(ctx, resource, nil, core.StreamOptions{Limit: 3}, func(event core.Object) (bool, error) {
				events = append(events, event)
				return true, nil
			})
			if err != nil || len(events) != 3 {
				t.Fatalf("fixture stream: %v, %v", events, err)
			}
			if resource == "traffic" {
				if events[0]["up"] == events[1]["up"] || events[0]["down"] == events[1]["down"] {
					t.Fatalf("traffic should vary: %v", events)
				}
			} else if events[0]["inuse"] != float64(0) || events[1]["inuse"] != float64(16<<20) || events[2]["inuse"] == events[1]["inuse"] {
				t.Fatalf("memory should warm up and vary: %v", events)
			}
		})
	}
}

func TestControllerLogMinimumSeverityAndBoundedCount(t *testing.T) {
	for _, test := range []struct {
		level string
		want  []string
	}{
		{"", []string{"info", "warning", "error"}},
		{"info", []string{"info", "warning", "error"}},
		{"debug", []string{"info", "debug", "warning"}},
		{"warning", []string{"warning", "error", "warning"}},
		{"error", []string{"error", "error"}},
	} {
		t.Run("level="+test.level, func(t *testing.T) {
			t.Parallel()
			server := testcore.NewServer()
			defer server.Close()
			client, err := core.New(core.Options{Endpoint: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var got []string
			err = client.StreamWithOptions(ctx, "logs", url.Values{"level": {test.level}}, core.StreamOptions{Limit: len(test.want)}, func(event core.Object) (bool, error) {
				got = append(got, event["type"].(string))
				return true, nil
			})
			if err != nil || !slices.Equal(got, test.want) {
				t.Fatalf("bounded severity stream: got %v, want %v, error %v", got, test.want, err)
			}
		})
	}
}

func TestControllerLogSilentAndInvalidLevels(t *testing.T) {
	server := testcore.NewServer()
	defer server.Close()
	client, err := core.New(core.Options{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = client.StreamWithOptions(ctx, "logs", url.Values{"level": {"silent"}}, core.StreamOptions{Duration: 30 * time.Millisecond}, func(core.Object) (bool, error) {
		t.Error("silent log stream emitted a record")
		return true, nil
	})
	if err != nil {
		t.Fatalf("silent duration bound: %v", err)
	}
	err = client.Stream(ctx, "logs", url.Values{"level": {"unknown"}}, func(core.Object) {})
	var apiErr *core.Error
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid log level: %v", err)
	}
}
