package vps

import (
	"context"
	"reflect"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

func TestAzureSizeQueryFiltersOnlyWhenPlanIsExplicit(t *testing.T) {
	for _, plan := range []string{"", "Standard_B2pts_v2"} {
		t.Run("plan="+plan, func(t *testing.T) {
			called := false
			s := New(serverstate.Store{}, Options{Run: func(_ context.Context, exe string, args []string) ([]byte, error) {
				called = true
				if exe != "az" || len(args) < 2 || args[0] != "vm" || args[1] != "list-skus" {
					t.Fatalf("unexpected command: %s %v", exe, args)
				}
				if got := azureFlag(args, "--size"); got != plan {
					t.Fatalf("size filter=%q, want %q: %v", got, plan, args)
				}
				return []byte(`[]`), nil
			}})
			_, err := (azureAdapter{s: s}).sizes(context.Background(), CreateRequest{Provider: "azure", SubscriptionID: "subscription", Region: "eastasia", Plan: plan})
			if err != nil || !called {
				t.Fatalf("called=%v error=%v", called, err)
			}
		})
	}
}

func TestAzureCLICommandPrecedesSubscriptionFlags(t *testing.T) {
	want := []string{"account", "show", "--output", "json", "--only-show-errors", "--subscription", "selected-subscription"}
	s := New(serverstate.Store{}, Options{Run: func(_ context.Context, exe string, args []string) ([]byte, error) {
		if exe != "az" || !reflect.DeepEqual(args, want) {
			t.Fatalf("Azure CLI cannot parse flags before its command: %s %v", exe, args)
		}
		return []byte(`{"id":"selected-subscription"}`), nil
	}})
	if _, err := s.call(context.Background(), CreateRequest{Provider: "azure", SubscriptionID: "selected-subscription"}, "account", "show"); err != nil {
		t.Fatal(err)
	}
}
