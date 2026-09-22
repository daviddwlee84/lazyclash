package vps

import (
	"context"
	"reflect"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

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
