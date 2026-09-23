package clientservice

import (
	"context"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

func TestManagedRPiRejectsGenericServiceBeforeHostCall(t *testing.T) {
	target := config.Target{ID: "pi", ManagedRPi: &config.ManagedRPi{}, Service: &config.ClientService{Kind: "systemd"}}
	opts := Options{Host: func(context.Context, config.Target, Request) (Status, error) {
		t.Fatal("managed RPi reached generic service host")
		return Status{}, nil
	}}
	if _, err := Inspect(context.Background(), target, opts); err == nil {
		t.Fatal("managed RPi service inspection accepted")
	}
	if _, err := PrepareBind(context.Background(), target, *target.Service, opts); err == nil {
		t.Fatal("managed RPi service takeover accepted")
	}
	if _, err := Preview(context.Background(), target, "stop", false, opts); err == nil {
		t.Fatal("managed RPi generic stop accepted")
	}
}
