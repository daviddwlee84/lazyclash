package main

import (
	"context"
	"github.com/daviddwlee84/lazyclash/internal/scoopupgrade"
	"os"
	"os/signal"
	"syscall"

	"github.com/daviddwlee84/lazyclash/internal/cli"
)

func main() {
	if code, handled := scoopupgrade.HandleHelper(scoopupgrade.Product{Binary: "lazyclash", Module: "github.com/daviddwlee84/lazyclash", Main: "github.com/daviddwlee84/lazyclash/cmd/lazyclash"}); handled {
		os.Exit(code)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx)
	stop()
	os.Exit(code)
}

func run(ctx context.Context) int {
	return cli.Execute(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
}
