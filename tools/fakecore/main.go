// fakecore runs a harmless, loopback-only controller for CLI/TUI terminal tests.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/testcore"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "loopback host:port to listen on")
	flag.Parse()
	log.SetFlags(0)
	host, port, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatal("invalid -addr: expected loopback host:port")
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		log.Fatal("-addr must use a loopback IP or localhost")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := &http.Server{Handler: testcore.NewHandler(), ReadHeaderTimeout: 5 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	fmt.Println("http://" + listener.Addr().String())
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
