package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/nativesession"
)

func main() {
	configPath := flag.String("config", "/etc/nvt-agent/session.json", "native guest session configuration")
	flag.Parse()
	if flag.NArg() != 0 || effectiveUID() != 0 {
		fatal("invalid startup configuration")
	}
	configuration, err := nativesession.LoadConfiguration(*configPath)
	if err != nil {
		fatal("configuration unavailable")
	}
	connector, err := nativesession.NewTLSConnectorFromFile(configuration.CAPEMPath)
	if err != nil {
		fatal("trust unavailable")
	}
	if err := configureConnector(connector); err != nil {
		fatal("transport unavailable")
	}
	runtime, err := nativesession.NewRuntime(configuration, &nativesession.IdentityClient{SocketPath: configuration.IdentitySocketPath}, connector)
	if err != nil {
		fatal("runtime unavailable")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := runtime.Run(ctx); err != nil {
		fatal("session lifecycle failed")
	}
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, "nvt-guest-sessiond: "+message)
	os.Exit(1)
}
