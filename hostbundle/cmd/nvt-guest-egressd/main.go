package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/nativeegress"
)

func main() {
	configPath := flag.String("config", "/etc/nvt-agent/native-egress.json", "native guest egress configuration")
	flag.Parse()
	if flag.NArg() != 0 || effectiveUID() != 0 {
		fatal("invalid startup configuration")
	}
	configuration, err := nativeegress.LoadConfiguration(*configPath)
	if err != nil {
		fatal("configuration unavailable")
	}
	connector, err := nativeegress.NewTLSConnectorFromFile(configuration.CAPEMPath)
	if err != nil {
		fatal("trust unavailable")
	}
	if err := configureConnector(connector); err != nil {
		fatal("transport unavailable")
	}
	runtime, err := nativeegress.NewRuntime(
		configuration,
		&nativeegress.IdentityClient{SocketPath: configuration.IdentitySocketPath},
		connector,
	)
	if err != nil {
		fatal("runtime unavailable")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := runtime.Run(ctx); err != nil {
		fatal("egress lifecycle failed")
	}
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, "nvt-guest-egressd: "+message)
	os.Exit(1)
}
