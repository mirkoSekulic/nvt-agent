package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/nativecapture"
)

func main() {
	configPath := flag.String("config", "/etc/nvt-agent/native-capture.json", "native guest capture configuration")
	flag.Parse()
	if flag.NArg() != 0 || os.Geteuid() != 0 {
		fatal("invalid startup configuration")
	}
	configuration, err := nativecapture.LoadConfiguration(*configPath)
	if err != nil {
		fatal("configuration unavailable")
	}
	server, err := nativecapture.NewServer(configuration)
	if err != nil {
		fatal("capture unavailable")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := server.Start(ctx); err != nil {
		fatal("capture unavailable")
	}
	select {
	case <-ctx.Done():
		_ = server.Close()
	case <-server.Done():
		_ = server.Close()
		fatal("capture failed")
	}
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, "nvt-guest-captured: "+message)
	os.Exit(1)
}
