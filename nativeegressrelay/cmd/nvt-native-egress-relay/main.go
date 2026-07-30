// Command nvt-native-egress-relay runs the provider-neutral native-egress
// authenticated session boundary. It resolves only an optional process-owned
// exact-binding egressd snapshot and remains deny-all when that snapshot is
// omitted.
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mirkoSekulic/nvt-agent/nativeegressrelay/relay"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

const defaultConfigPath = "/etc/nvt-agent/native-egress-relay.json"

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Print("nvt-native-egress-relay: unavailable")
		os.Exit(1)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("nvt-native-egress-relay", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", defaultConfigPath, "path to process-owned relay configuration")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("native egress relay arguments are invalid")
	}
	config, err := relay.LoadConfiguration(*configPath)
	if err != nil {
		return err
	}
	server, err := relay.NewServer(config, nil)
	if err != nil {
		return err
	}
	lifetime, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errorsChannel := make(chan error, 1)
	go func() { errorsChannel <- server.ListenAndServe() }()
	select {
	case err := <-errorsChannel:
		return err
	case <-lifetime.Done():
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), nativeegress.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		return errors.New("native egress relay shutdown failed")
	}
	return nil
}
