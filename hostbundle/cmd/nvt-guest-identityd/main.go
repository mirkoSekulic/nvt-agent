package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/guestidentity"
)

func main() {
	configPath := flag.String("config", "/etc/nvt-agent/identity.json", "guest runtime identity configuration")
	flag.Parse()
	if flag.NArg() != 0 || effectiveUID() != 0 {
		fatal("invalid startup configuration")
	}
	configuration, err := guestidentity.LoadConfiguration(*configPath)
	if err != nil {
		fatal("configuration unavailable")
	}
	store, err := guestidentity.OpenStore(configuration)
	if err != nil {
		fatal("state unavailable")
	}
	client, err := guestidentity.NewClientFromFile(configuration.CAPEMPath)
	if err != nil {
		fatal("trust unavailable")
	}
	runtime, err := guestidentity.NewRuntime(store, client)
	if err != nil {
		fatal("runtime unavailable")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, runtime, configuration.RuntimeDirectory, notifySystemdReady); err != nil {
		fatal("identity lifecycle failed")
	}
}

func run(ctx context.Context, runtime *guestidentity.Runtime, runtimeDirectory string, notifyReady func() error) error {
	_ = guestidentity.WriteReadiness(runtimeDirectory, false)
	defer guestidentity.WriteReadiness(runtimeDirectory, false)
	serverContext, stopServer := context.WithCancel(ctx)
	defer stopServer()
	serverDone := make(chan error, 1)
	go func() { serverDone <- guestidentity.ServeSessionCredentials(serverContext, runtime, runtimeDirectory) }()
	notified := false
	for {
		snapshot, wait, err := runtime.Reconcile(ctx)
		if err == nil && snapshot.Ready {
			if writeErr := guestidentity.WriteReadiness(runtimeDirectory, true); writeErr != nil {
				return writeErr
			}
			if !notified {
				if notifyReady != nil {
					if notifyErr := notifyReady(); notifyErr != nil {
						return notifyErr
					}
				}
				notified = true
			}
		} else {
			_ = guestidentity.WriteReadiness(runtimeDirectory, false)
			_, temporary, _ := guestidentity.FailureDetails(err)
			if err != nil && !temporary {
				return err
			}
		}
		if wait <= 0 || wait > 5*time.Minute {
			wait = 5 * time.Minute
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case serverErr := <-serverDone:
			if serverErr == nil && ctx.Err() != nil {
				return nil
			}
			return serverErr
		case <-timer.C:
		}
	}
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, "nvt-guest-identityd: "+message)
	os.Exit(1)
}
