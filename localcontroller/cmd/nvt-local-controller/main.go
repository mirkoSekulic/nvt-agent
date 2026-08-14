package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
)

func main() {
	logger := log.New(os.Stdout, "nvt-local-controller: ", log.LstdFlags|log.LUTC)
	config, err := controller.ConfigFromEnvironment()
	if err != nil {
		logger.Fatal("startup failed reason=invalid-configuration")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	store, err := controller.OpenStore(ctx, config.StatePath, controller.StoreOptions{
		MaxActiveRuns: config.MaxActiveRuns, MaxClaimLease: config.MaxClaimLease,
	})
	if err != nil {
		logger.Fatal("startup failed reason=state-unavailable")
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Print("shutdown warning reason=state-close-failed")
		}
	}()

	server := &http.Server{
		Addr: config.Bind, Handler: controller.NewHTTPHandler(store, logger),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
	}
	go sweep(ctx, logger, store, config.SweepInterval)
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.ListenAndServe() }()
	logger.Print("started")
	select {
	case <-ctx.Done():
	case err := <-serveErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("server stopped reason=listen-failed")
		}
	}
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		logger.Print("shutdown warning reason=http-shutdown-failed")
	}
}

func sweep(ctx context.Context, logger *log.Logger, store *controller.Store, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			operationContext, cancel := context.WithTimeout(ctx, interval)
			changed, err := store.Sweep(operationContext)
			cancel()
			if err != nil {
				logger.Print("sweep warning reason=state-unavailable")
			} else if changed > 0 {
				logger.Printf("sweep changed=%d", changed)
			}
		}
	}
}
