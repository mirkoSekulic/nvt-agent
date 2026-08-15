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
	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/dockerbackend"
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
	backend, err := dockerbackend.New(dockerbackend.Config{
		DockerHost: config.DockerHost, RunsDir: config.RunsDir, BrokerURL: config.BrokerURL, BrokerCAFile: config.BrokerCAFile,
		BrokerAgentsPath: config.BrokerAgentsPath, IdentityKeyPath: config.IdentityKeyPath, Owner: config.ControllerOwner,
		ExternalNetwork: config.ExternalNetwork, RunNetworkPool: config.RunNetworkPool, ProxyPort: config.ProxyPort, ProtectedCIDRs: config.ProtectedCIDRs, DindImage: config.DindImage, EgressdImage: config.EgressdImage,
		RouteBaseDomain: config.RouteBaseDomain, RoutePathPrefix: config.RoutePathPrefix, GatewayContainer: config.GatewayContainer,
		CapturedImage: config.CapturedImage, SeedImage: config.SeedImage, OperationTimeout: config.BackendOperationTimeout,
	})
	if err != nil {
		logger.Fatal("startup failed reason=backend-unavailable")
	}
	reconcileOwner, err := controller.NewProcessReconcileOwner(config.ControllerOwner)
	if err != nil {
		logger.Fatal("startup failed reason=identity-unavailable")
	}
	reconciler, err := controller.NewReconciler(store, backend, reconcileOwner, config.MaxClaimLease, logger)
	if err != nil {
		logger.Fatal("startup failed reason=invalid-configuration")
	}
	scheduler, err := controller.LoadSchedulers([]string{config.SchedulingConfigPath, config.NamedRunsConfigPath}, store)
	if err != nil {
		logger.Fatal("startup failed reason=scheduling-configuration-unavailable")
	}
	authorization, err := controller.LoadAPIAuthorization(config.AdminTokenFile, config.RouteTokenFile, scheduler)
	if err != nil {
		logger.Fatal("startup failed reason=api-authorization-unavailable")
	}
	handler, err := controller.NewAuthorizedHTTPHandlerWithServices(store, logger, backend.Ready, backend, scheduler, authorization)
	if err != nil {
		logger.Fatal("startup failed reason=api-authorization-unavailable")
	}
	if err := scheduler.BootstrapLocalRuns(ctx); err != nil {
		logger.Fatal("startup failed reason=local-run-configuration-unavailable")
	}

	server := &http.Server{
		Addr: config.Bind, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
	}
	go sweep(ctx, logger, store, config.SweepInterval)
	go reconciler.Run(ctx, config.ReconcileInterval)
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
