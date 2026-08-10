package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mirkoSekulic/nvt-agent/credentialportal/internal/portal"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("credential portal: %v", err)
	}
}

func run() error {
	configPath := os.Getenv("NVT_CREDENTIAL_PORTAL_CONFIG")
	if configPath == "" {
		configPath = "/etc/nvt-credential-portal/config.json"
	}
	// #nosec G304,G703 -- the deployment administrator explicitly chooses the read-only config path.
	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("open config: %w", err)
	}
	cfg, decodeErr := portal.DecodeConfig(file)
	closeErr := file.Close()
	if closeErr != nil {
		return fmt.Errorf("close config: %w", closeErr)
	}
	if decodeErr != nil {
		return fmt.Errorf("validate config: %w", decodeErr)
	}
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("create Kubernetes config: %w", err)
	}
	coreClient, err := corev1client.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("create Kubernetes client: %w", err)
	}
	auth, err := portal.NewAuthenticator(
		context.Background(),
		cfg,
		os.Getenv("NVT_CREDENTIAL_PORTAL_SESSION_SECRET"),
		os.Getenv("NVT_CREDENTIAL_PORTAL_CLIENT_ID"),
		os.Getenv("NVT_CREDENTIAL_PORTAL_CLIENT_SECRET"),
		nil,
	)
	if err != nil {
		return fmt.Errorf("configure authentication: %w", err)
	}
	handler := portal.NewServer(
		cfg,
		auth,
		portal.KubernetesSecretPatcher{Client: coreClient.RESTClient()},
		portal.NewAuditLogger(os.Stdout),
	)
	defer handler.Close()
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}
	lifetime, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errorsChannel := make(chan error, 1)
	go func() {
		log.Print("nvt-credential-portal listening")
		errorsChannel <- server.ListenAndServe()
	}()
	select {
	case err := <-errorsChannel:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-lifetime.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			return fmt.Errorf("shut down HTTP server: %w", err)
		}
	}
	return nil
}
