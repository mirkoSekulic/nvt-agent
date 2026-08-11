package main

import (
	"context"
	"errors"
	"flag"
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

var (
	errRunnerKeygenArguments = errors.New("runner-keygen requires exactly one output path")
	errUnknownCommand        = errors.New("unknown credential portal command")
	errRunnerArguments       = errors.New("invalid credential runner arguments")
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("credential portal: %v", err)
	}
}

func run() error {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "runner":
			return runCredentialRunner(os.Args[2:])
		case "runner-keygen":
			if len(os.Args) != 3 {
				return errRunnerKeygenArguments
			}
			if err := portal.GenerateRunnerKeyFile(os.Args[2]); err != nil {
				return fmt.Errorf("initialize credential runner authentication: %w", err)
			}

			return nil
		default:
			return errUnknownCommand
		}
	}

	return runPortal()
}

func runPortal() error {
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
	patcher, broker, err := configureCustody(cfg)
	if err != nil {
		return err
	}
	if broker != nil {
		defer broker.Close()
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
	runnerKeyPath := os.Getenv("NVT_CREDENTIAL_RUNNER_AUTH_KEY_FILE")
	runnerURL := os.Getenv("NVT_CREDENTIAL_RUNNER_URL")
	runnerKey, err := portal.ReadRunnerKey(runnerKeyPath)
	if err != nil {
		return fmt.Errorf("read credential runner authentication: %w", err)
	}
	defer clearSensitive(runnerKey)
	runner, err := portal.NewHTTPRunnerClient(runnerURL, runnerKey, cfg.Enrollment.MaxOutputBytes)
	if err != nil {
		return fmt.Errorf("configure credential runner: %w", err)
	}
	handler := portal.NewServer(cfg, auth, patcher, portal.NewAuditLogger(os.Stdout), runner, broker)
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

func configureCustody(
	cfg portal.Config,
) (portal.SecretPatcher, *portal.HTTPPrincipalAccountBroker, error) {
	if cfg.Dynamic.Enabled {
		broker, err := portal.NewHTTPPrincipalAccountBroker(cfg.Dynamic.Broker)
		if err != nil {
			return nil, nil, fmt.Errorf("configure principal account broker: %w", err)
		}
		return nil, broker, nil
	}
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("create Kubernetes config: %w", err)
	}
	coreClient, err := corev1client.NewForConfig(restConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	return portal.KubernetesSecretPatcher{Client: coreClient.RESTClient()}, nil, nil
}

func runCredentialRunner(args []string) error {
	flags := flag.NewFlagSet("runner", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:8081", "runner listen address")
	keyPath := flags.String("auth-key-file", "", "runner authentication key file")
	maxSessions := flags.Int("max-sessions", 64, "maximum retained runner sessions")
	maxConcurrent := flags.Int("max-concurrent", 2, "maximum concurrent CLI processes")
	timeoutSeconds := flags.Int("timeout-seconds", 600, "maximum CLI process lifetime")
	maxOutputBytes := flags.Int("max-output-bytes", 64*1024, "maximum CLI output and credential size")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *keyPath == "" {
		return errRunnerArguments
	}
	config := portal.EnrollmentConfig{
		MaxSessions: *maxSessions, MaxConcurrent: *maxConcurrent,
		TimeoutSeconds: *timeoutSeconds, MaxOutputBytes: *maxOutputBytes,
	}
	key, err := portal.ReadRunnerKey(*keyPath)
	if err != nil {
		return fmt.Errorf("read credential runner authentication: %w", err)
	}
	defer clearSensitive(key)
	runnerServer, err := portal.NewRunnerServer(key, config, portal.NewCLICredentialRunner(config))
	if err != nil {
		return fmt.Errorf("configure credential runner: %w", err)
	}
	defer runnerServer.Close()
	server := &http.Server{
		Addr: *listen, Handler: runnerServer, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 16 * 1024,
	}
	lifetime, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errorsChannel := make(chan error, 1)
	go func() {
		log.Print("nvt-credential-runner listening")
		errorsChannel <- server.ListenAndServe()
	}()
	select {
	case listenErr := <-errorsChannel:
		if !errors.Is(listenErr, http.ErrServerClosed) {
			return listenErr
		}
	case <-lifetime.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			return fmt.Errorf("shut down credential runner: %w", err)
		}
	}

	return nil
}

func clearSensitive(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
