package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver/host"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver/hostapi"
)

type stringsFlag []string

func (values *stringsFlag) String() string { return "<redacted>" }
func (values *stringsFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		fatal("execution driver host subcommand is required")
	}
	var err error
	switch os.Args[1] {
	case "install":
		err = install(os.Args[2:])
	case "serve":
		err = serve(os.Args[2:])
	default:
		err = errors.New("execution driver host subcommand is invalid")
	}
	if err != nil {
		fatal(err.Error())
	}
}

func install(arguments []string) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	destination := flags.String("destination", "", "absolute installation destination")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || *destination == "" || !filepath.IsAbs(*destination) {
		return errors.New("execution driver host install configuration is invalid")
	}
	source, err := os.Executable()
	if err != nil {
		return errors.New("execution driver host executable is unavailable")
	}
	input, err := os.Open(source)
	if err != nil {
		return errors.New("execution driver host executable could not be opened")
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(*destination), 0o755); err != nil {
		return errors.New("execution driver host destination is unavailable")
	}
	temporary := *destination + ".tmp"
	// An interrupted init-container attempt may leave only this private fixed
	// temporary path in the fresh emptyDir. Remove it before the bounded retry;
	// a completed destination is replaced atomically below.
	if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("execution driver host temporary destination could not be reset")
	}
	output, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o555)
	if err != nil {
		return errors.New("execution driver host temporary destination is unavailable")
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil || os.Chmod(temporary, 0o555) != nil || os.Rename(temporary, *destination) != nil {
		_ = os.Remove(temporary)
		return errors.New("execution driver host installation failed")
	}
	return nil
}

func serve(arguments []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	listen := flags.String("listen", ":9443", "HTTPS listen address")
	driverInstance := flags.String("driver-instance", "", "logical registration name")
	driverCommand := flags.String("driver-command", "", "absolute driver executable")
	tlsCert := flags.String("tls-cert", "", "TLS certificate path")
	tlsKey := flags.String("tls-key", "", "TLS private key path")
	authToken := flags.String("auth-token", "", "bearer-token path")
	initializeTimeout := flags.Duration("initialize-timeout", 30*time.Second, "driver initialize timeout")
	operationTimeout := flags.Duration("operation-timeout", 2*time.Minute, "driver operation timeout")
	shutdownTimeout := flags.Duration("shutdown-timeout", 15*time.Second, "driver shutdown timeout")
	terminationGrace := flags.Duration("termination-grace", 5*time.Second, "driver termination grace")
	restartBackoff := flags.Duration("restart-backoff", 5*time.Second, "driver restart backoff")
	var driverArgs stringsFlag
	var passEnvironment stringsFlag
	flags.Var(&driverArgs, "driver-arg", "driver argument (repeatable)")
	flags.Var(&passEnvironment, "pass-env", "required driver environment name (repeatable)")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || *driverInstance == "" || *driverCommand == "" || *tlsCert == "" || *tlsKey == "" || *authToken == "" {
		return errors.New("execution driver host serve configuration is invalid")
	}

	rootContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	token, err := hostapi.LoadToken(*authToken)
	if err != nil {
		return err
	}
	if _, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey); err != nil {
		return errors.New("execution driver host TLS identity is unavailable")
	}
	client, err := host.NewLocalExecutable(rootContext, host.LocalExecutableConfig{
		DriverInstanceName: *driverInstance,
		ExecutablePath:     *driverCommand,
		Args:               driverArgs,
		PassEnv:            passEnvironment,
		InitializeTimeout:  *initializeTimeout,
		OperationTimeout:   *operationTimeout,
		ShutdownTimeout:    *shutdownTimeout,
		TerminationGrace:   *terminationGrace,
		RestartBackoff:     *restartBackoff,
	})
	if err != nil {
		return errors.New("execution driver could not be initialized")
	}
	handler, err := hostapi.NewServer(hostapi.ServerConfig{Client: client, BearerToken: token, OperationTimeout: *operationTimeout})
	if err != nil {
		shutdownClient(client, *shutdownTimeout)
		return err
	}
	server := &http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       *operationTimeout + 5*time.Second,
		WriteTimeout:      *operationTimeout + 5*time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	serveError := make(chan error, 1)
	go func() { serveError <- server.ListenAndServeTLS(*tlsCert, *tlsKey) }()
	select {
	case <-rootContext.Done():
	case err := <-serveError:
		if !errors.Is(err, http.ErrServerClosed) {
			shutdownClient(client, *shutdownTimeout)
			return errors.New("execution driver host HTTPS service failed")
		}
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), *shutdownTimeout)
	defer cancel()
	_ = server.Shutdown(shutdownContext)
	if err := client.Shutdown(shutdownContext); err != nil {
		return errors.New("execution driver host shutdown failed")
	}
	return nil
}

func shutdownClient(client *host.LocalExecutable, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = client.Shutdown(ctx)
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
