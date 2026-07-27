// Package registry loads the bounded, installation-owned registry of remote
// execution-driver hosts. Loading validates local trust material only; it does
// not contact a host, so temporary host unavailability remains per-AgentRun.
package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver/host"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver/hostapi"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver/registration"
)

const (
	EnvironmentFile              = "NVT_EXECUTION_DRIVER_REGISTRATIONS_FILE"
	Version                      = 1
	maxRegistryBytes             = 256 << 10
	defaultRequestTimeout        = 2 * time.Minute
	defaultClientShutdownTimeout = 10 * time.Second
	projectionRoot               = "/var/run/nvt-execution-drivers"
)

type document struct {
	Version       int                 `json:"version"`
	Registrations []registrationEntry `json:"registrations"`
}

type registrationEntry struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	ServerName string `json:"serverName"`
	CAFile     string `json:"caFile"`
	TokenFile  string `json:"tokenFile"`
}

type clientFactory func(hostapi.ClientConfig) (host.Client, error)

// Registry is an immutable exact-name lookup plus bounded client lifecycle.
type Registry struct {
	clients map[string]host.Client
	once    sync.Once
	result  error
}

// LoadConfigured loads the registry only when EnvironmentFile is configured.
// An empty setting preserves the built-in Kubernetes-only installation.
func LoadConfigured() (*Registry, error) {
	path := os.Getenv(EnvironmentFile)
	if path == "" {
		return &Registry{clients: map[string]host.Client{}}, nil
	}
	return load(path, func(config hostapi.ClientConfig) (host.Client, error) {
		return hostapi.NewClient(config)
	})
}

func load(path string, factory clientFactory) (*Registry, error) {
	data, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	var value document
	if executiondriver.DecodeStrictJSON(data, &value) != nil || value.Version != Version ||
		len(value.Registrations) == 0 || len(value.Registrations) > registration.MaxRegistrations {
		return nil, errors.New("execution driver registry is invalid")
	}
	clients := make(map[string]host.Client, len(value.Registrations))
	seen := make(map[string]struct{}, len(value.Registrations))
	for _, entry := range value.Registrations {
		if _, duplicate := seen[entry.Name]; duplicate || validateEntry(entry) != nil {
			return nil, errors.New("execution driver registry is invalid")
		}
		seen[entry.Name] = struct{}{}
	}
	closeClients := func() {
		ctx, cancel := context.WithTimeout(context.Background(), defaultClientShutdownTimeout)
		defer cancel()
		shutdownClients(ctx, clients)
	}
	for _, entry := range value.Registrations {
		client, createErr := factory(hostapi.ClientConfig{
			BaseURL: entry.URL, ServerName: entry.ServerName, CAFile: entry.CAFile,
			BearerTokenFile: entry.TokenFile, RequestTimeout: defaultRequestTimeout,
		})
		if createErr != nil {
			closeClients()
			return nil, errors.New("execution driver registry trust material is invalid")
		}
		clients[entry.Name] = client
	}
	return &Registry{clients: clients}, nil
}

func readBounded(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("execution driver registry path is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("execution driver registry is unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRegistryBytes+1))
	if err != nil || len(data) > maxRegistryBytes {
		return nil, errors.New("execution driver registry is invalid")
	}
	return data, nil
}

func validateEntry(entry registrationEntry) error {
	if len(validation.IsDNS1123Label(entry.Name)) != 0 {
		return errors.New("name")
	}
	endpoint, err := url.Parse(entry.URL)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Opaque != "" ||
		endpoint.RawPath != "" || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.ForceQuery ||
		endpoint.Fragment != "" || endpoint.Hostname() != entry.ServerName ||
		endpoint.Port() != strconv.Itoa(registration.DriverHostPort) || net.ParseIP(endpoint.Hostname()) != nil ||
		len(validation.IsDNS1123Subdomain(entry.ServerName)) != 0 || endpoint.String() != entry.URL {
		return errors.New("endpoint")
	}
	root := filepath.Join(projectionRoot, entry.Name)
	if entry.CAFile != filepath.Join(root, "ca.crt") || entry.TokenFile != filepath.Join(root, "auth-token") {
		return errors.New("projection")
	}
	return nil
}

// Client returns only the exact logical registration name.
func (r *Registry) Client(name string) (host.Client, bool) {
	client, found := r.clients[name]
	return client, found
}

// Start implements manager.Runnable and authoritatively closes every client
// when the manager context ends.
func (r *Registry) Start(ctx context.Context) error {
	<-ctx.Done()
	shutdownContext, cancel := context.WithTimeout(context.Background(), defaultClientShutdownTimeout)
	defer cancel()
	return r.Shutdown(shutdownContext)
}

// Shutdown closes all clients concurrently within one caller-owned deadline.
func (r *Registry) Shutdown(ctx context.Context) error {
	r.once.Do(func() { r.result = shutdownClients(ctx, r.clients) })
	return r.result
}

func shutdownClients(ctx context.Context, clients map[string]host.Client) error {
	var wait sync.WaitGroup
	errorsChannel := make(chan error, len(clients))
	for _, client := range clients {
		wait.Add(1)
		go func(value host.Client) {
			defer wait.Done()
			if err := value.Shutdown(ctx); err != nil {
				errorsChannel <- err
			}
		}(client)
	}
	wait.Wait()
	close(errorsChannel)
	for range errorsChannel {
		return fmt.Errorf("execution driver clients did not shut down cleanly")
	}
	return nil
}
