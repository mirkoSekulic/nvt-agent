package registry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver/host"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver/hostapi"
)

type fakeClient struct {
	shutdown atomic.Int32
}

func (*fakeClient) Reconcile(context.Context, executiondriver.DesiredExecution) (executiondriver.Status, error) {
	return executiondriver.Status{}, nil
}
func (*fakeClient) Observe(context.Context, string) (executiondriver.Status, error) {
	return executiondriver.Status{}, nil
}
func (*fakeClient) Delete(context.Context, string) (executiondriver.Status, error) {
	return executiondriver.Status{}, nil
}
func (f *fakeClient) Shutdown(context.Context) error {
	f.shutdown.Add(1)
	return nil
}

func TestLoadStrictRegistryAndExactLookup(t *testing.T) {
	path := writeRegistry(t, validRegistry("driver-a"))
	var received hostapi.ClientConfig
	client := &fakeClient{}
	registry, err := load(path, func(config hostapi.ClientConfig) (host.Client, error) {
		received = config
		return client, nil
	})
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	if selected, found := registry.Client("driver-a"); !found || selected != client {
		t.Fatal("exact registration was not loaded")
	}
	if _, found := registry.Client("driver-b"); found {
		t.Fatal("unknown registration unexpectedly resolved")
	}
	if received.BaseURL != "https://nvt-execution-driver-driver-a.nvt.svc:9443" ||
		received.ServerName != "nvt-execution-driver-driver-a.nvt.svc" ||
		received.RequestTimeout != defaultRequestTimeout {
		t.Fatalf("unexpected client configuration: %#v", received)
	}
	if err := registry.Shutdown(context.Background()); err != nil || client.shutdown.Load() != 1 {
		t.Fatalf("shutdown error=%v count=%d", err, client.shutdown.Load())
	}
	if err := registry.Shutdown(context.Background()); err != nil || client.shutdown.Load() != 1 {
		t.Fatalf("repeated shutdown error=%v count=%d", err, client.shutdown.Load())
	}
}

func TestLoadRejectsMalformedRegistryBeforeUsableClient(t *testing.T) {
	valid := validRegistry("driver-a")
	tests := map[string]string{
		"unknown field":       strings.Replace(valid, `"version":1`, `"version":1,"extra":true`, 1),
		"duplicate field":     strings.Replace(valid, `"name":"driver-a"`, `"name":"driver-a","name":"driver-b"`, 1),
		"duplicate name":      strings.Replace(valid, `]}`, `,`+registrationJSON("driver-a")+`]}`, 1),
		"unsupported version": strings.Replace(valid, `"version":1`, `"version":2`, 1),
		"endpoint path":       strings.Replace(valid, `:9443"`, `:9443/v1"`, 1),
		"endpoint query":      strings.Replace(valid, `:9443"`, `:9443?x=1"`, 1),
		"wrong server name":   strings.Replace(valid, `"serverName":"nvt-execution-driver-driver-a.nvt.svc"`, `"serverName":"other.nvt.svc"`, 1),
		"IP endpoint":         strings.Replace(valid, `nvt-execution-driver-driver-a.nvt.svc`, `127.0.0.1`, 2),
		"wrong CA path":       strings.Replace(valid, `/driver-a/ca.crt`, `/driver-b/ca.crt`, 1),
		"wrong token path":    strings.Replace(valid, `/driver-a/auth-token`, `/driver-b/auth-token`, 1),
		"empty registrations": `{"version":1,"registrations":[]}`,
		"invalid UTF-8":       string([]byte{'{', '"', 0xff, '"', ':', '1', '}'}),
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			starts := 0
			_, err := load(writeRegistry(t, document), func(hostapi.ClientConfig) (host.Client, error) {
				starts++
				return &fakeClient{}, nil
			})
			if err == nil || strings.Contains(err.Error(), "driver-a") || starts != 0 {
				t.Fatalf("error=%v starts=%d", err, starts)
			}
		})
	}
}

func TestLoadRejectsMalformedTrustMaterialAndClosesEarlierClients(t *testing.T) {
	document := `{"version":1,"registrations":[` + registrationJSON("driver-a") + `,` + registrationJSON("driver-b") + `]}`
	first := &fakeClient{}
	created := 0
	_, err := load(writeRegistry(t, document), func(hostapi.ClientConfig) (host.Client, error) {
		created++
		if created == 2 {
			return nil, errors.New("SECRET-CANARY malformed certificate")
		}
		return first, nil
	})
	if err == nil || strings.Contains(err.Error(), "SECRET-CANARY") || first.shutdown.Load() != 1 {
		t.Fatalf("error=%v first shutdown=%d", err, first.shutdown.Load())
	}
}

func TestRegistryManagerLifecycleIsBounded(t *testing.T) {
	client := &fakeClient{}
	registry := &Registry{clients: map[string]host.Client{"driver-a": client}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- registry.Start(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil || client.shutdown.Load() != 1 {
			t.Fatalf("start returned err=%v shutdown=%d", err, client.shutdown.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("registry lifecycle did not terminate")
	}
}

func TestLoadConfiguredOmittedPreservesEmptyRegistry(t *testing.T) {
	t.Setenv(EnvironmentFile, "")
	registry, err := LoadConfigured()
	if err != nil {
		t.Fatal(err)
	}
	if _, found := registry.Client("anything"); found {
		t.Fatal("omitted registry returned a client")
	}
}

func TestRegistryFileIsBoundedAndMustUseCanonicalAbsolutePath(t *testing.T) {
	if _, err := load("relative.json", func(hostapi.ClientConfig) (host.Client, error) { return &fakeClient{}, nil }); err == nil {
		t.Fatal("relative registry path was accepted")
	}
	path := filepath.Join(t.TempDir(), "oversized.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxRegistryBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := load(path, func(hostapi.ClientConfig) (host.Client, error) { return &fakeClient{}, nil }); err == nil {
		t.Fatal("oversized registry was accepted")
	}
}

func validRegistry(name string) string {
	return `{"version":1,"registrations":[` + registrationJSON(name) + `]}`
}

func registrationJSON(name string) string {
	hostname := "nvt-execution-driver-" + name + ".nvt.svc"
	root := projectionRoot + "/" + name
	return `{"name":"` + name + `","url":"https://` + hostname + `:9443","serverName":"` + hostname + `","caFile":"` + root + `/ca.crt","tokenFile":"` + root + `/auth-token"}`
}

func writeRegistry(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registrations.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
