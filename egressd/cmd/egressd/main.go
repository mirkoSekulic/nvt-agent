// Command egressd runs the credential-injecting egress proxy for mediated
// agent runs (protocol/injection.md).
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/mirkoSekulic/nvt-agent/egressd/internal/egress"
)

const forwardProxyReadHeaderTimeout = 5 * time.Second

func main() {
	if err := run(); err != nil {
		log.Printf("egressd: %v", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := os.Getenv("NVT_EGRESSD_CONFIG")
	if configPath == "" {
		configPath = "/etc/nvt-egressd/config.json"
	}
	config, err := egress.LoadConfig(configPath)
	if err != nil {
		return err
	}
	var broker *egress.BrokerClient
	if len(config.Routes) > 0 {
		token := os.Getenv("NVT_BROKER_TOKEN")
		if token == "" {
			return fmt.Errorf("NVT_BROKER_TOKEN is required when injection routes are configured")
		}
		brokerHTTP, err := brokerHTTPClient(config)
		if err != nil {
			return err
		}
		broker = &egress.BrokerClient{URL: config.BrokerURL, Token: token, Client: brokerHTTP}
	}
	transport := &http.Transport{ForceAttemptHTTP2: true}
	listenerCount := len(config.Routes)
	if config.ForwardProxy != nil {
		listenerCount++
	}
	errors := make(chan error, listenerCount)
	for _, route := range config.Routes {
		proxy := &egress.Proxy{Route: route, Broker: broker, Transport: transport}
		server := &http.Server{Addr: route.Listen, Handler: proxy}
		scheme := "http"
		if route.TLSEnabled() {
			scheme = "https"
		}
		log.Printf("egressd: routing %s (%s) -> %s (capability %s)", route.Listen, scheme, route.Upstream, route.Capability)
		go func(route egress.Route, server *http.Server) {
			if route.TLSEnabled() {
				errors <- server.ListenAndServeTLS(route.ListenTLSCert, route.ListenTLSKey)
				return
			}
			errors <- server.ListenAndServe()
		}(route, server)
	}
	if config.ForwardProxy != nil {
		proxy := &egress.ForwardProxy{
			Config: *config.ForwardProxy,
			Logger: log.New(os.Stdout, "", 0),
		}
		server := &http.Server{
			Addr:              config.ForwardProxy.Listen,
			Handler:           proxy,
			ReadHeaderTimeout: forwardProxyReadHeaderTimeout,
		}
		go func() {
			errors <- server.ListenAndServe()
		}()
	}
	return <-errors
}

func brokerHTTPClient(config *egress.Config) (*http.Client, error) {
	if config.BrokerCAFile == "" {
		return http.DefaultClient, nil
	}
	pem, err := os.ReadFile(config.BrokerCAFile)
	if err != nil {
		return nil, fmt.Errorf("read broker CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("broker CA file contains no certificates")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	return &http.Client{Transport: transport}, nil
}
