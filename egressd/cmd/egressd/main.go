// Command egressd runs the credential-injecting egress proxy for mediated
// agent runs (protocol/injection.md).
package main

import (
	"context"
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
	forwardProxyInjects := config.ForwardProxy != nil && len(config.ForwardProxy.InjectRoutes) > 0
	var broker *egress.BrokerClient
	if len(config.Routes) > 0 || forwardProxyInjects {
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
	var ca *egress.CA
	if config.CA != nil {
		upstreamLeafNames := config.ForwardProxyUpstreamLeafNames()
		if config.CA.CertFile != "" {
			ca, err = egress.LoadCAWithUpstreams(config.CA.CertFile, config.CA.KeyFile, config.CA.LeafDNSNames, upstreamLeafNames)
			if err != nil {
				return err
			}
		} else {
			ca, err = egress.NewCAWithUpstreams(config.CA.LeafDNSNames, upstreamLeafNames)
			if err != nil {
				return err
			}
		}
		if config.CA.PublishDir != "" {
			if err := ca.PublishCert(config.CA.PublishDir); err != nil {
				return err
			}
			log.Printf("egressd: published per-agent CA certificate to %s", config.CA.PublishDir)
		}
		ca.Logger = log.Default()
	}
	transport := &http.Transport{ForceAttemptHTTP2: true}
	// One reporter per process, shared across routes and the forward proxy,
	// draining a bounded queue to the broker's audit endpoint out-of-band.
	reporter := egress.NewReporter(broker)
	if reporter != nil {
		go reporter.Run(context.Background())
	}
	listenerCount := len(config.Routes)
	if config.ForwardProxy != nil {
		listenerCount++
	}
	if config.CA != nil && config.CA.ServeAddr != "" {
		listenerCount++
	}
	errors := make(chan error, listenerCount)
	for _, route := range config.Routes {
		proxy := &egress.Proxy{Route: route, Broker: broker, Transport: transport, Reporter: reporter}
		server := &http.Server{Addr: route.Listen, Handler: proxy}
		scheme := "http"
		if route.TLSEnabled() {
			scheme = "https"
		}
		log.Printf("egressd: routing %s (%s) -> %s (capability %s)", route.Listen, scheme, route.Upstream, route.Capability)
		go func(route egress.Route, server *http.Server) {
			switch {
			case route.ListenTLS == egress.RouteListenTLSCA:
				server.TLSConfig = ca.ServerTLSConfig()
				errors <- server.ListenAndServeTLS("", "")
			case route.TLSEnabled():
				errors <- server.ListenAndServeTLS(route.ListenTLSCert, route.ListenTLSKey)
			default:
				errors <- server.ListenAndServe()
			}
		}(route, server)
	}
	if config.ForwardProxy != nil {
		proxy := &egress.ForwardProxy{
			Config:    *config.ForwardProxy,
			Logger:    log.New(os.Stdout, "", 0),
			Reporter:  reporter,
			CA:        ca,
			Broker:    broker,
			Transport: transport,
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
	if config.CA != nil && config.CA.ServeAddr != "" {
		// Plain HTTP by design: the certificate is public material and is
		// the trust anchor being bootstrapped (egress.CAEndpointHandler).
		server := &http.Server{
			Addr:              config.CA.ServeAddr,
			Handler:           egress.CAEndpointHandler(ca),
			ReadHeaderTimeout: forwardProxyReadHeaderTimeout,
		}
		log.Printf("egressd: serving CA certificate endpoint on %s", config.CA.ServeAddr)
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
