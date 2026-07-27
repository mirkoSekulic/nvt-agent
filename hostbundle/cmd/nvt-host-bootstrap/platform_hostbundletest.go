//go:build hostbundletest

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/oci"
)

func effectiveUID() int {
	value, err := strconv.Atoi(os.Getenv("NVT_HOST_BUNDLE_TEST_EUID"))
	if err != nil || value < 0 {
		return -1
	}
	return value
}

func newOCIClient(timeout time.Duration) (*oci.Client, error) {
	certificatePath := os.Getenv("NVT_HOST_BUNDLE_TEST_CA_FILE")
	dialAddress := os.Getenv("NVT_HOST_BUNDLE_TEST_DIAL_ADDRESS")
	certificate, err := os.ReadFile(certificatePath)
	if err != nil || dialAddress == "" {
		return nil, errors.New("test transport is unavailable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certificate) {
		return nil, errors.New("test CA is invalid")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, dialAddress)
	}
	return oci.NewClientWithTransport(timeout, transport)
}
