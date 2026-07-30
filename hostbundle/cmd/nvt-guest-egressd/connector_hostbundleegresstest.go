//go:build hostbundleegresstest

package main

import (
	"context"
	"errors"
	"net"
	"os"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/nativeegress"
)

func configureConnector(connector *nativeegress.TLSConnector) error {
	address := os.Getenv("NVT_GUEST_EGRESS_TEST_DIAL_ADDRESS")
	if address == "" {
		return errors.New("test dial address is unavailable")
	}
	connector.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	return nil
}
