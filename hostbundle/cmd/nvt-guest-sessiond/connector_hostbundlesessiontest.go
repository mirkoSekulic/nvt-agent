//go:build hostbundlesessiontest

package main

import (
	"context"
	"errors"
	"net"
	"os"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/nativesession"
)

func configureConnector(connector *nativesession.TLSConnector) error {
	address := os.Getenv("NVT_GUEST_SESSION_TEST_DIAL_ADDRESS")
	if address == "" {
		return errors.New("test dial address is unavailable")
	}
	connector.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	return nil
}
