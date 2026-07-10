package egress

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestDestinationPolicyDeniesNonPublicIPv4AndIPv6(t *testing.T) {
	policy, err := newDestinationPolicy([]string{"203.0.114.0/24", "2001:4860:ffff::/48"})
	if err != nil {
		t.Fatal(err)
	}
	denied := []string{
		"0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.169.254",
		"172.16.0.1", "192.168.1.1", "198.18.0.1", "224.0.0.1", "255.255.255.255",
		"::", "::1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1",
		"203.0.114.9", "2001:4860:ffff::1",
	}
	for _, value := range denied {
		if policy.allowed(netip.MustParseAddr(value)) {
			t.Errorf("policy allowed denied address %s", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"} {
		if !policy.allowed(netip.MustParseAddr(value)) {
			t.Errorf("policy denied public address %s", value)
		}
	}
}

func TestResolveAllowedAddressRejectsAnyDeniedCandidate(t *testing.T) {
	policy, _ := newDestinationPolicy(nil)
	resolver := &staticResolver{addresses: []netip.Addr{
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("169.254.169.254"),
	}}
	if _, err := resolveAllowedAddress(context.Background(), resolver, policy, "mixed.example"); err == nil {
		t.Fatal("mixed public/private DNS answer must fail closed")
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want exactly one", resolver.calls)
	}
}

func TestForwardProxyResolvesOnceAndDialsValidatedAddress(t *testing.T) {
	resolver := &staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	var dialed string
	var logs bytes.Buffer
	proxy := &ForwardProxy{
		Config:   ForwardProxyConfig{AllowUnmatchedHosts: true, AllowPorts: []int{443}},
		Resolver: resolver,
		Logger:   log.New(&logs, "", 0),
		DialContext: func(_ context.Context, _ string, address string) (net.Conn, error) {
			dialed = address
			return nil, errors.New("fixture dial stop")
		},
	}
	server := httptest.NewServer(proxy)
	defer server.Close()
	conn, status := sendRawProxyRequest(t, proxyAddress(t, server),
		"CONNECT rebound.example:443 HTTP/1.1\r\nHost: rebound.example:443\r\n\r\n")
	defer conn.Close()
	if !strings.Contains(status, "502") {
		t.Fatalf("CONNECT status = %q", status)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want one", resolver.calls)
	}
	if dialed != "93.184.216.34:443" {
		t.Fatalf("dialed %q, want validated address", dialed)
	}
}

func TestForwardProxyDeniesPrivateLiteralBeforeDial(t *testing.T) {
	var dialed bool
	proxy := &ForwardProxy{
		Config: ForwardProxyConfig{AllowUnmatchedHosts: true, AllowPorts: []int{443}},
		Logger: log.New(&bytes.Buffer{}, "", 0),
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("must not dial")
		},
	}
	server := httptest.NewServer(proxy)
	defer server.Close()
	conn, status := sendRawProxyRequest(t, proxyAddress(t, server),
		"CONNECT 169.254.169.254:443 HTTP/1.1\r\nHost: 169.254.169.254:443\r\n\r\n")
	defer conn.Close()
	if !strings.Contains(status, "403") || dialed {
		t.Fatalf("private destination status=%q dialed=%v", status, dialed)
	}
}
