package egress

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"net/http"
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
		"::", "::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "64:ff9b::a00:1",
		"64:ff9b::a9fe:a9fe", "2002:7f00:1::1", "fc00::1", "fe80::1", "fec0::1", "ff02::1", "2001:db8::1",
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

func TestDestinationPolicyDeniesNAT64PrivateAndMetadataCanaries(t *testing.T) {
	policy, err := newDestinationPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"64:ff9b::7f00:1",      // 127.0.0.1
		"64:ff9b::a00:1",       // 10.0.0.1
		"64:ff9b::c0a8:101",    // 192.168.1.1
		"64:ff9b::a9fe:a9fe",   // 169.254.169.254
		"64:ff9b:1::a9fe:a9fe", // local-use NAT64 metadata
	} {
		if policy.allowed(netip.MustParseAddr(value)) {
			t.Errorf("policy allowed NAT64 canary %s", value)
		}
	}
}

func TestResolveAllowedAddressRejectsAnyDeniedCandidate(t *testing.T) {
	policy, _ := newDestinationPolicy(nil)
	resolver := &staticResolver{addresses: []netip.Addr{
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("169.254.169.254"),
	}}
	if _, err := resolveAllowedAddresses(context.Background(), resolver, policy, "mixed.example"); err == nil {
		t.Fatal("mixed public/private DNS answer must fail closed")
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want exactly one", resolver.calls)
	}
}

func TestForwardProxyPrefersIPv4AndFallsBackAcrossValidatedAddresses(t *testing.T) {
	resolver := &staticResolver{addresses: []netip.Addr{
		netip.MustParseAddr("2606:4700:4700::1111"),
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("93.184.216.35"),
	}}
	dialed := []string{}
	proxy := &ForwardProxy{
		Resolver: resolver,
		DialContext: func(_ context.Context, _ string, address string) (net.Conn, error) {
			dialed = append(dialed, address)
			if address == "93.184.216.35:80" {
				client, peer := net.Pipe()
				_ = peer.Close()
				return client, nil
			}
			return nil, errors.New("fixture address unavailable")
		},
	}
	policy, err := newDestinationPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy.destinationPolicy = policy
	connection, err := proxy.dialResolvedTarget(context.Background(), "packages.example", "80")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if got, want := strings.Join(dialed, ","), "93.184.216.34:80,93.184.216.35:80"; got != want {
		t.Fatalf("dial order = %q, want %q", got, want)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want one", resolver.calls)
	}
}

func TestForwardProxyRejectsEmptyResolvedAddressSet(t *testing.T) {
	proxy := &ForwardProxy{}
	if _, err := proxy.dialResolvedAddresses(context.Background(), nil, "443"); err == nil || !strings.Contains(err.Error(), "no validated addresses") {
		t.Fatalf("empty address error = %v, want explicit rejection", err)
	}
}

func TestForwardProxyStopsFallbackDialingWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dials := 0
	proxy := &ForwardProxy{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			dials++
			cancel()
			return nil, errors.New("fixture address unavailable")
		},
	}
	addresses := []netip.Addr{
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("93.184.216.35"),
	}
	_, err := proxy.dialResolvedAddresses(ctx, addresses, "443")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("dial error = %v, want context cancellation", err)
	}
	if dials != 1 {
		t.Fatalf("dial attempts = %d, want one", dials)
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

func TestInjectRouteTransportResolvesOnceAndDialsValidatedAddress(t *testing.T) {
	resolver := &staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	var dialed string
	proxy := &ForwardProxy{
		Resolver:  resolver,
		Transport: &http.Transport{},
		DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" {
				t.Fatalf("network = %q", network)
			}
			dialed = address
			client, peer := net.Pipe()
			_ = peer.Close()
			return client, nil
		},
	}
	policy, err := newDestinationPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy.destinationPolicy = policy
	transport, ok := proxy.injectRouteTransport(ForwardProxyInjectRoute{}).(*http.Transport)
	if !ok || transport.DialContext == nil {
		t.Fatalf("inject transport = %T, want policy-pinned *http.Transport", transport)
	}
	conn, err := transport.DialContext(context.Background(), "tcp", "api.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if dialed != "93.184.216.34:443" {
		t.Fatalf("dialed %q, want validated address", dialed)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want one", resolver.calls)
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
