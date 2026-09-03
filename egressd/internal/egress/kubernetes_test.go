package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

type pinnedResolver struct{ addresses []netip.Addr }

func (r pinnedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.addresses, nil
}

func TestKubernetesCallerCredentialsAndImpersonationHeadersAreStripped(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://route.invalid/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer caller-token")
	request.Header.Set("Proxy-Authorization", "Basic caller")
	request.Header.Set("Impersonate-User", "admin")
	request.Header.Set("Impersonate-Group", "system:masters")
	request.Header.Set("Impersonate-Extra-Scopes", "everything")
	request.Header.Set("X-Preserved", "yes")
	proxy := &Proxy{Route: Route{Upstream: "kubernetes.internal"}}
	outbound, err := proxy.buildOutbound(request, &Material{Headers: map[string]string{"authorization": "Bearer injected-token"}})
	if err != nil {
		t.Fatal(err)
	}
	if outbound.Header.Get("Authorization") != "Bearer injected-token" || outbound.Header.Get("X-Preserved") != "yes" {
		t.Fatalf("replacement/preserved headers = %#v", outbound.Header)
	}
	for _, name := range []string{"Proxy-Authorization", "Impersonate-User", "Impersonate-Group", "Impersonate-Extra-Scopes"} {
		if outbound.Header.Get(name) != "" {
			t.Fatalf("caller header %s reached upstream", name)
		}
	}
}

func TestPinnedRouteResolutionCanReachExactPrivateEndpoint(t *testing.T) {
	private := netip.MustParseAddr("10.20.30.40")
	resolver := pinnedResolver{addresses: []netip.Addr{private}}
	if _, err := resolveAllowedAddresses(context.Background(), resolver, destinationPolicy{denied: defaultDeniedPrefixes}, "api.internal"); err == nil {
		t.Fatal("ordinary forward proxy path accepted a private destination")
	}
	addresses, err := resolvePinnedAddresses(context.Background(), resolver, "api.internal")
	if err != nil || len(addresses) != 1 || addresses[0] != private {
		t.Fatalf("trusted pinned route resolution = %v, %v", addresses, err)
	}
}

func TestCatalogRouteUsesSyntheticHostForBrokerAuthorization(t *testing.T) {
	var requested injectionRequest
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		if err := json.NewDecoder(r.Body).Decode(&requested); err != nil {
			t.Errorf("decode broker request: %v", err)
		}
		_, _ = w.Write([]byte(`{"ok":true,"headers":{"authorization":"Bearer injected"},"append_headers":{},"strip_request_headers":[]}`))
	}))
	defer broker.Close()
	proxy := &Proxy{
		Route:  Route{Capability: "clusters", Upstream: "10.20.30.40:6443", InjectionHost: "k-context.kube.nvt.invalid"},
		Broker: &BrokerClient{URL: broker.URL, Token: "egress", Client: broker.Client()},
	}
	material, err := proxy.material(context.Background(), http.MethodPost, "/api/v1/namespaces")
	if err != nil || !bytes.Equal([]byte(material.Headers["authorization"]), []byte("Bearer injected")) {
		t.Fatalf("material = %#v, %v", material, err)
	}
	if requested.Host != "k-context.kube.nvt.invalid" || requested.Capability != "clusters" {
		t.Fatalf("broker authorization request = %#v", requested)
	}
}

func TestCatalogRouteUsesFrozenCAAndServerIdentity(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("pinned"))
	}))
	defer upstream.Close()
	parsed, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	certificate := upstream.Certificate()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
	proxy := &ForwardProxy{Resolver: pinnedResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}
	transport := proxy.injectRouteTransport(ForwardProxyInjectRoute{
		Upstream: parsed.Host, UpstreamCAPEM: caPEM, UpstreamServerName: "example.com", AllowPrivateUpstream: true,
	})
	request, err := http.NewRequest(http.MethodGet, "https://"+parsed.Host+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("frozen route TLS failed: %v", err)
	}
	_ = response.Body.Close()
	wrong := proxy.injectRouteTransport(ForwardProxyInjectRoute{
		Upstream: parsed.Host, UpstreamCAPEM: caPEM, UpstreamServerName: "wrong.invalid", AllowPrivateUpstream: true,
	})
	_, err = wrong.RoundTrip(request)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("wrong frozen identity was accepted: %v", err)
	}
}
