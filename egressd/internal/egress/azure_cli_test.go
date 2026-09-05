package egress

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// Actual pinned CLI -> real egress CONNECT/TLS/injection -> isolated fixture.
// The fixture bridge calls the production classifier and supplies inert token
// material. Broker-core/protocol behavior is covered separately in tests/broker.
// No Azure credentials or cloud calls are used.
func TestAzureCLIThroughMediatedEgress(t *testing.T) {
	python := os.Getenv("NVT_AZURE_CLI_PYTHON")
	if python == "" {
		t.Skip("optional pinned Azure CLI environment not installed")
	}
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", ".."))
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-egress-role" {
			w.WriteHeader(403)
			return
		}
		input, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		command := exec.Command("python3", filepath.Join(root, "tests/azure-cli/authorize_fixture.py"))
		command.Stdin = bytes.NewReader(input)
		output, err := command.Output()
		if err != nil {
			w.WriteHeader(500)
			return
		}
		var result map[string]any
		if json.Unmarshal(output, &result) != nil || result["ok"] != true {
			w.WriteHeader(403)
		}
		_, _ = w.Write(output)
	}))
	defer broker.Close()
	var mu sync.Mutex
	var upstreamCalls []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer fixture-trusted-azure-one" && token != "Bearer fixture-trusted-azure-two" {
			w.WriteHeader(401)
			return
		}
		if r.Header.Get("X-Ms-Authorization-Auxiliary") != "" || r.Header.Get("Proxy-Authorization") != "" {
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		upstreamCalls = append(upstreamCalls, r.Method+" "+r.URL.Path+" "+token)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			_, _ = io.WriteString(w, `{"tables":[{"name":"PrimaryResult","columns":[{"name":"Result","type":"long"}],"rows":[[42]]}]}`)
		} else {
			_, _ = io.WriteString(w, `{"value":[{"name":"fixture","location":"westeurope"}]}`)
		}
	}))
	defer upstream.Close()
	ca, err := NewCAWithUpstreams(nil, []string{"management.azure.com", "api.loganalytics.io"})
	if err != nil {
		t.Fatal(err)
	}
	routes := []ForwardProxyInjectRoute{}
	for _, host := range []string{"management.azure.com", "api.loganalytics.io"} {
		for _, capability := range []string{"azure-one", "azure-two"} {
			routes = append(routes, ForwardProxyInjectRoute{Host: host, Capability: capability, Upstream: strings.TrimPrefix(upstream.URL, "http://"), AllowInsecureUpstream: true})
		}
	}
	proxy := httptest.NewServer(&ForwardProxy{Config: ForwardProxyConfig{Listen: "unused", InjectRoutes: routes}, CA: ca,
		Broker:    &BrokerClient{URL: broker.URL, Token: "fixture-egress-role", Client: broker.Client()},
		Transport: &http.Transport{}, Resolver: &staticResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}})
	defer proxy.Close()
	agentHome := t.TempDir()
	cert := filepath.Join(agentHome, "public-ca.pem")
	if err := os.WriteFile(cert, ca.CertPEM(), 0600); err != nil {
		t.Fatal(err)
	}
	metadata := `{"providers":{"azure-one":{"tenant":"22222222-2222-2222-2222-222222222222","subscriptions":[{"id":"11111111-1111-1111-1111-111111111111"}]},"azure-two":{"tenant":"22222222-2222-2222-2222-222222222222","subscriptions":[{"id":"11111111-1111-1111-1111-111111111111"}]}}}`
	config := filepath.Join(agentHome, "plugin.json")
	if err := os.WriteFile(config, []byte(metadata), 0600); err != nil {
		t.Fatal(err)
	}
	baseEnv := []string{"PATH=" + filepath.Join(agentHome, ".local/bin") + ":/usr/bin:/bin", "HOME=" + agentHome,
		"NVT_STATE_DIR=" + filepath.Join(agentHome, ".nvt-agent"), "NVT_WORKSPACE=" + agentHome, "NVT_EGRESS_MODE=mediated",
		"NVT_PLUGIN_CONFIG=" + config, "NVT_PLUGIN_EGRESS_PROVIDER=azure-one",
		"AZURE_EXTENSION_DIR=" + os.Getenv("AZURE_EXTENSION_DIR"), "REQUESTS_CA_BUNDLE=" + cert}
	for _, capability := range []string{"azure-one", "azure-two"} {
		parsed, _ := url.Parse(proxy.URL)
		parsed.User = url.UserPassword(capability, "x")
		baseEnv = append(baseEnv, "NVT_EGRESS_FORWARD_PROXY_URL_"+strings.ToUpper(strings.ReplaceAll(capability, "-", "_"))+"="+parsed.String())
	}
	// Run the real startup exporter before invoking its az wrapper. Relocate
	// image installation paths only; keep launcher and egress dispatch intact.
	export := exec.Command(python, filepath.Join(root, "tests/azure-cli/export_fixture.py"), python)
	export.Env = baseEnv
	if output, err := export.CombinedOutput(); err != nil {
		t.Fatalf("Azure plugin startup export: %v\n%s", err, output)
	}
	run := func(provider string, args ...string) {
		command := exec.Command(filepath.Join(agentHome, ".local/bin/az"), args...)
		command.Env = append(append([]string{}, baseEnv...), "NVT_AZURE_PROVIDER="+provider)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("actual CLI %v: %v\n%s", args, err, output)
		}
		if strings.Contains(string(output), "fixture-trusted") {
			t.Fatal("broker token entered CLI output")
		}
		if args[0] == "account" && !strings.Contains(string(output), Placeholder) {
			t.Fatal("token output was not inert")
		}
	}
	run("azure-one", "group", "list")
	run("azure-two", "group", "list")
	run("azure-one", "monitor", "log-analytics", "query", "-w", "33333333-3333-3333-3333-333333333333", "--analytics-query", "print Result=42")
	run("azure-one", "account", "get-access-token")
	mu.Lock()
	count := len(upstreamCalls)
	records := strings.Join(upstreamCalls, "\n")
	mu.Unlock()
	if count != 3 || !strings.Contains(records, "fixture-trusted-azure-one") || !strings.Contains(records, "fixture-trusted-azure-two") {
		t.Fatalf("unexpected fixture request routing: %s", records)
	}
	// Equivalent raw clients cannot mutate, export credentials, or select another
	// subscription even with attacker-supplied bearer/auxiliary headers.
	parsed, _ := url.Parse(proxy.URL)
	parsed.User = url.UserPassword("azure-one", "x")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(parsed), TLSClientConfig: &tls.Config{RootCAs: caCertPool(t, ca)}}}
	for _, item := range []struct{ method, path string }{
		{"DELETE", "/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/fixture/providers/Microsoft.Compute/virtualMachines/vm?api-version=2025-11-01"},
		{"POST", "/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/fixture/providers/Microsoft.Storage/storageAccounts/s/listKeys?api-version=2025-08-01"},
		{"GET", "/subscriptions/99999999-1111-1111-1111-111111111111/resourcegroups?api-version=2024-11-01"},
	} {
		request, _ := http.NewRequest(item.method, "https://management.azure.com"+item.path, nil)
		request.Header.Set("Authorization", "Bearer attacker")
		request.Header.Set("X-Ms-Authorization-Auxiliary", "Bearer attacker")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode < 400 {
			t.Fatal("raw bypass authorized")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(upstreamCalls) != count {
		t.Fatal("denied request reached authenticated upstream")
	}
	if err := filepath.WalkDir(agentHome, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		content, err := os.ReadFile(path)
		if err == nil && (bytes.Contains(content, []byte("fixture-trusted")) || strings.Contains(entry.Name(), "token_cache")) {
			t.Errorf("credential cache or fixture token in agent file %s", entry.Name())
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
