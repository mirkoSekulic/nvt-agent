package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/localroutes"
)

type fakeLocalRunSource struct {
	runs []localroutes.Run
}

func TestLocalRunsConfigIsOptInAndStrict(t *testing.T) {
	base := Config{BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090}
	if err := base.Validate(); err != nil {
		t.Fatalf("omitted local routes changed compatibility: %v", err)
	}
	valid := base
	valid.LocalRuns = LocalRunsConfig{
		Enabled: true, ControllerURL: "http://local-controller:7480",
		BaseDomain: "agent.localhost", PathPrefix: "/agents", Timeout: time.Second, DisableKubernetes: true,
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*LocalRunsConfig){
		func(value *LocalRunsConfig) { value.ControllerURL = "http://user@local-controller:7480" },
		func(value *LocalRunsConfig) { value.ControllerURL = "ftp://local-controller:7480" },
		func(value *LocalRunsConfig) { value.BaseDomain = "Bad.Domain" },
		func(value *LocalRunsConfig) { value.PathPrefix = "/agents/../other" },
		func(value *LocalRunsConfig) { value.Timeout = 11 * time.Second },
	} {
		candidate := valid
		mutate(&candidate.LocalRuns)
		if err := candidate.Validate(); err == nil {
			t.Fatal("invalid local route config accepted")
		}
	}
	disabled := base
	disabled.LocalRuns.DisableKubernetes = true
	if err := disabled.Validate(); err == nil {
		t.Fatal("Kubernetes discovery disabled without local route source")
	}
}

func (source fakeLocalRunSource) Get(_ context.Context, runID string) (localroutes.Run, error) {
	for _, run := range source.runs {
		if run.RunID == runID {
			return run, nil
		}
	}
	return localroutes.Run{}, fmt.Errorf("not found")
}

func (source fakeLocalRunSource) List(context.Context) ([]localroutes.Run, error) {
	return append([]localroutes.Run(nil), source.runs...), nil
}

func TestLocalPathProxyPreservesWebSocketUpgradeAndPrefix(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Host != "run-1.agent.localhost" || request.URL.Path != "/websocket" || request.Header.Get("X-Forwarded-Prefix") != "/agents/run-1" {
			t.Errorf("upstream request host=%q path=%q prefix=%q", request.Host, request.URL.Path, request.Header.Get("X-Forwarded-Prefix"))
			http.Error(response, "wrong route", http.StatusBadRequest)
			return
		}
		connection, buffer, err := response.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer connection.Close()
		_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = buffer.Flush()
		payload := make([]byte, 4)
		if _, err := io.ReadFull(connection, payload); err == nil {
			_, _ = connection.Write(payload)
		}
	}))
	defer upstream.Close()

	run := testLocalRoute("run-1", "https://identity.example", "42", true)
	server := testLocalGateway(t, upstream.URL, fakeLocalRunSource{runs: []localroutes.Run{run}}, false)
	public := httptest.NewServer(server)
	defer public.Close()
	publicURL, _ := url.Parse(public.URL)
	connection, err := net.DialTimeout("tcp", publicURL.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(connection, "GET /agents/run-1/websocket HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("websocket status=%q err=%v", status, err)
	}
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("websocket echo=%q err=%v", echo, err)
	}
}

func TestLocalExposureHostRoutePreservesRootPath(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	requests := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests <- request.Host + " " + request.URL.RequestURI()
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	run := testLocalRoute("run-1", "https://identity.example", "42", true)
	server := testLocalGateway(t, upstream.URL, fakeLocalRunSource{runs: []localroutes.Run{run}}, false)
	request := httptest.NewRequest(http.MethodGet, "http://app.run-1.agent.localhost/deep/link?mode=root", nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if got := <-requests; got != "app.run-1.agent.localhost /deep/link?mode=root" {
		t.Fatalf("root exposure rewritten: %q", got)
	}
}

func TestLocalRouteConfigurationDriftFailsClosed(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	run := testLocalRoute("run-1", "https://identity.example", "42", true)
	run.Session.Host = "run-1.other.localhost"
	server := testLocalGateway(t, upstream.URL, fakeLocalRunSource{runs: []localroutes.Run{run}}, false)

	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://run-1.agent.localhost/", nil))
	if response.Code != http.StatusNotFound || upstreamCalls != 0 {
		t.Fatalf("drifted route = %d calls=%d body=%s", response.Code, upstreamCalls, response.Body.String())
	}
	dashboard := httptest.NewRecorder()
	server.ServeHTTP(dashboard, httptest.NewRequest(http.MethodGet, "http://localhost/agents/", nil))
	if dashboard.Code != http.StatusServiceUnavailable || upstreamCalls != 0 {
		t.Fatalf("drifted dashboard = %d calls=%d body=%s", dashboard.Code, upstreamCalls, dashboard.Body.String())
	}
}

func TestLocalDashboardAndRoutesEnforceExactOwnerAndReadiness(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	owned := testLocalRoute("owned-run", "https://identity.example", "42", true)
	other := testLocalRoute("other-run", "https://identity.example", "99", true)
	unready := testLocalRoute("unready-run", "https://identity.example", "42", false)
	source := fakeLocalRunSource{runs: []localroutes.Run{owned, other, unready}}
	server := testLocalGateway(t, upstream.URL, source, true)

	dashboard := httptest.NewRequest(http.MethodGet, "http://localhost/agents/?view=all", nil)
	setTestPrincipalSession(t, server, dashboard, Principal{Issuer: "https://identity.example", Subject: "42", DisplayName: "Alice"})
	dashboardResponse := httptest.NewRecorder()
	server.ServeHTTP(dashboardResponse, dashboard)
	if dashboardResponse.Code != http.StatusOK || !strings.Contains(dashboardResponse.Body.String(), "owned-run") || !strings.Contains(dashboardResponse.Body.String(), "unready-run") ||
		!strings.Contains(dashboardResponse.Body.String(), `/agents/?view=active`) || strings.Contains(dashboardResponse.Body.String(), "other-run") {
		t.Fatalf("owner dashboard=%d %s", dashboardResponse.Code, dashboardResponse.Body.String())
	}
	ownedRequest := httptest.NewRequest(http.MethodGet, "http://owned-run.agent.localhost/", nil)
	setTestPrincipalSession(t, server, ownedRequest, Principal{Issuer: "https://identity.example", Subject: "42"})
	ownedResponse := httptest.NewRecorder()
	server.ServeHTTP(ownedResponse, ownedRequest)
	if ownedResponse.Code != http.StatusNoContent || upstreamCalls != 1 {
		t.Fatalf("authorized owner route=%d calls=%d body=%s", ownedResponse.Code, upstreamCalls, ownedResponse.Body.String())
	}

	denied := httptest.NewRequest(http.MethodGet, "http://other-run.agent.localhost/", nil)
	setTestPrincipalSession(t, server, denied, Principal{Issuer: "https://identity.example", Subject: "42"})
	deniedResponse := httptest.NewRecorder()
	server.ServeHTTP(deniedResponse, denied)
	missing := httptest.NewRequest(http.MethodGet, "http://missing.agent.localhost/", nil)
	setTestPrincipalSession(t, server, missing, Principal{Issuer: "https://identity.example", Subject: "42"})
	missingResponse := httptest.NewRecorder()
	server.ServeHTTP(missingResponse, missing)
	if deniedResponse.Code != http.StatusNotFound || missingResponse.Code != http.StatusNotFound || deniedResponse.Body.String() != missingResponse.Body.String() || upstreamCalls != 1 {
		t.Fatalf("cross-owner disclosed existence: denied=%d %q missing=%d %q", deniedResponse.Code, deniedResponse.Body.String(), missingResponse.Code, missingResponse.Body.String())
	}
	unreadyRequest := httptest.NewRequest(http.MethodGet, "http://unready-run.agent.localhost/", nil)
	setTestPrincipalSession(t, server, unreadyRequest, Principal{Issuer: "https://identity.example", Subject: "42"})
	unreadyResponse := httptest.NewRecorder()
	server.ServeHTTP(unreadyResponse, unreadyRequest)
	if unreadyResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("unready route=%d %s", unreadyResponse.Code, unreadyResponse.Body.String())
	}
}

func TestHTTPLocalRouteSourcePaginatesStrictlyAndFailsClosed(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	controller := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		if request.URL.Query().Get("after") == "run-08" {
			_, _ = response.Write([]byte(`{"api_version":"nvt.local-routes/v1","runs":[` + mustRouteJSON(t, testLocalRoute("run-09", "https://identity.example", "42", true)) + `]}`))
			return
		}
		runs := make([]string, 0, localroutes.MaxRunsPerPage)
		for index := 1; index <= localroutes.MaxRunsPerPage; index++ {
			runs = append(runs, mustRouteJSON(t, testLocalRoute(fmt.Sprintf("run-%02d", index), "https://identity.example", "42", true)))
		}
		_, _ = response.Write([]byte(`{"api_version":"nvt.local-routes/v1","runs":[` + strings.Join(runs, ",") + `],"next_after":"run-08"}`))
	}))
	defer controller.Close()
	config := LocalRunsConfig{Enabled: true, ControllerURL: controller.URL, Timeout: time.Second}
	source, err := newHTTPLocalRunSource(config)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := source.List(context.Background())
	mu.Lock()
	requestCount := requests
	mu.Unlock()
	if err != nil || len(runs) != 9 || requestCount != 2 {
		t.Fatalf("paginated runs=%d requests=%d err=%v", len(runs), requestCount, err)
	}

	malformed := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"api_version":"nvt.local-routes/v1","runs":[],"unknown":true}`))
	}))
	defer malformed.Close()
	config.ControllerURL = malformed.URL
	source, _ = newHTTPLocalRunSource(config)
	if _, err := source.List(context.Background()); err == nil {
		t.Fatal("malformed controller response accepted")
	}
}

func testLocalGateway(t *testing.T, proxyURL string, source LocalRunSource, authenticated bool) *Server {
	t.Helper()
	proxy, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(proxy.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	if fake, ok := source.(fakeLocalRunSource); ok {
		for index := range fake.runs {
			fake.runs[index].Session.UpstreamHost, fake.runs[index].Session.UpstreamPort = host, port
			for exposure := range fake.runs[index].Exposures {
				fake.runs[index].Exposures[exposure].UpstreamHost, fake.runs[index].Exposures[exposure].UpstreamPort = host, port
			}
		}
		source = fake
	}
	config := Config{
		BaseDomain: "localhost", ListenAddr: ":8080", DefaultTargetPort: 4090,
		LocalRuns: LocalRunsConfig{Enabled: true, ControllerURL: "http://controller.test:7480", BaseDomain: "agent.localhost", PathPrefix: "/agents", Timeout: time.Second, DisableKubernetes: true},
	}
	if authenticated {
		config = authenticatedTestConfig()
		config.BaseDomain = "localhost"
		config.LocalRuns = LocalRunsConfig{Enabled: true, ControllerURL: "http://controller.test:7480", BaseDomain: "agent.localhost", PathPrefix: "/agents", Timeout: time.Second, DisableKubernetes: true}
		config.Auth.Authorization.Rules = []AuthorizationRule{{ID: "owner", Effect: authorizationEffectAllow, Owner: true}}
	}
	server, err := NewServerWithSources(config, nil, "", nil, source)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func testLocalRoute(runID, issuer, subject string, ready bool) localroutes.Run {
	state := "preparing"
	if ready {
		state = "running"
	}
	return localroutes.Run{
		APIVersion: localroutes.APIVersion, RunID: runID, State: state, Ready: ready,
		Principal: localroutes.Principal{Issuer: issuer, Subject: subject, DisplayName: "Alice"}, Profile: "engineering", Workflow: "development",
		CreatedAt: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC), Session: localroutes.Endpoint{Host: runID + ".agent.localhost", Path: "/agents/" + runID + "/", UpstreamHost: "upstream.internal", UpstreamPort: 4090},
		Exposures: []localroutes.Exposure{{Name: "app", Host: "app." + runID + ".agent.localhost", UpstreamHost: "upstream.internal", UpstreamPort: 3000}},
	}
}

func mustRouteJSON(t *testing.T, run localroutes.Run) string {
	t.Helper()
	data, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
