package gateway

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/workspacetunnel"
)

type dialingWorkspaceOpener struct {
	binding  guestenrollment.Binding
	sequence uint64
	address  string
	err      error
	opens    atomic.Int32
}

func (opener *dialingWorkspaceOpener) OpenStream(ctx context.Context) (net.Conn, error) {
	opener.opens.Add(1)
	if opener.err != nil {
		return nil, opener.err
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", opener.address)
}

func (opener *dialingWorkspaceOpener) Binding() guestenrollment.Binding { return opener.binding }
func (opener *dialingWorkspaceOpener) Sequence() uint64                 { return opener.sequence }
func (*dialingWorkspaceOpener) Close() error                            { return nil }

type recordingWorkspaceResolver struct {
	mu      sync.Mutex
	calls   []string
	openers map[string]workspacetunnel.StreamOpener
	err     error
}

func (resolver *recordingWorkspaceResolver) Resolve(run *nvtv1alpha1.AgentRun) (workspacetunnel.StreamOpener, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.calls = append(resolver.calls, run.Name)
	if resolver.err != nil {
		return nil, resolver.err
	}
	opener, ok := resolver.openers[run.Name]
	if !ok {
		return nil, ErrNativeWorkspaceRouteUnavailable
	}
	return opener, nil
}

func (resolver *recordingWorkspaceResolver) called() []string {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return append([]string(nil), resolver.calls...)
}

func TestAuthorizedNativeWorkspaceHTTPUsesExactFixedStream(t *testing.T) {
	type upstreamRequest struct {
		host, path, query, body, cookie, forwarded string
	}
	seen := make(chan upstreamRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		seen <- upstreamRequest{
			host: request.Host, path: request.URL.Path, query: request.URL.RawQuery, body: string(body),
			cookie: request.Header.Get("Cookie"), forwarded: request.Header.Get("Forwarded"),
		}
		response.Header().Add("Set-Cookie", defaultSessionCookie+"=must-not-escape; Path=/")
		response.Header().Add("Set-Cookie", "workspace-theme=dark; Domain=guest.invalid; Path=/")
		response.Header().Set("X-Workspace", "ready")
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte("workspace-response:" + string(body)))
	}))
	defer upstream.Close()

	run, binding := nativeBrowserRun(t, "vm-http", "vm-key", "owner")
	run.Annotations[AccessPortAnnotation] = "1"
	opener := &dialingWorkspaceOpener{binding: binding, sequence: 7, address: mustURLHost(t, upstream.URL)}
	server := mustNewServerWithWorkspaceResolver(t, pathTestConfig(authModeNone), fakeClient(t, run), exactNativeResolver(opener))

	request := httptest.NewRequest(http.MethodPost, "https://agents.altinn.studio/vm-key/api/workspaces?target=http%3A%2F%2Fevil.invalid", strings.NewReader("request-body"))
	request.Host = "agents.altinn.studio"
	request.Header.Set("Forwarded", "host=evil.invalid;proto=http")
	request.Header.Set("X-Forwarded-Host", "evil.invalid")
	request.Header.Set("Cookie", defaultSessionCookie+"=gateway-canary; workspace-preference=kept")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || response.Body.String() != "workspace-response:request-body" || response.Header().Get("X-Workspace") != "ready" {
		t.Fatalf("native HTTP response status=%d headers=%#v body=%q", response.Code, response.Header(), response.Body.String())
	}
	got := <-seen
	if got.host != nativeWorkspaceSyntheticAuthority || got.path != "/api/workspaces" || got.query != "target=http%3A%2F%2Fevil.invalid" || got.body != "request-body" ||
		got.cookie != "workspace-preference=kept" || got.forwarded != "" {
		t.Fatalf("native fixed upstream request=%#v", got)
	}
	if opener.opens.Load() != 1 {
		t.Fatalf("workspace stream opens=%d", opener.opens.Load())
	}
	setCookies := response.Header().Values("Set-Cookie")
	if len(setCookies) != 1 || !strings.Contains(setCookies[0], "workspace-theme=dark") || !strings.Contains(setCookies[0], "Path=/vm-key/") || strings.Contains(strings.ToLower(setCookies[0]), "domain=") || strings.Contains(strings.Join(setCookies, "\n"), "must-not-escape") {
		t.Fatalf("native response cookie filtering=%q", setCookies)
	}
}

func TestAuthorizedNativeWorkspaceUpgradeIsBidirectional(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		connection, buffer, err := response.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack workspace fixture: %v", err)
			return
		}
		defer connection.Close()
		_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = buffer.Flush()
		line, err := buffer.ReadString('\n')
		if err == nil {
			_, _ = buffer.WriteString("echo:" + line)
			_ = buffer.Flush()
		}
	}))
	defer upstream.Close()
	run, binding := nativeBrowserRun(t, "vm-upgrade", "upgrade-key", "owner")
	opener := &dialingWorkspaceOpener{binding: binding, sequence: 1, address: mustURLHost(t, upstream.URL)}
	server := mustNewServerWithWorkspaceResolver(t, Config{BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090}, fakeClient(t, run), exactNativeResolver(opener))
	gatewayServer := httptest.NewServer(server)
	defer gatewayServer.Close()

	connection, err := net.DialTimeout("tcp", mustURLHost(t, gatewayServer.URL), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = fmt.Fprintf(connection, "GET /socket?browser_target=evil.invalid HTTP/1.1\r\nHost: upgrade-key.agents.localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGVzdA==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("native upgrade status=%d", response.StatusCode)
	}
	_, _ = connection.Write([]byte("hello-workspace\n"))
	line, err := reader.ReadString('\n')
	if err != nil || line != "echo:hello-workspace\n" {
		t.Fatalf("native bidirectional response=%q error=%v", line, err)
	}
}

func TestNativeWorkspaceAuthorizationPrecedesResolverLookup(t *testing.T) {
	run, _ := nativeBrowserRun(t, "owned-vm", "owned-key", "42")
	config := authenticatedTestConfig()
	config.Auth.Authorization.Rules = []AuthorizationRule{{ID: "owner", Effect: authorizationEffectAllow, Owner: true}}
	resolver := &recordingWorkspaceResolver{err: ErrNativeWorkspaceRouteUnavailable}
	server := mustNewServerWithWorkspaceResolver(t, config, fakeClient(t, run), resolver)

	denied := httptest.NewRequest(http.MethodGet, "http://owned-key.agents.localhost/", nil)
	setTestPrincipalSession(t, server, denied, Principal{Issuer: "https://identity.example", Subject: "99"})
	deniedResponse := httptest.NewRecorder()
	server.ServeHTTP(deniedResponse, denied)
	if deniedResponse.Code != http.StatusNotFound || len(resolver.called()) != 0 {
		t.Fatalf("denied route status=%d resolver=%#v", deniedResponse.Code, resolver.called())
	}

	for _, rawURL := range []string{"http://nested.owned-key.agents.localhost/", "http://missing-key.agents.localhost/"} {
		request := httptest.NewRequest(http.MethodGet, rawURL, nil)
		setTestPrincipalSession(t, server, request, Principal{Issuer: "https://identity.example", Subject: "42"})
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound || len(resolver.called()) != 0 {
			t.Fatalf("unrelated route %q status=%d resolver=%#v", rawURL, response.Code, resolver.called())
		}
	}

	allowed := httptest.NewRequest(http.MethodGet, "http://owned-key.agents.localhost/", nil)
	setTestPrincipalSession(t, server, allowed, Principal{Issuer: "https://identity.example", Subject: "42"})
	allowedResponse := httptest.NewRecorder()
	server.ServeHTTP(allowedResponse, allowed)
	if allowedResponse.Code != http.StatusServiceUnavailable || !equalStrings(resolver.called(), []string{"owned-vm"}) {
		t.Fatalf("authorized route status=%d resolver=%#v", allowedResponse.Code, resolver.called())
	}
}

func TestNativeWorkspaceRoutingFailuresAreGenericAndNeverFallBackToPod(t *testing.T) {
	baseRun, binding := nativeBrowserRun(t, "vm-fail-closed", "vm-fail-key", "owner")
	readyPod := dashboardPod(baseRun.Name, readyPodStatus("127.0.0.1"))
	canary := "guest-binding-credential-canary"
	tests := []struct {
		name      string
		mutate    func(*nvtv1alpha1.AgentRun)
		control   *resolverControl
		workspace *resolverWorkspace
		resolver  NativeWorkspaceResolver
		want      int
	}{
		{name: "listeners disabled", resolver: nil, want: http.StatusServiceUnavailable},
		{name: "missing binding", mutate: func(run *nvtv1alpha1.AgentRun) { run.Status.NativeGuestBinding = nil }, control: &resolverControl{ready: true}, workspace: &resolverWorkspace{ready: true, opener: &resolverOpener{binding: binding, sequence: 1}}, want: http.StatusServiceUnavailable},
		{name: "mismatched binding", mutate: func(run *nvtv1alpha1.AgentRun) { run.Status.NativeGuestBinding.GuestInstanceID = canary }, control: &resolverControl{}, workspace: &resolverWorkspace{ready: true, opener: &resolverOpener{binding: binding, sequence: 1}}, want: http.StatusServiceUnavailable},
		{name: "stale generation", mutate: func(run *nvtv1alpha1.AgentRun) { run.Status.NativeGuestBinding.DesiredGeneration++ }, control: &resolverControl{ready: true}, workspace: &resolverWorkspace{ready: true, opener: &resolverOpener{binding: binding, sequence: 1}}, want: http.StatusServiceUnavailable},
		{name: "deleting", mutate: func(run *nvtv1alpha1.AgentRun) {
			now := metav1.Now()
			run.DeletionTimestamp = &now
			run.Finalizers = []string{"nvt.dev/test-finalizer"}
		}, control: &resolverControl{ready: true}, workspace: &resolverWorkspace{ready: true, opener: &resolverOpener{binding: binding, sequence: 1}}, want: http.StatusServiceUnavailable},
		{name: "terminal", mutate: func(run *nvtv1alpha1.AgentRun) { run.Status.Phase = nvtv1alpha1.AgentRunPhaseFailed }, control: &resolverControl{ready: true}, workspace: &resolverWorkspace{ready: true, opener: &resolverOpener{binding: binding, sequence: 1}}, want: http.StatusServiceUnavailable},
		{name: "control unavailable", control: &resolverControl{}, workspace: &resolverWorkspace{ready: true, opener: &resolverOpener{binding: binding, sequence: 1}}, want: http.StatusServiceUnavailable},
		{name: "workspace unavailable", control: &resolverControl{ready: true}, workspace: &resolverWorkspace{}, want: http.StatusServiceUnavailable},
		{name: "stream open failure", resolver: &recordingWorkspaceResolver{openers: map[string]workspacetunnel.StreamOpener{baseRun.Name: &dialingWorkspaceOpener{binding: binding, sequence: 1, err: errors.New(canary)}}}, want: http.StatusBadGateway},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			run := baseRun.DeepCopyObject().(*nvtv1alpha1.AgentRun)
			if testCase.mutate != nil {
				testCase.mutate(run)
			}
			resolver := testCase.resolver
			if resolver == nil && (testCase.control != nil || testCase.workspace != nil) {
				resolver = NewNativeWorkspaceResolver(testCase.control, testCase.workspace)
			}
			server := mustNewServerWithWorkspaceResolver(t, Config{BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090}, fakeClient(t, run, readyPod), resolver)
			response := httptest.NewRecorder()
			server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://vm-fail-key.agents.localhost/?host=evil.invalid", nil))
			if response.Code != testCase.want || strings.Contains(response.Body.String(), canary) || strings.Contains(response.Body.String(), binding.GuestInstanceID) || strings.Contains(response.Body.String(), binding.ExecutionID) {
				t.Fatalf("failure status=%d body=%q, want=%d", response.Code, response.Body.String(), testCase.want)
			}
		})
	}
}

func TestDashboardResolvesOnlyAuthorizedNativeVMRuns(t *testing.T) {
	ownedVM, _ := nativeBrowserRun(t, "owned-vm", "owned-key", "42")
	ownedVM.Annotations[DisplayNameAnnotation] = "Owned VM"
	hiddenVM, _ := nativeBrowserRun(t, "hidden-vm", "hidden-key", "99")
	hiddenVM.Annotations[DisplayNameAnnotation] = "Hidden VM canary"
	unavailableVM, _ := nativeBrowserRun(t, "unavailable-vm", "unavailable-key", "42")
	unavailableVM.Annotations[DisplayNameAnnotation] = "Unavailable VM"
	podRun := ownedAgentRun("pod-run", "pod-key", "https://identity.example", "42", "owner")
	podRun.Status.Phase = nvtv1alpha1.AgentRunPhaseRunning
	podRun.Annotations[DisplayNameAnnotation] = "Pod run"

	resolver := &recordingWorkspaceResolver{openers: map[string]workspacetunnel.StreamOpener{
		ownedVM.Name: &resolverOpener{binding: guestenrollment.Binding{}, sequence: 1},
	}}
	config := authenticatedTestConfig()
	config.Auth.Authorization.Rules = []AuthorizationRule{{ID: "owner", Effect: authorizationEffectAllow, Owner: true}}
	server := mustNewServerWithWorkspaceResolver(t, config, fakeClient(t, ownedVM, hiddenVM, unavailableVM, &podRun, dashboardPod(podRun.Name, readyPodStatus("10.0.0.8"))), resolver)

	for _, query := range []string{"", "?view=all"} {
		request := httptest.NewRequest(http.MethodGet, "http://agents.localhost/"+query, nil)
		setTestPrincipalSession(t, server, request, Principal{Issuer: "https://identity.example", Subject: "42"})
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		body := response.Body.String()
		if response.Code != http.StatusOK || !strings.Contains(body, "Owned VM") || !strings.Contains(body, "Pod run") || strings.Contains(body, "Hidden VM canary") {
			t.Fatalf("dashboard query=%q status=%d body=%s", query, response.Code, body)
		}
		if query == "" && strings.Contains(body, "Unavailable VM") {
			t.Fatalf("active dashboard included unavailable VM: %s", body)
		}
		if query != "" && !strings.Contains(body, "Unavailable VM") {
			t.Fatalf("all dashboard omitted authorized unavailable VM: %s", body)
		}
	}
	for _, called := range resolver.called() {
		if called == hiddenVM.Name {
			t.Fatalf("dashboard resolved unauthorized VM: %#v", resolver.called())
		}
	}
}

func nativeBrowserRun(t *testing.T, name, key, ownerSubject string) (*nvtv1alpha1.AgentRun, guestenrollment.Binding) {
	t.Helper()
	uid := types.UID(name + "-11111111-2222-3333-444444444444")
	executionID, err := executiondriver.AgentRunExecutionID(string(uid))
	if err != nil {
		t.Fatal(err)
	}
	binding := guestenrollment.Binding{
		AgentRunUID: string(uid), ExecutionID: executionID, DriverRegistration: "vm-driver",
		DesiredGeneration: 3, GuestInstanceID: name + "-guest",
	}
	run := &nvtv1alpha1.AgentRun{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nvt", Name: name, UID: uid, Generation: 3, Annotations: map[string]string{AccessKeyAnnotation: key}},
		Spec: nvtv1alpha1.AgentRunSpec{
			Execution: &nvtv1alpha1.AgentRunExecution{Kind: nvtv1alpha1.AgentRunExecutionVM, Driver: binding.DriverRegistration},
			ProfileProvenance: &nvtv1alpha1.AgentRunProfileProvenance{Principal: &nvtv1alpha1.AgentRunPrincipal{
				Issuer: "https://identity.example", Subject: ownerSubject, DisplayName: "owner",
			}},
		},
		Status: nvtv1alpha1.AgentRunStatus{
			Phase: nvtv1alpha1.AgentRunPhaseRunning,
			NativeGuestBinding: &nvtv1alpha1.AgentRunNativeGuestBinding{
				AgentRunUID: binding.AgentRunUID, ExecutionID: binding.ExecutionID, DriverRegistration: binding.DriverRegistration,
				DesiredGeneration: binding.DesiredGeneration, GuestInstanceID: binding.GuestInstanceID,
			},
		},
	}
	return run, binding
}

func exactNativeResolver(opener workspacetunnel.StreamOpener) NativeWorkspaceResolver {
	return NewNativeWorkspaceResolver(&resolverControl{ready: true}, &resolverWorkspace{ready: true, opener: opener})
}

func mustNewServerWithWorkspaceResolver(t *testing.T, config Config, client ctrlclient.Client, resolver NativeWorkspaceResolver) *Server {
	t.Helper()
	server, err := NewServerWithNativeWorkspaceResolver(config, client, "nvt", resolver)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func mustURLHost(t *testing.T, rawURL string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Host
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
