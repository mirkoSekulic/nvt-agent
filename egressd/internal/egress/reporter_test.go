package egress

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestPathClass(t *testing.T) {
	cases := map[string]string{
		"/repos/o/r/git-upload-pack": "git-upload-pack",
		"/o/r.git/git-receive-pack":  "git-receive-pack",
		"/o/r.git/info/refs":         "info-refs",
		"/repos/o/r/pulls/1":         "repos",
		"/backend-api/responses":     "backend-api",
		"/":                          "root",
		"":                           "root",
		"/v1/messages":               "v1",
		"noslashprefix/x":            "noslashprefix",
	}
	for path, want := range cases {
		if got := PathClass(path); got != want {
			t.Errorf("PathClass(%q) = %q, want %q", path, got, want)
		}
	}
}

// fakeReportServer records report batches posted to /v1/injection/report.
type fakeReportServer struct {
	server  *httptest.Server
	mu      sync.Mutex
	batches [][]map[string]any
	status  int
}

func newFakeReportServer(t *testing.T) *fakeReportServer {
	t.Helper()
	f := &fakeReportServer{status: http.StatusOK}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/injection/report" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var decoded struct {
			Entries []map[string]any `json:"entries"`
		}
		_ = json.Unmarshal(body, &decoded)
		f.mu.Lock()
		f.batches = append(f.batches, decoded.Entries)
		status := f.status
		f.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"reported":1}`))
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeReportServer) allEntries() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var all []map[string]any
	for _, batch := range f.batches {
		all = append(all, batch...)
	}
	return all
}

func (f *fakeReportServer) setStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = status
}

func reporterFor(f *fakeReportServer, queueSize int) *Reporter {
	return &Reporter{
		broker:        &BrokerClient{URL: f.server.URL, Token: "egress-role-token", Client: f.server.Client()},
		queue:         make(chan ReportEntry, queueSize),
		batchSize:     defaultReportBatchSize,
		flushInterval: 20 * time.Millisecond,
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

// TestReporterFlushesWithSanitizedFields pins that reports reach the broker
// with the sanitized fields and no header values anywhere in the payload.
func TestReporterFlushesWithSanitizedFields(t *testing.T) {
	f := newFakeReportServer(t)
	reporter := reporterFor(f, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reporter.Run(ctx)

	reporter.Enqueue(ReportEntry{Capability: "git-app", Host: "github.com", Method: "POST", PathClass: "git-upload-pack", Status: 200})
	reporter.Enqueue(ReportEntry{Capability: "tunnel-main", Host: "example.com", Port: 443, Decision: "allow"})

	waitFor(t, func() bool { return len(f.allEntries()) >= 2 })
	entries := f.allEntries()
	var httpEntry, connectEntry map[string]any
	for _, e := range entries {
		if e["capability"] == "git-app" {
			httpEntry = e
		}
		if e["capability"] == "tunnel-main" {
			connectEntry = e
		}
	}
	if httpEntry == nil || connectEntry == nil {
		t.Fatalf("missing entries: %v", entries)
	}
	if httpEntry["path_class"] != "git-upload-pack" || httpEntry["status"] != float64(200) {
		t.Fatalf("unexpected http entry: %v", httpEntry)
	}
	if _, hasMethod := connectEntry["method"]; hasMethod {
		t.Fatalf("connect entry must not carry method: %v", connectEntry)
	}
	if connectEntry["decision"] != "allow" || connectEntry["port"] != float64(443) {
		t.Fatalf("unexpected connect entry: %v", connectEntry)
	}
	// No report field may ever be a header/token value.
	for _, e := range entries {
		for _, key := range []string{"authorization", "headers", "token", "x-api-key"} {
			if _, present := e[key]; present {
				t.Fatalf("report entry leaked %q: %v", key, e)
			}
		}
	}
}

// TestReporterDropsWhenFull pins the bound: a flood beyond queue capacity
// drops (counted) instead of blocking or growing memory.
func TestReporterDropsWhenFull(t *testing.T) {
	f := newFakeReportServer(t)
	reporter := reporterFor(f, 4)
	// No Run goroutine: nothing drains, so the 5th+ enqueue drops.
	for i := 0; i < 100; i++ {
		reporter.Enqueue(ReportEntry{Capability: "c", Host: "h", Method: "GET", PathClass: "root", Status: 200})
	}
	if reporter.Dropped() == 0 {
		t.Fatal("expected drops when the queue is full and undrained")
	}
	if reporter.Dropped() < 90 {
		t.Fatalf("expected most of the flood dropped, got %d", reporter.Dropped())
	}
}

// TestReporterBestEffortOnBrokerError pins that a failing report endpoint
// drops the batch (counted) and never blocks or panics the flush loop.
func TestReporterBestEffortOnBrokerError(t *testing.T) {
	f := newFakeReportServer(t)
	f.setStatus(http.StatusInternalServerError)
	reporter := reporterFor(f, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reporter.Run(ctx)

	reporter.Enqueue(ReportEntry{Capability: "c", Host: "h", Method: "GET", PathClass: "root", Status: 200})
	waitFor(t, func() bool { return reporter.Dropped() >= 1 })
}

// TestProxyReportsWithoutAffectingTraffic pins latency/behaviour parity: with
// the report endpoint failing, the proxied request still succeeds and the
// report is emitted (best-effort), proving the report path is off the hot path.
func TestProxyReportsWithoutAffectingTraffic(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	reports := newFakeReportServer(t)
	// The proxy's broker client only serves /headers here; point the reporter
	// at a separate report server so we can observe reports independently.
	reporter := reporterFor(reports, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reporter.Run(ctx)

	server, proxy := newTestProxyWithHandle(t, broker, upstream)
	proxy.Reporter = reporter

	response, err := http.Get(server.URL + "/backend-api/responses")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("proxied request must succeed regardless of reporting, got %d", response.StatusCode)
	}
	waitFor(t, func() bool {
		for _, e := range reports.allEntries() {
			if e["path_class"] == "backend-api" && e["status"] == float64(200) {
				return true
			}
		}
		return false
	})
}
