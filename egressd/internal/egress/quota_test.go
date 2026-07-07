package egress

import (
	"net/http"
	"sync"
	"testing"
)

// TestQuotaEnforcesExactlyN pins the TOCTOU-free quota: with MaxRequests=N and
// M>N concurrent requests, exactly N reach the upstream and the rest fail
// closed with 429, regardless of interleaving.
func TestQuotaEnforcesExactlyN(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	server, proxy := newTestProxyWithHandle(t, broker, upstream)

	const limit = 5
	const parallel = 40
	proxy.Route.MaxRequests = limit

	var wg sync.WaitGroup
	var mu sync.Mutex
	statusCounts := map[int]int{}
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, err := http.Get(server.URL + "/backend-api/responses")
			if err != nil {
				return
			}
			defer response.Body.Close()
			mu.Lock()
			statusCounts[response.StatusCode]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	if statusCounts[http.StatusOK] != limit {
		t.Fatalf("expected exactly %d OK responses, got %d (%v)", limit, statusCounts[http.StatusOK], statusCounts)
	}
	if statusCounts[http.StatusTooManyRequests] != parallel-limit {
		t.Fatalf("expected %d 429 responses, got %d (%v)", parallel-limit, statusCounts[http.StatusTooManyRequests], statusCounts)
	}
	// Exactly N requests reached the upstream — the security-relevant claim.
	upstream.mu.Lock()
	reached := len(upstream.records)
	upstream.mu.Unlock()
	if reached != limit {
		t.Fatalf("expected exactly %d requests to reach upstream, got %d", limit, reached)
	}
}

// TestQuotaUnlimitedWhenZero pins the backward-compatible default: 0 means no
// cap.
func TestQuotaUnlimitedWhenZero(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	server, proxy := newTestProxyWithHandle(t, broker, upstream)
	proxy.Route.MaxRequests = 0

	for i := 0; i < 20; i++ {
		response, err := http.Get(server.URL + "/x")
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("request %d got %d, want 200 (unlimited)", i, response.StatusCode)
		}
	}
}

// TestQuotaBreachIsReported pins that a quota-rejected request is audited with
// status 429 (still observability), never reaching the broker headers path.
func TestQuotaBreachIsReported(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	reports := newFakeReportServer(t)
	reporter := reporterFor(reports, 16)
	go reporter.Run(t.Context())

	server, proxy := newTestProxyWithHandle(t, broker, upstream)
	proxy.Reporter = reporter
	proxy.Route.MaxRequests = 1

	for i := 0; i < 2; i++ {
		response, err := http.Get(server.URL + "/backend-api/x")
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
	}
	waitFor(t, func() bool {
		for _, e := range reports.allEntries() {
			if e["status"] == float64(http.StatusTooManyRequests) {
				return true
			}
		}
		return false
	})
	// The second (rejected) request never fetched headers: exactly one broker
	// headers call for the one request that passed quota.
	if broker.callCount() != 1 {
		t.Fatalf("quota-rejected request must not hit the broker: %d calls", broker.callCount())
	}
}
