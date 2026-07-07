package egress

import (
	"fmt"
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

// TestQuotaNotConsumedByBrokerFailures pins finding 1: requests that fail
// before the upstream (broker outage, revoked grant, projection lag) do not
// burn quota. After the broker recovers, the full quota is still available.
func TestQuotaNotConsumedByBrokerFailures(t *testing.T) {
	broker := newFakeBroker(t)
	upstream := newFakeUpstream(t)
	server, proxy := newTestProxyWithHandle(t, broker, upstream)
	proxy.Route.MaxRequests = 2

	// Broker unavailable: several requests fail closed (502) and must not
	// consume the quota. Distinct paths avoid any caching interaction.
	broker.setFail(true)
	for i := 0; i < 5; i++ {
		response, err := http.Get(fmt.Sprintf("%s/down-%d", server.URL, i))
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadGateway {
			t.Fatalf("broker-down request %d got %d, want 502", i, response.StatusCode)
		}
	}

	// Broker recovers: the full quota of 2 is still available, then the 3rd
	// is rejected.
	broker.setFail(false)
	for i := 0; i < 2; i++ {
		response, err := http.Get(fmt.Sprintf("%s/up-%d", server.URL, i))
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("within-quota request %d got %d, want 200", i, response.StatusCode)
		}
	}
	response, err := http.Get(server.URL + "/up-over")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over-quota request got %d, want 429", response.StatusCode)
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
// status 429 and never reaches the upstream, while exactly the within-quota
// request does.
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
	// Quota is enforced after authorization but before the upstream, so
	// exactly the within-quota request reaches upstream.
	upstream.mu.Lock()
	reached := len(upstream.records)
	upstream.mu.Unlock()
	if reached != 1 {
		t.Fatalf("expected exactly 1 request to reach upstream, got %d", reached)
	}
}
