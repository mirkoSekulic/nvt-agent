package nativeegress

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

type fakeTarget struct {
	binding  guestenrollment.Binding
	deny     func(Destination) bool
	block    <-chan struct{}
	echo     bool
	onClose  func()
	err      error
	decorate func(net.Conn) net.Conn
	calls    atomic.Int32
	mu       sync.Mutex
	seen     []Destination
	peers    []net.Conn
}

func (target *fakeTarget) Binding() guestenrollment.Binding { return target.binding }

func (target *fakeTarget) OpenFlow(ctx context.Context, destination Destination) (net.Conn, error) {
	target.calls.Add(1)
	target.mu.Lock()
	target.seen = append(target.seen, destination)
	target.mu.Unlock()
	if target.err != nil {
		return nil, target.err
	}
	if target.deny != nil && target.deny(destination) {
		return nil, ErrDenied
	}
	if target.block != nil {
		select {
		case <-target.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	client, peer := net.Pipe()
	target.mu.Lock()
	target.peers = append(target.peers, peer)
	target.mu.Unlock()
	if target.echo {
		go func() {
			_, _ = io.Copy(peer, peer)
			_ = peer.Close()
		}()
	}
	connection := net.Conn(client)
	if target.onClose != nil {
		connection = &observedConn{Conn: connection, onClose: target.onClose}
	}
	if target.decorate != nil {
		connection = target.decorate(connection)
	}
	return connection, nil
}

func (target *fakeTarget) closePeers() {
	target.mu.Lock()
	peers := append([]net.Conn(nil), target.peers...)
	target.peers = nil
	target.mu.Unlock()
	for _, peer := range peers {
		_ = peer.Close()
	}
}

func TestExactTargetRoutingPreservesDestinationWithoutCrossRunSelection(t *testing.T) {
	bindingA := testBinding("run-a")
	bindingB := testBinding("run-b")
	targetA := &fakeTarget{binding: bindingA, echo: true, deny: func(destination Destination) bool {
		return destination.Host == "egress-run-b.cluster.local" || destination.Host == "10.0.0.7"
	}}
	targetB := &fakeTarget{binding: bindingB}
	defer targetA.closePeers()
	defer targetB.closePeers()
	session, err := NewSession(testAuthentication(bindingA, 1, time.Minute), targetA)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	destination := Destination{Network: NetworkTCP, Host: "api.example", Port: 443, CapabilityHint: "codex-main"}
	flow, err := session.OpenFlow(t.Context(), destination)
	if err != nil {
		t.Fatal(err)
	}
	const payload = "opaque-agent-payload-canary"
	if _, err := flow.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(flow, response); err != nil || string(response) != payload {
		t.Fatalf("flow response=%q error=%v", response, err)
	}
	_ = flow.Close()
	targetA.mu.Lock()
	seen := append([]Destination(nil), targetA.seen...)
	targetA.mu.Unlock()
	if len(seen) != 1 || seen[0] != destination || targetB.calls.Load() != 0 {
		t.Fatalf("target A destinations=%#v target B calls=%d", seen, targetB.calls.Load())
	}
	for _, forbidden := range []Destination{
		{Network: NetworkTCP, Host: "egress-run-b.cluster.local", Port: 443},
		{Network: NetworkTCP, Host: "10.0.0.7", Port: 443},
	} {
		if _, err := session.OpenFlow(t.Context(), forbidden); !errors.Is(err, ErrDenied) {
			t.Fatalf("private/cross-run intent error=%v", err)
		}
	}
	if targetB.calls.Load() != 0 {
		t.Fatalf("guest intent selected another target: %d", targetB.calls.Load())
	}
	if _, err := NewSession(testAuthentication(bindingA, 1, time.Minute), targetB); !errors.Is(err, ErrProtocol) {
		t.Fatalf("cross-binding target accepted: %v", err)
	}
}

func TestFlowCapacityCancellationReleaseAndShutdown(t *testing.T) {
	binding := testBinding("run-capacity")
	target := &fakeTarget{binding: binding}
	defer target.closePeers()
	session, err := NewSession(testAuthentication(binding, 1, time.Minute), target)
	if err != nil {
		t.Fatal(err)
	}
	destination := Destination{Network: NetworkTCP, Host: "api.example", Port: 443}
	flows := make([]net.Conn, 0, MaxActiveFlows)
	for range MaxActiveFlows {
		flow, err := session.OpenFlow(t.Context(), destination)
		if err != nil {
			t.Fatalf("open flow %d: %v", len(flows), err)
		}
		flows = append(flows, flow)
	}
	if _, err := session.OpenFlow(t.Context(), destination); !errors.Is(err, ErrCapacity) {
		t.Fatalf("active overflow error=%v", err)
	}
	_ = flows[0].Close()
	replacement, err := session.OpenFlow(t.Context(), destination)
	if err != nil {
		t.Fatalf("released capacity unavailable: %v", err)
	}
	_ = replacement.Close()

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := session.OpenFlow(cancelled, destination); err == nil {
		t.Fatal("cancelled flow open succeeded")
	}
	if err := session.Close(); err != nil || session.Ready() {
		t.Fatalf("shutdown error=%v ready=%t", err, session.Ready())
	}
	for _, flow := range flows[1:] {
		buffer := make([]byte, 1)
		if _, err := flow.Read(buffer); err == nil {
			t.Fatal("shutdown retained an active flow")
		}
	}
	if _, err := session.OpenFlow(t.Context(), destination); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("post-shutdown open error=%v", err)
	}
}

func TestPendingFlowOpenBoundAndDeadline(t *testing.T) {
	binding := testBinding("run-pending")
	release := make(chan struct{})
	target := &fakeTarget{binding: binding, block: release}
	session, err := NewSession(testAuthentication(binding, 1, time.Minute), target)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	destination := Destination{Network: NetworkTCP, Host: "api.example", Port: 443}
	results := make(chan error, MaxPendingFlowOpens)
	for range MaxPendingFlowOpens {
		go func() {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			connection, err := session.OpenFlow(ctx, destination)
			if connection != nil {
				_ = connection.Close()
			}
			results <- err
		}()
	}
	deadline := time.Now().Add(time.Second)
	for target.calls.Load() < MaxPendingFlowOpens && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if _, err := session.OpenFlow(t.Context(), destination); !errors.Is(err, ErrCapacity) {
		t.Fatalf("pending overflow error=%v calls=%d", err, target.calls.Load())
	}
	close(release)
	for range MaxPendingFlowOpens {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestUnavailableEgressTargetFailsClosedWithGenericError(t *testing.T) {
	binding := testBinding("run-unavailable")
	const canary = "internal-target-endpoint-canary"
	target := &fakeTarget{binding: binding, err: errors.New(canary)}
	session, err := NewSession(testAuthentication(binding, 1, time.Minute), target)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	_, err = session.OpenFlow(t.Context(), Destination{Network: NetworkTCP, Host: "api.example", Port: 443})
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), canary) {
		t.Fatalf("target failure error=%v", err)
	}
}

func TestFlowOpenDeadlineFailsClosedAndReleasesCapacity(t *testing.T) {
	binding := testBinding("run-deadline")
	blocked := make(chan struct{})
	target := &fakeTarget{binding: binding, block: blocked}
	session, err := NewSession(testAuthentication(binding, 1, time.Minute), target)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if _, err := session.OpenFlow(ctx, Destination{Network: NetworkTCP, Host: "api.example", Port: 443}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("deadline error=%v", err)
	}
	close(blocked)
	flow, err := session.OpenFlow(t.Context(), Destination{Network: NetworkTCP, Host: "api.example", Port: 443})
	if err != nil {
		t.Fatalf("deadline did not release capacity: %v", err)
	}
	_ = flow.Close()
	target.closePeers()
}

func TestSessionShutdownCancelsPendingTargetOpen(t *testing.T) {
	binding := testBinding("run-cancel-open")
	blocked := make(chan struct{})
	target := &fakeTarget{binding: binding, block: blocked}
	session, err := NewSession(testAuthentication(binding, 1, time.Minute), target)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := session.OpenFlow(t.Context(), Destination{Network: NetworkTCP, Host: "api.example", Port: 443})
		result <- err
	}()
	deadline := time.Now().Add(time.Second)
	for target.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("pending shutdown error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel pending target open")
	}
	close(blocked)
}

func TestSessionAndRegistryShutdownAreBoundedWhenConnectionCloseBlocks(t *testing.T) {
	for _, test := range []struct {
		name     string
		shutdown func(*SessionRegistry, *Session, time.Duration) error
	}{
		{name: "session", shutdown: func(_ *SessionRegistry, session *Session, timeout time.Duration) error {
			return session.closeWithin(timeout)
		}},
		{name: "registry", shutdown: func(registry *SessionRegistry, _ *Session, timeout time.Duration) error {
			return registry.closeWithin(timeout)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding := testBinding("run-blocking-close-" + test.name)
			release := make(chan struct{})
			target := &fakeTarget{binding: binding, decorate: func(connection net.Conn) net.Conn {
				return &blockingCloseConn{Conn: connection, release: release}
			}}
			registry := NewSessionRegistry()
			session, err := NewSession(testAuthentication(binding, 1, time.Minute), target)
			if err != nil {
				t.Fatal(err)
			}
			reservation, err := registry.Reserve(session)
			if err != nil || !reservation.Activate() {
				t.Fatal(err)
			}
			flow, err := session.OpenFlow(t.Context(), Destination{Network: NetworkTCP, Host: "api.example", Port: 443})
			if err != nil {
				t.Fatal(err)
			}
			const timeout = 40 * time.Millisecond
			started := time.Now()
			if err := test.shutdown(registry, session, timeout); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("blocking shutdown error=%v", err)
			}
			if elapsed := time.Since(started); elapsed > timeout*4 {
				t.Fatalf("shutdown exceeded bound: %s", elapsed)
			}
			if session.Ready() {
				t.Fatal("bounded shutdown retained readiness")
			}
			close(release)
			_ = flow.Close()
			target.closePeers()
			_ = registry.Close()
		})
	}
}

func TestFlowIdleDeadlineIsBidirectionalActivity(t *testing.T) {
	binding := testBinding("run-idle")
	target := &fakeTarget{binding: binding}
	defer target.closePeers()
	const idle = 50 * time.Millisecond
	session, err := newSession(testAuthentication(binding, 1, time.Minute), target, idle)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	flow, err := session.OpenFlow(t.Context(), Destination{Network: NetworkTCP, Host: "api.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	target.mu.Lock()
	peer := target.peers[len(target.peers)-1]
	target.mu.Unlock()

	readDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		_, err := flow.Read(buffer)
		readDone <- err
	}()
	for range 5 {
		go func() {
			buffer := make([]byte, 1)
			_, _ = peer.Read(buffer)
		}()
		if _, err := flow.Write([]byte{'x'}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(idle / 2)
		select {
		case err := <-readDone:
			t.Fatalf("one-way activity did not refresh read deadline: %v", err)
		default:
		}
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("idle read ended without error")
		}
	case <-time.After(idle * 3):
		t.Fatal("truly idle flow did not close")
	}
}

func testAuthentication(binding guestenrollment.Binding, sequence uint64, lifetime time.Duration) Authentication {
	now := time.Now()
	localLifetime := lifetime
	if localLifetime > RevalidationInterval {
		localLifetime = RevalidationInterval
	}
	return Authentication{
		Binding: binding, Sequence: sequence, IssuedAt: now.Add(-time.Second),
		ExpiresAt: now.Add(lifetime), LocalExpiresAt: now.Add(localLifetime),
	}
}

var _ io.ReadWriteCloser = (*flowConn)(nil)

type observedConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (connection *observedConn) Close() error {
	connection.once.Do(connection.onClose)
	return connection.Conn.Close()
}

type blockingCloseConn struct {
	net.Conn
	release <-chan struct{}
}

func (connection *blockingCloseConn) Close() error {
	<-connection.release
	return connection.Conn.Close()
}
