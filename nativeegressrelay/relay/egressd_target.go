package relay

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

const maxEgressdConnectResponseBytes = 16 << 10

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

// EgressdTargetDescriptor is non-secret, trusted control-plane input. The
// complete binding selects exactly one per-run egressd CONNECT listener before
// any guest destination is considered.
type EgressdTargetDescriptor struct {
	Binding    guestenrollment.Binding `json:"binding"`
	ConnectURL string                  `json:"connect_url"`
}

type parsedEgressdTargetDescriptor struct {
	descriptor EgressdTargetDescriptor
	address    string
}

// EgressdTargetRegistry is a bounded, exact-only, level-triggered target
// source. Reconcile replaces the complete trusted snapshot atomically; it
// exposes no lookup by partial scope and no enumeration API.
type EgressdTargetRegistry struct {
	mu               sync.RWMutex
	targets          map[guestenrollment.Binding]*egressdTarget
	dial             dialContextFunc
	withdrawSessions func([]guestenrollment.Binding) (<-chan struct{}, error)
}

type egressdTarget struct {
	registry   *EgressdTargetRegistry
	binding    guestenrollment.Binding
	connectURL string
	address    string
	active     bool
	done       chan struct{}
}

func NewEgressdTargetRegistry(descriptors []EgressdTargetDescriptor) (*EgressdTargetRegistry, error) {
	dialer := &net.Dialer{}
	return newEgressdTargetRegistry(descriptors, dialer.DialContext)
}

func newEgressdTargetRegistry(descriptors []EgressdTargetDescriptor, dial dialContextFunc) (*EgressdTargetRegistry, error) {
	if dial == nil {
		return nil, errors.New("native egress target configuration is invalid")
	}
	registry := &EgressdTargetRegistry{
		targets: make(map[guestenrollment.Binding]*egressdTarget, len(descriptors)),
		dial:    dial,
	}
	if err := registry.Reconcile(descriptors); err != nil {
		return nil, err
	}
	return registry, nil
}

// Reconcile atomically replaces the complete bounded target snapshot. An
// unchanged descriptor retains its target identity and does not churn live
// sessions. Removed or replaced targets are withdrawn before future opens;
// their Done channel lets the relay withdraw exact session readiness before
// closing existing flows.
func (registry *EgressdTargetRegistry) Reconcile(descriptors []EgressdTargetDescriptor) error {
	return registry.ReconcileContext(context.Background(), descriptors)
}

// ReconcileContext validates the complete snapshot before taking the registry
// lock. Once commit begins, affected exact sessions synchronously lose flow
// authority and readiness before replacement targets become visible. Teardown
// completes concurrently under the one existing shutdown budget.
func (registry *EgressdTargetRegistry) ReconcileContext(ctx context.Context, descriptors []EgressdTargetDescriptor) error {
	if registry == nil || registry.dial == nil {
		return errors.New("native egress target configuration is invalid")
	}
	if ctx == nil || ctx.Err() != nil {
		return errors.New("native egress target configuration is invalid")
	}
	parsed, err := validateEgressdTargetDescriptors(descriptors)
	if err != nil {
		return err
	}
	registry.mu.Lock()
	if ctx.Err() != nil {
		registry.mu.Unlock()
		return errors.New("native egress target configuration is invalid")
	}
	next := make(map[guestenrollment.Binding]*egressdTarget, len(parsed))
	changed := make([]guestenrollment.Binding, 0, len(registry.targets))
	for binding, descriptor := range parsed {
		current := registry.targets[binding]
		if current != nil && current.active && current.connectURL == descriptor.descriptor.ConnectURL {
			next[binding] = current
			continue
		}
		if current != nil && current.active {
			changed = append(changed, binding)
		}
		next[binding] = &egressdTarget{
			registry: registry, binding: binding, connectURL: descriptor.descriptor.ConnectURL,
			address: descriptor.address, active: true, done: make(chan struct{}),
		}
	}
	for binding, current := range registry.targets {
		if next[binding] == current || !current.active {
			continue
		}
		if _, remains := parsed[binding]; !remains {
			changed = append(changed, binding)
		}
	}
	withdrawn := closedSignal()
	if len(changed) != 0 && registry.withdrawSessions != nil {
		withdrawn, err = registry.withdrawSessions(changed)
		if err != nil || withdrawn == nil {
			registry.mu.Unlock()
			return errors.New("native egress target configuration is invalid")
		}
	}
	for binding, current := range registry.targets {
		if next[binding] == current || !current.active {
			continue
		}
		current.active = false
		close(current.done)
	}
	registry.targets = next
	registry.mu.Unlock()
	timer := time.NewTimer(nativeegress.ShutdownTimeout)
	defer timer.Stop()
	select {
	case <-withdrawn:
	case <-timer.C:
	case <-ctx.Done():
		// The complete map and readiness withdrawal already committed. Return
		// success so the publisher records the applied generation/digest; a
		// lost HTTP response is recovered through status or idempotent retry.
	}
	return nil
}

func (registry *EgressdTargetRegistry) bindSessionWithdrawal(withdraw func([]guestenrollment.Binding) (<-chan struct{}, error)) error {
	if registry == nil || withdraw == nil {
		return errors.New("native egress target configuration is invalid")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.withdrawSessions != nil {
		return errors.New("native egress target configuration is invalid")
	}
	registry.withdrawSessions = withdraw
	return nil
}

func (registry *EgressdTargetRegistry) ResolveNativeEgressTarget(_ context.Context, binding guestenrollment.Binding) (nativeegress.EgressTarget, error) {
	if registry == nil || guestenrollment.ValidateBinding(binding) != nil {
		return nil, ErrTargetUnavailable
	}
	registry.mu.RLock()
	target := registry.targets[binding]
	if target == nil || !target.active {
		registry.mu.RUnlock()
		return nil, ErrTargetUnavailable
	}
	registry.mu.RUnlock()
	return target, nil
}

func validateEgressdTargetDescriptors(descriptors []EgressdTargetDescriptor) (map[guestenrollment.Binding]parsedEgressdTargetDescriptor, error) {
	if len(descriptors) > nativeegress.MaxSessionBindings {
		return nil, errors.New("native egress target configuration is invalid")
	}
	parsed := make(map[guestenrollment.Binding]parsedEgressdTargetDescriptor, len(descriptors))
	addresses := make(map[string]struct{}, len(descriptors))
	for _, descriptor := range descriptors {
		if guestenrollment.ValidateBinding(descriptor.Binding) != nil {
			return nil, errors.New("native egress target configuration is invalid")
		}
		address, err := parseEgressdConnectURL(descriptor.ConnectURL)
		if err != nil {
			return nil, errors.New("native egress target configuration is invalid")
		}
		if _, exists := parsed[descriptor.Binding]; exists {
			return nil, errors.New("native egress target configuration is invalid")
		}
		if _, exists := addresses[address]; exists {
			return nil, errors.New("native egress target configuration is invalid")
		}
		addresses[address] = struct{}{}
		parsed[descriptor.Binding] = parsedEgressdTargetDescriptor{descriptor: descriptor, address: address}
	}
	return parsed, nil
}

func parseEgressdConnectURL(value string) (string, error) {
	if nativeegress.ValidateEgressdConnectURL(value) != nil {
		return "", errors.New("native egress target configuration is invalid")
	}
	return value[len("http://"):], nil
}

func (target *egressdTarget) Binding() guestenrollment.Binding {
	if target == nil {
		return guestenrollment.Binding{}
	}
	return target.binding
}

func (target *egressdTarget) OpenFlow(ctx context.Context, destination nativeegress.Destination) (net.Conn, error) {
	if target == nil || ctx == nil || nativeegress.ValidateDestination(destination) != nil {
		return nil, ErrTargetUnavailable
	}
	deadline := time.Now().Add(nativeegress.FlowOpenTimeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	operationContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	target.registry.mu.RLock()
	defer target.registry.mu.RUnlock()
	if !target.active || target.registry.targets[target.binding] != target {
		return nil, ErrTargetUnavailable
	}
	return target.connect(operationContext, destination)
}

func (target *egressdTarget) connect(ctx context.Context, destination nativeegress.Destination) (net.Conn, error) {
	connection, err := target.registry.dial(ctx, "tcp", target.address)
	if err != nil || connection == nil {
		if connection != nil {
			_ = connection.Close()
		}
		return nil, ErrTargetUnavailable
	}
	closeOnCancellation := context.AfterFunc(ctx, func() {
		_ = connection.SetDeadline(time.Now())
		_ = connection.Close()
	})
	closeConnection := true
	defer func() {
		if closeConnection {
			_ = connection.Close()
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, ErrTargetUnavailable
		}
	}

	authority := net.JoinHostPort(destination.Host, strconv.Itoa(int(destination.Port)))
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: authority},
		Host:   authority,
		Header: make(http.Header),
	}
	if destination.CapabilityHint != "" {
		request.Header.Set("X-NVT-Capability", destination.CapabilityHint)
	}
	if err := request.Write(connection); err != nil {
		return nil, ErrTargetUnavailable
	}

	bounded := &boundedConnectResponseConn{Conn: connection, remaining: maxEgressdConnectResponseBytes, bounded: true}
	reader := bufio.NewReaderSize(bounded, maxEgressdConnectResponseBytes)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, ErrTargetUnavailable
	}
	if response.ProtoMajor != 1 || response.ProtoMinor != 1 {
		return nil, ErrTargetUnavailable
	}
	if response.StatusCode == http.StatusForbidden {
		return nil, nativeegress.ErrDenied
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, ErrTargetUnavailable
	}
	if response.ContentLength > 0 || len(response.TransferEncoding) != 0 {
		return nil, ErrTargetUnavailable
	}
	bounded.unbound()
	if !closeOnCancellation() || ctx.Err() != nil {
		return nil, ErrTargetUnavailable
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return nil, ErrTargetUnavailable
	}
	closeConnection = false
	return &bufferedEgressdConn{Conn: connection, reader: reader}, nil
}

func (target *egressdTarget) acquireAdmission() (func(), bool) {
	if target == nil || target.registry == nil {
		return nil, false
	}
	target.registry.mu.RLock()
	if !target.active || target.registry.targets[target.binding] != target {
		target.registry.mu.RUnlock()
		return nil, false
	}
	return target.registry.mu.RUnlock, true
}

func (target *egressdTarget) Done() <-chan struct{} {
	if target == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return target.done
}

type boundedConnectResponseConn struct {
	net.Conn
	mu        sync.Mutex
	remaining int
	bounded   bool
}

func (connection *boundedConnectResponseConn) Read(buffer []byte) (int, error) {
	connection.mu.Lock()
	if !connection.bounded {
		connection.mu.Unlock()
		return connection.Conn.Read(buffer)
	}
	if connection.remaining <= 0 {
		connection.mu.Unlock()
		return 0, errors.New("native egress target response is invalid")
	}
	if len(buffer) > connection.remaining {
		buffer = buffer[:connection.remaining]
	}
	connection.mu.Unlock()
	count, err := connection.Conn.Read(buffer)
	connection.mu.Lock()
	connection.remaining -= count
	connection.mu.Unlock()
	return count, err
}

func (connection *boundedConnectResponseConn) unbound() {
	connection.mu.Lock()
	connection.bounded = false
	connection.mu.Unlock()
}

type bufferedEgressdConn struct {
	net.Conn
	reader *bufio.Reader
}

func (connection *bufferedEgressdConn) Read(buffer []byte) (int, error) {
	if connection.reader != nil && connection.reader.Buffered() > 0 {
		return connection.reader.Read(buffer)
	}
	return connection.Conn.Read(buffer)
}

func (connection *bufferedEgressdConn) CloseWrite() error {
	if writer, ok := connection.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return connection.Conn.Close()
}

func (EgressdTargetDescriptor) String() string   { return "[native egress egressd target descriptor]" }
func (EgressdTargetDescriptor) GoString() string { return "[native egress egressd target descriptor]" }
func (*EgressdTargetRegistry) String() string    { return "[native egress egressd target registry]" }
func (*EgressdTargetRegistry) GoString() string  { return "[native egress egressd target registry]" }
func (*egressdTarget) String() string            { return "[native egress egressd target]" }
func (*egressdTarget) GoString() string          { return "[native egress egressd target]" }

func closedSignal() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}

var _ TargetResolver = (*EgressdTargetRegistry)(nil)
var _ nativeegress.EgressTarget = (*egressdTarget)(nil)
var _ io.ReadWriteCloser = (*bufferedEgressdConn)(nil)
