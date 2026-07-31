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
	revision         uint64
	dial             dialContextFunc
	withdrawSessions func([]guestenrollment.Binding) (<-chan struct{}, error)
}

type egressdTargetState uint8

const (
	egressdTargetActive egressdTargetState = iota + 1
	egressdTargetDraining
	egressdTargetClosed
)

type egressdTarget struct {
	registry   *EgressdTargetRegistry
	binding    guestenrollment.Binding
	connectURL string
	address    string

	lifecycleMu      sync.Mutex
	state            egressdTargetState
	epoch            uint64
	admissions       int
	drained          chan struct{}
	drainedClosed    bool
	admissionContext context.Context
	cancelAdmission  context.CancelFunc
	done             chan struct{}
}

type egressdTargetAdmission struct {
	target  *egressdTarget
	epoch   uint64
	context context.Context
	once    sync.Once
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

func newEgressdTarget(registry *EgressdTargetRegistry, binding guestenrollment.Binding, descriptor parsedEgressdTargetDescriptor) *egressdTarget {
	admissionContext, cancelAdmission := context.WithCancel(context.Background())
	return &egressdTarget{
		registry: registry, binding: binding, connectURL: descriptor.descriptor.ConnectURL, address: descriptor.address,
		state: egressdTargetActive, epoch: 1, admissionContext: admissionContext, cancelAdmission: cancelAdmission,
		done: make(chan struct{}),
	}
}

// Reconcile atomically replaces the complete bounded target snapshot. An
// unchanged descriptor retains its target identity and does not churn live
// sessions. Removed or replaced targets are withdrawn before future opens;
// their Done channel lets the relay withdraw exact session readiness before
// closing existing flows.
func (registry *EgressdTargetRegistry) Reconcile(descriptors []EgressdTargetDescriptor) error {
	return registry.ReconcileContext(context.Background(), descriptors)
}

// ReconcileContext validates the complete snapshot before taking any lock.
// Changed targets first enter a per-target draining epoch, which rejects and
// cancels admission without coupling unrelated targets through the global map
// lock. The commit linearization point is synchronous exact-session authority
// withdrawal followed by replacement map visibility. A failed pre-commit
// drain restores the prior complete snapshot.
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
	baseRevision := registry.revision
	changed := make([]guestenrollment.Binding, 0, len(registry.targets))
	draining := make([]*egressdTarget, 0, len(registry.targets))
	for binding, descriptor := range parsed {
		current := registry.targets[binding]
		if current != nil && current.isActive() && current.connectURL == descriptor.descriptor.ConnectURL {
			next[binding] = current
			continue
		}
		if current != nil {
			if _, ok := current.beginDrain(); !ok {
				rollbackTargetDrains(draining)
				registry.mu.Unlock()
				return errors.New("native egress target configuration is invalid")
			}
			draining = append(draining, current)
			changed = append(changed, binding)
		}
		next[binding] = newEgressdTarget(registry, binding, descriptor)
	}
	for binding, current := range registry.targets {
		if next[binding] == current {
			continue
		}
		if _, remains := parsed[binding]; !remains {
			if _, ok := current.beginDrain(); !ok {
				rollbackTargetDrains(draining)
				registry.mu.Unlock()
				return errors.New("native egress target configuration is invalid")
			}
			draining = append(draining, current)
			changed = append(changed, binding)
		}
	}
	registry.mu.Unlock()

	drainDeadline := time.Now().Add(nativeegress.ShutdownTimeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(drainDeadline) {
		drainDeadline = callerDeadline
	}
	if !waitTargetDrains(ctx, draining, drainDeadline) {
		rollbackTargetDrains(draining)
		return errors.New("native egress target configuration is invalid")
	}
	registry.mu.Lock()
	if registry.revision != baseRevision {
		rollbackTargetDrains(draining)
		registry.mu.Unlock()
		return errors.New("native egress target configuration is invalid")
	}
	withdrawn := closedSignal()
	if len(changed) != 0 && registry.withdrawSessions != nil {
		withdrawn, err = registry.withdrawSessions(changed)
		if err != nil || withdrawn == nil {
			rollbackTargetDrains(draining)
			registry.mu.Unlock()
			return errors.New("native egress target configuration is invalid")
		}
	}
	// Exact session flow authority is now synchronously absent. Committing each
	// drained epoch and publishing the complete replacement map is the
	// withdrawal linearization point.
	for _, target := range draining {
		target.commitDrain()
	}
	registry.targets = next
	registry.revision++
	registry.mu.Unlock()

	remaining := time.Until(drainDeadline)
	if remaining <= 0 {
		return nil
	}
	timer := time.NewTimer(remaining)
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

func waitTargetDrains(ctx context.Context, targets []*egressdTarget, deadline time.Time) bool {
	if len(targets) == 0 {
		return ctx.Err() == nil
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	for _, target := range targets {
		drained := target.drainedSignal()
		select {
		case <-drained:
		case <-ctx.Done():
			return false
		case <-timer.C:
			return false
		}
	}
	return true
}

func rollbackTargetDrains(targets []*egressdTarget) {
	for _, target := range targets {
		target.rollbackDrain()
	}
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
	if target == nil {
		registry.mu.RUnlock()
		return nil, ErrTargetUnavailable
	}
	registry.mu.RUnlock()
	if !target.isActive() {
		return nil, ErrTargetUnavailable
	}
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
	admission, ok := target.acquireAdmission()
	if !ok {
		return nil, ErrTargetUnavailable
	}
	defer admission.Release()
	deadline := time.Now().Add(nativeegress.FlowOpenTimeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	operationContext, cancel := context.WithDeadline(admission.Context(), deadline)
	stopCallerCancellation := context.AfterFunc(ctx, cancel)
	defer stopCallerCancellation()
	defer cancel()

	connection, err := target.connect(operationContext, destination)
	if err != nil || connection == nil || operationContext.Err() != nil || !admission.Active() {
		if connection != nil {
			_ = connection.Close()
		}
		if errors.Is(err, nativeegress.ErrDenied) && operationContext.Err() == nil && admission.Active() {
			return nil, nativeegress.ErrDenied
		}
		return nil, ErrTargetUnavailable
	}
	return connection, nil
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

func (target *egressdTarget) acquireAdmission() (targetAdmissionLease, bool) {
	if target == nil {
		return nil, false
	}
	target.lifecycleMu.Lock()
	if target.state != egressdTargetActive || target.admissionContext == nil || target.admissionContext.Err() != nil {
		target.lifecycleMu.Unlock()
		return nil, false
	}
	target.admissions++
	admission := &egressdTargetAdmission{target: target, epoch: target.epoch, context: target.admissionContext}
	target.lifecycleMu.Unlock()
	return admission, true
}

func (target *egressdTarget) isActive() bool {
	if target == nil {
		return false
	}
	target.lifecycleMu.Lock()
	defer target.lifecycleMu.Unlock()
	return target.state == egressdTargetActive
}

func (target *egressdTarget) beginDrain() (<-chan struct{}, bool) {
	if target == nil {
		return nil, false
	}
	target.lifecycleMu.Lock()
	defer target.lifecycleMu.Unlock()
	if target.state != egressdTargetActive {
		return nil, false
	}
	target.state = egressdTargetDraining
	target.epoch++
	target.drained = make(chan struct{})
	target.drainedClosed = false
	target.cancelAdmission()
	if target.admissions == 0 {
		close(target.drained)
		target.drainedClosed = true
	}
	return target.drained, true
}

func (target *egressdTarget) drainedSignal() <-chan struct{} {
	target.lifecycleMu.Lock()
	defer target.lifecycleMu.Unlock()
	if target.drained == nil {
		return closedSignal()
	}
	return target.drained
}

func (target *egressdTarget) rollbackDrain() {
	if target == nil {
		return
	}
	target.lifecycleMu.Lock()
	defer target.lifecycleMu.Unlock()
	if target.state != egressdTargetDraining {
		return
	}
	target.epoch++
	target.admissionContext, target.cancelAdmission = context.WithCancel(context.Background())
	target.state = egressdTargetActive
	target.drained = nil
	target.drainedClosed = false
}

func (target *egressdTarget) commitDrain() {
	if target == nil {
		return
	}
	target.lifecycleMu.Lock()
	defer target.lifecycleMu.Unlock()
	if target.state != egressdTargetDraining {
		return
	}
	target.state = egressdTargetClosed
	close(target.done)
}

func (admission *egressdTargetAdmission) Context() context.Context {
	if admission == nil || admission.context == nil {
		return context.Background()
	}
	return admission.context
}

func (admission *egressdTargetAdmission) Active() bool {
	if admission == nil || admission.target == nil {
		return false
	}
	target := admission.target
	target.lifecycleMu.Lock()
	defer target.lifecycleMu.Unlock()
	return target.state == egressdTargetActive && target.epoch == admission.epoch && admission.context.Err() == nil
}

func (admission *egressdTargetAdmission) Release() {
	if admission == nil || admission.target == nil {
		return
	}
	admission.once.Do(func() {
		target := admission.target
		target.lifecycleMu.Lock()
		if target.admissions > 0 {
			target.admissions--
		}
		if target.state == egressdTargetDraining && target.admissions == 0 && target.drained != nil && !target.drainedClosed {
			close(target.drained)
			target.drainedClosed = true
		}
		target.lifecycleMu.Unlock()
	})
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
