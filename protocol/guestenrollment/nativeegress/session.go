package nativeegress

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

// EgressTarget is the separately trusted per-run cluster egress path. Binding
// selects it before any guest destination is considered. OpenFlow performs
// final destination, DNS, private-address, policy, grant, and quota checks.
type EgressTarget interface {
	Binding() guestenrollment.Binding
	OpenFlow(context.Context, Destination) (net.Conn, error)
}

// Session is an authenticated exact-binding routing boundary. It owns no
// provider endpoint and exposes no registry enumeration.
type Session struct {
	mu             sync.Mutex
	authentication Authentication
	target         EgressTarget
	lifetime       context.Context
	cancelLifetime context.CancelFunc
	pending        chan struct{}
	opening        int
	active         map[*flowConn]struct{}
	idleTimeout    time.Duration
	closed         bool
	done           chan struct{}
	shutdownDone   chan struct{}
	shutdownErr    error
	beforeShutdown []func()
}

func NewSession(authentication Authentication, target EgressTarget) (*Session, error) {
	return newSession(authentication, target, FlowIdleTimeout)
}

func newSession(authentication Authentication, target EgressTarget, idleTimeout time.Duration) (*Session, error) {
	if target == nil || validateAuthentication(authentication, time.Now()) != nil || target.Binding() != authentication.Binding {
		return nil, ErrProtocol
	}
	if idleTimeout <= 0 || idleTimeout > FlowIdleTimeout {
		return nil, ErrProtocol
	}
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	session := &Session{
		authentication: authentication,
		target:         target,
		lifetime:       lifetime,
		cancelLifetime: cancelLifetime,
		pending:        make(chan struct{}, MaxPendingFlowOpens),
		active:         make(map[*flowConn]struct{}, MaxActiveFlows),
		idleTimeout:    idleTimeout,
		done:           make(chan struct{}),
		shutdownDone:   make(chan struct{}),
	}
	go session.expire(authentication.LocalExpiresAt)
	return session, nil
}

func (session *Session) Binding() guestenrollment.Binding {
	if session == nil {
		return guestenrollment.Binding{}
	}
	return session.authentication.Binding
}

func (session *Session) Sequence() uint64 {
	if session == nil {
		return 0
	}
	return session.authentication.Sequence
}

func (session *Session) Done() <-chan struct{} {
	if session == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return session.done
}

// OpenFlow routes only through the target already selected by the exact
// authenticated binding. Destination remains untrusted intent passed to that
// target's final policy validation.
func (session *Session) OpenFlow(ctx context.Context, destination Destination) (net.Conn, error) {
	if session == nil || ctx == nil || ValidateDestination(destination) != nil {
		return nil, ErrProtocol
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	select {
	case session.pending <- struct{}{}:
		defer func() { <-session.pending }()
	default:
		return nil, ErrCapacity
	}

	session.mu.Lock()
	if session.closed || !time.Now().Before(session.authentication.LocalExpiresAt) {
		session.mu.Unlock()
		return nil, ErrUnavailable
	}
	if len(session.active)+session.opening >= MaxActiveFlows {
		session.mu.Unlock()
		return nil, ErrCapacity
	}
	session.opening++
	target := session.target
	session.mu.Unlock()

	deadline := operationDeadline(ctx, FlowOpenTimeout)
	openContext, cancel := context.WithDeadline(session.lifetime, deadline)
	stopCallerCancellation := context.AfterFunc(ctx, cancel)
	connection, err := target.OpenFlow(openContext, destination)
	deadlineExceeded := openContext.Err() != nil || !time.Now().Before(deadline)
	stopCallerCancellation()
	cancel()

	session.mu.Lock()
	session.opening--
	if err != nil || deadlineExceeded || connection == nil || session.closed || !time.Now().Before(session.authentication.LocalExpiresAt) {
		session.mu.Unlock()
		if connection != nil {
			_ = connection.Close()
		}
		if err != nil && !deadlineExceeded {
			if errors.Is(err, ErrDenied) {
				return nil, ErrDenied
			}
			return nil, ErrUnavailable
		}
		return nil, ErrUnavailable
	}
	flow := &flowConn{Conn: connection, session: session}
	session.active[flow] = struct{}{}
	session.mu.Unlock()
	flow.refreshDeadline()
	return flow, nil
}

func (session *Session) Ready() bool {
	if session == nil {
		return false
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	return !session.closed && time.Now().Before(session.authentication.LocalExpiresAt)
}

func (session *Session) Close() error {
	return session.closeWithin(ShutdownTimeout)
}

func (session *Session) closeWithin(timeout time.Duration) error {
	if session == nil {
		return nil
	}
	if timeout <= 0 || timeout > ShutdownTimeout {
		return ErrProtocol
	}
	session.mu.Lock()
	var flows []*flowConn
	var beforeShutdown []func()
	startShutdown := false
	if !session.closed {
		session.closed = true
		session.cancelLifetime()
		close(session.done)
		flows = make([]*flowConn, 0, len(session.active))
		for flow := range session.active {
			flows = append(flows, flow)
		}
		beforeShutdown = append(beforeShutdown, session.beforeShutdown...)
		session.beforeShutdown = nil
		startShutdown = true
	}
	done := session.shutdownDone
	session.mu.Unlock()
	if startShutdown {
		for _, callback := range beforeShutdown {
			callback()
		}
		go session.finishShutdown(flows, timeout)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		session.mu.Lock()
		err := session.shutdownErr
		session.mu.Unlock()
		return err
	case <-timer.C:
		return ErrUnavailable
	}
}

func (session *Session) addBeforeShutdown(callback func()) bool {
	if session == nil || callback == nil {
		return false
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return false
	}
	session.beforeShutdown = append(session.beforeShutdown, callback)
	return true
}

func (session *Session) finishShutdown(flows []*flowConn, timeout time.Duration) {
	results := make(chan struct{}, len(flows))
	for _, flow := range flows {
		go func() {
			_ = flow.Close()
			results <- struct{}{}
		}()
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	err := error(nil)
	for range flows {
		select {
		case <-results:
		case <-timer.C:
			err = ErrUnavailable
			goto complete
		}
	}

complete:
	session.mu.Lock()
	session.shutdownErr = err
	close(session.shutdownDone)
	session.mu.Unlock()
}

func (session *Session) expire(deadline time.Time) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-timer.C:
		_ = session.Close()
	case <-session.done:
	}
}

func (session *Session) remove(flow *flowConn) {
	session.mu.Lock()
	delete(session.active, flow)
	session.mu.Unlock()
}

type flowConn struct {
	net.Conn
	session *Session
	once    sync.Once
}

func (flow *flowConn) Read(buffer []byte) (int, error) {
	count, err := flow.Conn.Read(buffer)
	if count > 0 {
		flow.refreshDeadline()
	}
	if err != nil {
		_ = flow.Close()
	}
	return count, err
}

func (flow *flowConn) Write(buffer []byte) (int, error) {
	count, err := flow.Conn.Write(buffer)
	if count > 0 {
		flow.refreshDeadline()
	}
	if err != nil {
		_ = flow.Close()
	}
	return count, err
}

func (flow *flowConn) Close() error {
	var err error
	flow.once.Do(func() {
		_ = flow.Conn.SetDeadline(time.Now())
		err = flow.Conn.Close()
		flow.session.remove(flow)
	})
	return err
}

func (flow *flowConn) refreshDeadline() {
	_ = flow.Conn.SetDeadline(time.Now().Add(flow.session.idleTimeout))
}

func (*Session) String() string   { return "[native egress session]" }
func (*Session) GoString() string { return "[native egress session]" }
