package relay

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

var (
	errTargetPublicationConflict    = errors.New("native egress target publication conflict")
	errTargetPublicationInvalid     = errors.New("native egress target publication invalid")
	errTargetPublicationUnavailable = errors.New("native egress target publication unavailable")
)

// TargetPublisher owns only in-memory publication metadata and the complete
// exact target snapshot. A fresh process is always unpublished and deny-all.
type TargetPublisher struct {
	mu         sync.Mutex
	registry   *EgressdTargetRegistry
	published  bool
	generation uint64
	digest     string
	targets    int
}

func NewTargetPublisher(registry *EgressdTargetRegistry) (*TargetPublisher, error) {
	if registry == nil {
		return nil, errTargetPublicationInvalid
	}
	return &TargetPublisher{registry: registry}, nil
}

func (publisher *TargetPublisher) Apply(ctx context.Context, snapshot nativeegress.TargetSnapshot) (nativeegress.TargetSnapshotAcknowledgement, error) {
	if publisher == nil || ctx == nil || nativeegress.ValidateTargetSnapshot(snapshot) != nil {
		return nativeegress.TargetSnapshotAcknowledgement{}, errTargetPublicationInvalid
	}
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if ctx.Err() != nil {
		return nativeegress.TargetSnapshotAcknowledgement{}, errTargetPublicationUnavailable
	}
	if publisher.published {
		if snapshot.Generation < publisher.generation || (snapshot.Generation == publisher.generation && snapshot.Digest != publisher.digest) {
			return nativeegress.TargetSnapshotAcknowledgement{}, errTargetPublicationConflict
		}
		if snapshot.Generation == publisher.generation {
			return publisher.acknowledgement(), nil
		}
	}
	descriptors := make([]EgressdTargetDescriptor, len(snapshot.Targets))
	for index, target := range snapshot.Targets {
		descriptors[index] = EgressdTargetDescriptor{Binding: target.Binding, ConnectURL: target.ConnectURL}
	}
	if err := publisher.registry.ReconcileContext(ctx, descriptors); err != nil {
		if ctx.Err() != nil {
			return nativeegress.TargetSnapshotAcknowledgement{}, errTargetPublicationUnavailable
		}
		return nativeegress.TargetSnapshotAcknowledgement{}, errTargetPublicationInvalid
	}
	publisher.published = true
	publisher.generation = snapshot.Generation
	publisher.digest = snapshot.Digest
	publisher.targets = len(snapshot.Targets)
	return publisher.acknowledgement(), nil
}

func (publisher *TargetPublisher) Status() nativeegress.TargetStatus {
	if publisher == nil {
		return nativeegress.TargetStatus{ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetPublicationStatusResponse}
	}
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	return nativeegress.TargetStatus{
		ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetPublicationStatusResponse,
		Published: publisher.published, Generation: publisher.generation, Digest: publisher.digest, TargetCount: publisher.targets,
	}
}

func (publisher *TargetPublisher) acknowledgement() nativeegress.TargetSnapshotAcknowledgement {
	return nativeegress.TargetSnapshotAcknowledgement{
		ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetSnapshotAck,
		Generation: publisher.generation, Digest: publisher.digest, TargetCount: publisher.targets,
	}
}

// ControlServer is the separate authenticated TLS publication/status surface.
// It has no data-plane, target lookup, or topology enumeration endpoint.
type ControlServer struct {
	listenAddress string
	tlsConfig     *tls.Config
	credential    []byte
	timeout       time.Duration
	publisher     *TargetPublisher
	requestSlots  chan struct{}

	serveStarted    atomic.Bool
	shutdownStarted atomic.Bool
	httpMu          sync.Mutex
	httpServer      *http.Server
	listener        net.Listener
	done            chan struct{}
	doneOnce        sync.Once
	zeroOnce        sync.Once
}

func NewControlServer(config Configuration, publisher *TargetPublisher) (*ControlServer, error) {
	if config.validate() != nil || publisher == nil {
		return nil, errors.New("native egress relay control configuration is invalid")
	}
	tlsConfig, err := loadControlTLS(config)
	if err != nil {
		return nil, errors.New("native egress relay control configuration is invalid")
	}
	credential, err := readProcessOwnedFile(config.ControlCredentialFile, 256, true)
	if err != nil || nativeegress.ValidateRelayControlCredential(string(credential)) != nil {
		zero(credential)
		return nil, errors.New("native egress relay control configuration is invalid")
	}
	return &ControlServer{
		listenAddress: config.ControlListenAddress, tlsConfig: tlsConfig, credential: credential,
		timeout: time.Duration(config.ControlTimeoutSeconds) * time.Second, publisher: publisher,
		requestSlots: make(chan struct{}, nativeegress.MaxTargetPublicationConcurrency), done: make(chan struct{}),
	}, nil
}

func (server *ControlServer) ListenAndServe() error {
	if server == nil {
		return errTargetPublicationUnavailable
	}
	listener, err := net.Listen("tcp", server.listenAddress)
	if err != nil {
		return errTargetPublicationUnavailable
	}
	return server.Serve(listener)
}

func (server *ControlServer) Serve(listener net.Listener) error {
	if server == nil || listener == nil || server.tlsConfig == nil || server.publisher == nil || server.timeout <= 0 ||
		server.timeout > nativeegress.TargetPublicationTimeout || cap(server.requestSlots) != nativeegress.MaxTargetPublicationConcurrency ||
		!server.serveStarted.CompareAndSwap(false, true) {
		if listener != nil {
			_ = listener.Close()
		}
		return errTargetPublicationUnavailable
	}
	httpServer := &http.Server{
		Handler: server, ReadHeaderTimeout: server.timeout, ReadTimeout: server.timeout, WriteTimeout: server.timeout,
		IdleTimeout: server.timeout, MaxHeaderBytes: nativeegress.MaxTargetPublicationHeadersBytes,
		ErrorLog: log.New(io.Discard, "", 0), TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	server.httpMu.Lock()
	if server.shutdownStarted.Load() {
		server.httpMu.Unlock()
		_ = listener.Close()
		server.finish()
		return nil
	}
	server.listener = listener
	server.httpServer = httpServer
	server.httpMu.Unlock()
	bounded := &boundedControlListener{Listener: listener, slots: make(chan struct{}, nativeegress.MaxTargetPublicationConcurrency)}
	err := httpServer.Serve(tls.NewListener(bounded, server.tlsConfig.Clone()))
	if errors.Is(err, http.ErrServerClosed) || server.shutdownStarted.Load() {
		err = nil
	} else if err != nil {
		err = errTargetPublicationUnavailable
	}
	server.finish()
	return err
}

func (server *ControlServer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if server == nil || request == nil || request.Method != http.MethodPost || request.URL.RawQuery != "" || request.URL.Fragment != "" ||
		(request.URL.Path != nativeegress.TargetSnapshotPath && request.URL.Path != nativeegress.TargetStatusPath) {
		writeControlFailure(response, http.StatusNotFound, nativeegress.TargetPublicationReasonNotFound)
		return
	}
	select {
	case server.requestSlots <- struct{}{}:
		defer func() { <-server.requestSlots }()
	default:
		writeControlFailure(response, http.StatusTooManyRequests, nativeegress.TargetPublicationReasonCapacity)
		return
	}
	if !server.authorized(request.Header.Values("Authorization")) {
		writeControlFailure(response, http.StatusUnauthorized, nativeegress.TargetPublicationReasonDenied)
		return
	}
	if request.Header.Get("Content-Type") != "application/json" || request.ContentLength > nativeegress.MaxTargetPublicationRequestBytes {
		writeControlFailure(response, http.StatusBadRequest, nativeegress.TargetPublicationReasonInvalid)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), server.timeout)
	defer cancel()
	body, err := readControlBody(response, request, nativeegress.MaxTargetPublicationRequestBytes)
	if err != nil || ctx.Err() != nil {
		zero(body)
		writeControlFailure(response, http.StatusBadRequest, nativeegress.TargetPublicationReasonInvalid)
		return
	}
	defer zero(body)
	if request.URL.Path == nativeegress.TargetStatusPath {
		if _, err := nativeegress.DecodeTargetStatusRequest(body); err != nil {
			writeControlFailure(response, http.StatusBadRequest, nativeegress.TargetPublicationReasonInvalid)
			return
		}
		encoded, err := nativeegress.EncodeTargetStatus(server.publisher.Status())
		if err != nil {
			writeControlFailure(response, http.StatusServiceUnavailable, nativeegress.TargetPublicationReasonFailed)
			return
		}
		writeControlJSON(response, http.StatusOK, encoded)
		return
	}
	snapshot, err := nativeegress.DecodeTargetSnapshot(body)
	if err != nil {
		writeControlFailure(response, http.StatusBadRequest, nativeegress.TargetPublicationReasonInvalid)
		return
	}
	acknowledgement, err := server.publisher.Apply(ctx, snapshot)
	if err != nil {
		switch {
		case errors.Is(err, errTargetPublicationConflict):
			writeControlFailure(response, http.StatusConflict, nativeegress.TargetPublicationReasonConflict)
		case errors.Is(err, errTargetPublicationInvalid):
			writeControlFailure(response, http.StatusBadRequest, nativeegress.TargetPublicationReasonInvalid)
		default:
			writeControlFailure(response, http.StatusServiceUnavailable, nativeegress.TargetPublicationReasonFailed)
		}
		return
	}
	encoded, err := nativeegress.EncodeTargetSnapshotAcknowledgement(acknowledgement)
	if err != nil {
		writeControlFailure(response, http.StatusServiceUnavailable, nativeegress.TargetPublicationReasonFailed)
		return
	}
	writeControlJSON(response, http.StatusOK, encoded)
}

func (server *ControlServer) authorized(values []string) bool {
	if server == nil || len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return false
	}
	provided := []byte(strings.TrimPrefix(values[0], "Bearer "))
	defer zero(provided)
	return len(provided) == len(server.credential) && subtle.ConstantTimeCompare(provided, server.credential) == 1
}

func (server *ControlServer) Shutdown(ctx context.Context) error {
	if server == nil {
		return nil
	}
	if ctx == nil {
		return context.Canceled
	}
	server.shutdownStarted.Store(true)
	server.httpMu.Lock()
	httpServer := server.httpServer
	listener := server.listener
	server.httpMu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	if httpServer != nil {
		if err := httpServer.Shutdown(ctx); err != nil {
			_ = httpServer.Close()
			return errTargetPublicationUnavailable
		}
	}
	if !server.serveStarted.Load() {
		server.finish()
	}
	select {
	case <-server.done:
		server.zeroOnce.Do(func() {
			zero(server.credential)
			server.credential = nil
		})
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (server *ControlServer) finish() {
	server.doneOnce.Do(func() { close(server.done) })
}

func readControlBody(response http.ResponseWriter, request *http.Request, maximum int64) ([]byte, error) {
	reader := http.MaxBytesReader(response, request.Body, maximum)
	defer reader.Close()
	return io.ReadAll(reader)
}

func writeControlFailure(response http.ResponseWriter, status int, reason string) {
	encoded, _ := nativeegress.EncodeTargetPublicationFailure(nativeegress.TargetPublicationFailure{
		ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetPublicationError, Reason: reason,
	})
	writeControlJSON(response, status, encoded)
}

func writeControlJSON(response http.ResponseWriter, status int, encoded []byte) {
	if len(encoded) > nativeegress.MaxTargetPublicationResponseBytes {
		response.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

type boundedControlListener struct {
	net.Listener
	slots chan struct{}
}

func (listener *boundedControlListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case listener.slots <- struct{}{}:
			return &boundedControlConnection{Conn: connection, release: func() { <-listener.slots }}, nil
		default:
			_ = connection.Close()
		}
	}
}

type boundedControlConnection struct {
	net.Conn
	release func()
	once    sync.Once
}

func (connection *boundedControlConnection) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(connection.release)
	return err
}

func (*TargetPublisher) String() string   { return "[native egress target publisher]" }
func (*TargetPublisher) GoString() string { return "[native egress target publisher]" }
func (*ControlServer) String() string     { return "[native egress relay control server]" }
func (*ControlServer) GoString() string   { return "[native egress relay control server]" }
