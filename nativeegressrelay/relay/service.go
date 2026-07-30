package relay

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment/nativeegress"
)

// Service coordinates the distinct guest data and trusted publication TLS
// listeners. It starts with an empty target registry and an unpublished
// publisher on every process start.
type Service struct {
	data      *Server
	control   *ControlServer
	publisher *TargetPublisher
	registry  *EgressdTargetRegistry

	shutdownOnce sync.Once
	shutdownDone chan struct{}
	shutdownMu   sync.Mutex
	shutdownErr  error
}

func NewService(config Configuration) (*Service, error) {
	if config.validate() != nil {
		return nil, errors.New("native egress relay service configuration is invalid")
	}
	registry, err := NewEgressdTargetRegistry([]EgressdTargetDescriptor{})
	if err != nil {
		return nil, errors.New("native egress relay service configuration is invalid")
	}
	data, err := NewServer(config, registry)
	if err != nil {
		return nil, err
	}
	publisher, err := NewTargetPublisher(registry)
	if err != nil {
		return nil, errors.New("native egress relay service configuration is invalid")
	}
	control, err := NewControlServer(config, publisher)
	if err != nil {
		return nil, err
	}
	return &Service{
		data: data, control: control, publisher: publisher, registry: registry,
		shutdownDone: make(chan struct{}),
	}, nil
}

func (service *Service) ListenAndServe() error {
	if service == nil || service.data == nil || service.control == nil {
		return errors.New("native egress relay unavailable")
	}
	dataListener, err := net.Listen("tcp", service.data.listenAddress)
	if err != nil {
		return errors.New("native egress relay unavailable")
	}
	controlListener, err := net.Listen("tcp", service.control.listenAddress)
	if err != nil {
		_ = dataListener.Close()
		return errors.New("native egress relay unavailable")
	}
	return service.Serve(dataListener, controlListener)
}

func (service *Service) Serve(dataListener, controlListener net.Listener) error {
	if service == nil || dataListener == nil || controlListener == nil || service.data == nil || service.control == nil {
		if dataListener != nil {
			_ = dataListener.Close()
		}
		if controlListener != nil {
			_ = controlListener.Close()
		}
		return errors.New("native egress relay unavailable")
	}
	results := make(chan error, 2)
	go func() { results <- service.data.Serve(dataListener) }()
	go func() { results <- service.control.Serve(controlListener) }()
	first := <-results
	shutdownContext, cancel := context.WithTimeout(context.Background(), nativeegress.ShutdownTimeout)
	_ = service.Shutdown(shutdownContext)
	cancel()
	second := <-results
	if first != nil || second != nil {
		return errors.New("native egress relay unavailable")
	}
	return nil
}

func (service *Service) Shutdown(ctx context.Context) error {
	if service == nil {
		return nil
	}
	if ctx == nil {
		return context.Canceled
	}
	service.shutdownOnce.Do(func() {
		go func() {
			defer close(service.shutdownDone)
			results := make(chan error, 2)
			go func() { results <- service.control.Shutdown(ctx) }()
			go func() { results <- service.data.Shutdown(ctx) }()
			first, second := <-results, <-results
			if first != nil || second != nil {
				service.shutdownMu.Lock()
				service.shutdownErr = errors.New("native egress relay shutdown failed")
				service.shutdownMu.Unlock()
			}
		}()
	})
	select {
	case <-service.shutdownDone:
		service.shutdownMu.Lock()
		err := service.shutdownErr
		service.shutdownMu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (service *Service) Sessions() SessionLookup {
	if service == nil {
		return nil
	}
	return service.data.Sessions()
}

func (service *Service) PublicationStatus() nativeegress.TargetStatus {
	if service == nil || service.publisher == nil {
		return nativeegress.TargetStatus{ContractVersion: nativeegress.TargetPublicationVersion, Type: nativeegress.TargetPublicationStatusResponse}
	}
	return service.publisher.Status()
}

func (*Service) String() string   { return "[native egress relay service]" }
func (*Service) GoString() string { return "[native egress relay service]" }
