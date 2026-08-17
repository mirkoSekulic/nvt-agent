package capture

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/mirkoSekulic/nvt-agent/captured/internal/captureinspect"
)

const (
	DefaultExplicitListen    = "127.0.0.1:15002"
	DefaultTransparentListen = "127.0.0.1:15001"
	defaultInspectLimit      = 16 << 10
	defaultInspectTimeout    = 2 * time.Second
	defaultDialTimeout       = 10 * time.Second
)

type OriginalDestination func(*net.TCPConn) (string, error)

type Server struct {
	ExplicitListen    string
	TransparentListen string
	EgressProxy       string
	InspectLimit      int
	InspectTimeout    time.Duration
	Dialer            *net.Dialer
	Logger            *log.Logger
	OriginalDst       OriginalDestination
}

func (s *Server) Validate() error {
	if s.ExplicitListen == "" || s.TransparentListen == "" || s.EgressProxy == "" {
		return errors.New("explicit listen, transparent listen, and egress proxy are required")
	}
	if s.ExplicitListen == s.TransparentListen {
		return errors.New("explicit and transparent listeners must differ")
	}
	if s.EgressProxy == s.ExplicitListen || s.EgressProxy == s.TransparentListen {
		return errors.New("egress proxy must not recurse into a captured listener")
	}
	for _, value := range []string{s.ExplicitListen, s.TransparentListen, s.EgressProxy} {
		if _, _, err := net.SplitHostPort(value); err != nil {
			return fmt.Errorf("invalid address %q: %w", value, err)
		}
	}
	return nil
}

func (s *Server) Run(ctx context.Context) error {
	if err := s.Validate(); err != nil {
		return err
	}
	explicit, err := net.Listen("tcp", s.ExplicitListen)
	if err != nil {
		return fmt.Errorf("listen explicit: %w", err)
	}
	defer explicit.Close()
	transparent, err := net.Listen("tcp", s.TransparentListen)
	if err != nil {
		return fmt.Errorf("listen transparent: %w", err)
	}
	defer transparent.Close()
	go func() {
		<-ctx.Done()
		_ = explicit.Close()
		_ = transparent.Close()
	}()
	serveErrs := make(chan error, 2)
	go func() { serveErrs <- s.serve(explicit, false) }()
	go func() { serveErrs <- s.serve(transparent, true) }()
	err = <-serveErrs
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) serve(listener net.Listener, transparent bool) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn, transparent)
	}
}

func (s *Server) handle(conn net.Conn, transparent bool) {
	defer conn.Close()
	if !transparent {
		s.relayExplicit(conn)
		return
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		s.log("event=capture decision=deny error_class=non_tcp_connection")
		return
	}
	original := s.OriginalDst
	if original == nil {
		original = originalDestination
	}
	destination, err := original(tcp)
	if err != nil {
		s.log("event=capture decision=deny error_class=original_destination_unavailable")
		return
	}
	s.relayTransparent(conn, destination)
}

func (s *Server) relayExplicit(client net.Conn) {
	upstream, err := s.dial(s.EgressProxy)
	if err != nil {
		s.log("event=capture mode=explicit decision=deny error_class=egress_unavailable")
		return
	}
	defer upstream.Close()
	s.log("event=capture mode=explicit decision=relay")
	relay(client, upstream)
}

func (s *Server) relayTransparent(client net.Conn, original string) {
	host, port, err := net.SplitHostPort(original)
	if err != nil {
		s.log("event=capture mode=transparent decision=deny error_class=invalid_original_destination")
		return
	}
	reader := bufio.NewReaderSize(client, s.inspectLimit())
	_ = client.SetReadDeadline(time.Now().Add(s.inspectTimeout()))
	detected, err := inspectHostname(reader, s.inspectLimit())
	_ = client.SetReadDeadline(time.Time{})
	if err != nil && !errors.Is(err, errHostnameUnavailable) {
		s.log("event=capture mode=transparent decision=deny error_class=malformed_preface")
		return
	}
	if detected != "" {
		host = detected
	}
	target := net.JoinHostPort(host, port)
	upstream, err := s.dial(s.EgressProxy)
	if err != nil {
		s.log("event=capture mode=transparent target_host=%s target_port=%s decision=deny error_class=egress_unavailable", host, port)
		return
	}
	defer upstream.Close()
	request := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
	if _, err := io.WriteString(upstream, request); err != nil {
		return
	}
	response, err := http.ReadResponse(bufio.NewReader(upstream), &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode/100 != 2 {
		s.log("event=capture mode=transparent target_host=%s target_port=%s decision=deny error_class=connect_rejected", host, port)
		return
	}
	_ = response.Body.Close()
	s.log("event=capture mode=transparent target_host=%s target_port=%s decision=relay", host, port)
	relayReaders(client, reader, upstream)
}

func (s *Server) dial(address string) (net.Conn, error) {
	dialer := s.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: defaultDialTimeout}
	}
	return dialer.Dial("tcp", address)
}

func (s *Server) inspectLimit() int {
	if s.InspectLimit <= 0 {
		return defaultInspectLimit
	}
	return s.InspectLimit
}

func (s *Server) inspectTimeout() time.Duration {
	if s.InspectTimeout <= 0 {
		return defaultInspectTimeout
	}
	return s.InspectTimeout
}

func (s *Server) log(format string, values ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, values...)
	}
}

var errHostnameUnavailable = captureinspect.ErrHostnameUnavailable

func inspectHostname(reader *bufio.Reader, limit int) (string, error) {
	return captureinspect.InspectHostname(reader, limit)
}

func relay(left, right net.Conn) { relayReaders(left, left, right) }

func relayReaders(left net.Conn, leftReader io.Reader, right net.Conn) {
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, _ = io.Copy(right, leftReader)
		closeWrite(right)
	}()
	go func() {
		defer wait.Done()
		_, _ = io.Copy(left, right)
		closeWrite(left)
	}()
	wait.Wait()
}

func closeWrite(conn net.Conn) {
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
		return
	}
	_ = conn.Close()
}
