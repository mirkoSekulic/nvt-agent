// Command nvt-qemu-agent-fixture is installed only in the unpublished QEMU
// reference guest. It proves that an ordinary UID-65532 process can use both
// native capture paths without receiving any credential material.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maximumResponseBytes = 16 << 10

type result struct {
	TransparentCredentialMatch bool   `json:"transparent_credential_match"`
	ExplicitCredentialMatch    bool   `json:"explicit_credential_match"`
	AuthorityMaterialAbsent    bool   `json:"authority_material_absent"`
	Failure                    string `json:"failure,omitempty"`
}

type echoResponse struct {
	Authenticated   bool `json:"authenticated"`
	CredentialMatch bool `json:"credential_match"`
}

func main() {
	host := flag.String("host", "", "test upstream host")
	port := flag.Int("port", 0, "test upstream port")
	capability := flag.String("capability", "", "non-secret capability selector")
	explicit := flag.String("explicit-proxy", "", "explicit capture listener")
	output := flag.String("output", "", "non-secret proof output")
	flag.Parse()
	if flag.NArg() != 0 || *host == "" || *port < 1 || *port > 65535 || *capability == "" || *explicit == "" || *output == "" || authorityMaterialPresent(os.Args, os.Environ()) {
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := os.Stat(*output); err != nil {
		if !errors.Is(err, os.ErrNotExist) || writeProof(*output, result{Failure: "explicit-pending"}) != nil {
			os.Exit(1)
		}
	}
	explicitResult, err := retryProbe(ctx, func(operation context.Context) (echoResponse, error) {
		response, probeErr := probeExplicit(operation, *explicit, *host, *port, *capability)
		if probeErr != nil {
			_ = writeProof(*output, result{Failure: "explicit-" + failureClass(probeErr)})
		}
		return response, probeErr
	})
	if err != nil {
		_ = writeProof(*output, result{Failure: "explicit-" + failureClass(err)})
		os.Exit(1)
	}
	_ = writeProof(*output, result{Failure: "transparent-pending"})
	transparent, err := retryProbe(ctx, func(operation context.Context) (echoResponse, error) {
		response, probeErr := probeTransparent(operation, *host, *port)
		if probeErr != nil {
			_ = writeProof(*output, result{Failure: "transparent-" + failureClass(probeErr)})
		}
		return response, probeErr
	})
	if err != nil {
		_ = writeProof(*output, result{Failure: "transparent-" + failureClass(err)})
		os.Exit(1)
	}
	proof := result{
		TransparentCredentialMatch: transparent.Authenticated && transparent.CredentialMatch,
		ExplicitCredentialMatch:    explicitResult.Authenticated && explicitResult.CredentialMatch,
		AuthorityMaterialAbsent:    !authorityMaterialPresent(os.Args, os.Environ()),
	}
	if !proof.TransparentCredentialMatch || !proof.ExplicitCredentialMatch || !proof.AuthorityMaterialAbsent || writeProof(*output, proof) != nil {
		os.Exit(1)
	}
	lifetime, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-lifetime.Done()
}

func retryProbe(ctx context.Context, operation func(context.Context) (echoResponse, error)) (echoResponse, error) {
	var lastError error
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
		response, err := operation(attempt)
		cancel()
		if err == nil && response.Authenticated && response.CredentialMatch {
			return response, nil
		}
		lastError = err
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	if lastError == nil {
		lastError = errors.New("unavailable")
	}
	return echoResponse{}, lastError
}

func probeTransparent(ctx context.Context, host string, port int) (echoResponse, error) {
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(addresses) == 0 {
		return echoResponse{}, errors.New("resolve-unavailable")
	}
	dialer := &net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(addresses[0].String(), strconv.Itoa(port)))
	if err != nil {
		return echoResponse{}, errors.New("dial-unavailable")
	}
	return exchange(ctx, connection, host, "/transparent")
}

func probeExplicit(ctx context.Context, proxy, host string, port int, capability string) (echoResponse, error) {
	dialer := &net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return echoResponse{}, errors.New("dial-unavailable")
	}
	authority := net.JoinHostPort(host, strconv.Itoa(port))
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: authority}, Host: authority, Header: make(http.Header)}
	request.Header.Set("X-NVT-Capability", capability)
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := request.Write(connection); err != nil {
		connection.Close()
		return echoResponse{}, errors.New("request-unavailable")
	}
	reader := bufio.NewReaderSize(connection, maximumResponseBytes)
	response, err := http.ReadResponse(reader, request)
	if err != nil || response.StatusCode != http.StatusOK || response.ContentLength > 0 || len(response.TransferEncoding) != 0 {
		connection.Close()
		return echoResponse{}, errors.New("connect-unavailable")
	}
	return exchange(ctx, &bufferedConn{Conn: connection, reader: reader}, host, "/explicit")
}

func exchange(ctx context.Context, raw net.Conn, host, path string) (echoResponse, error) {
	defer raw.Close()
	// The per-run MITM CA is deliberately not part of the portable attachment.
	// This unpublished fixture validates only the mediated transport/injection
	// proof and never makes this test-only trust relaxation agent configuration.
	tlsConnection := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}) //nolint:gosec
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConnection.SetDeadline(deadline)
	}
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return echoResponse{}, errors.New("tls-unavailable")
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path, nil)
	if err := request.Write(tlsConnection); err != nil {
		return echoResponse{}, errors.New("request-unavailable")
	}
	response, err := http.ReadResponse(bufio.NewReaderSize(tlsConnection, maximumResponseBytes), request)
	if err != nil || response.StatusCode != http.StatusOK {
		return echoResponse{}, errors.New("response-unavailable")
	}
	defer response.Body.Close()
	var reflected echoResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, maximumResponseBytes+1))
	if decoder.Decode(&reflected) != nil || !reflected.Authenticated || !reflected.CredentialMatch {
		return echoResponse{}, errors.New("response-invalid")
	}
	return reflected, nil
}

func failureClass(err error) string {
	if err == nil {
		return "unavailable"
	}
	for _, value := range []string{"resolve-unavailable", "dial-unavailable", "request-unavailable", "connect-unavailable", "tls-unavailable", "response-unavailable", "response-invalid"} {
		if err.Error() == value {
			return value
		}
	}
	return "unavailable"
}

func writeProof(path string, value result) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(encoded, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func authorityMaterialPresent(arguments, environment []string) bool {
	joined := strings.ToLower(strings.Join(append(append([]string{}, arguments...), environment...), "\x00"))
	for _, forbidden := range []string{"nvt_eg1_", "nvt_ri1_", "runtime_identity", "egress_broker_token", "relay_control", "relay-control"} {
		if strings.Contains(joined, forbidden) {
			return true
		}
	}
	return false
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (connection *bufferedConn) Read(destination []byte) (int, error) {
	return connection.reader.Read(destination)
}
