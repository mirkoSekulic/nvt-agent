package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func main() {
	root := flag.String("layout", "/fixture/oci", "OCI layout root")
	certificate := flag.String("tls-cert", "/fixture/tls.crt", "TLS certificate")
	key := flag.String("tls-key", "/fixture/tls.key", "TLS private key")
	gatewayAddress := flag.String("gateway-address", ":7443", "test native-session gateway address")
	flag.Parse()
	if flag.NArg() != 0 {
		fatal("configuration is invalid")
	}
	certificatePair, err := tls.LoadX509KeyPair(*certificate, *key)
	if err != nil {
		fatal("TLS configuration failed")
	}
	if brokerURL := os.Getenv("NVT_TEST_BROKER_URL"); brokerURL != "" {
		brokerCA := os.Getenv("NVT_TEST_BROKER_CA_FILE")
		go serveNativeSessionGateway(*gatewayAddress, certificatePair, brokerURL, brokerCA)
	}
	server := &http.Server{
		Addr:              ":443",
		Handler:           handler(*root),
		ReadHeaderTimeout: 3 * time.Second,
		IdleTimeout:       5 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if err := server.ListenAndServeTLS(*certificate, *key); err != nil {
		fatal("server failed")
	}
}

func serveNativeSessionGateway(address string, certificate tls.Certificate, brokerURL, brokerCAPath string) {
	var caPEM []byte
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		value, err := os.ReadFile(brokerCAPath)
		if err == nil && len(value) > 0 && len(value) <= 1<<20 {
			caPEM = value
			break
		}
		time.Sleep(time.Second)
	}
	if len(caPEM) == 0 {
		fatal("gateway broker trust failed")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		fatal("gateway broker trust failed")
	}
	listener, err := tls.Listen("tcp", address, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}})
	if err != nil {
		fatal("gateway listener failed")
	}
	slots := make(chan struct{}, 16)
	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			fatal("gateway listener failed")
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); serveNativeConnection(connection, brokerURL, roots) }()
		default:
			_ = connection.Close()
		}
	}
}

func serveNativeConnection(connection net.Conn, brokerURL string, roots *x509.CertPool) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReaderSize(connection, guestenrollment.MaxNativeSessionFrameBytes)
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return
	}
	hello, err := guestenrollment.DecodeNativeSessionMessage(line)
	if err != nil || hello.Type != guestenrollment.NativeSessionHello || hello.Binding == nil {
		return
	}
	if !authenticateNativeSession(brokerURL, roots, hello.Credential, *hello.Binding) {
		writeNativeFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionHelloReject, Reason: "unauthorized",
		})
		return
	}
	hello.Credential = ""
	writeNativeFrame(connection, guestenrollment.NativeSessionMessage{
		ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionHelloAck,
		Binding: hello.Binding, Audience: guestenrollment.NativeGuestControlAudience,
	})
	writeNativeFrame(connection, guestenrollment.NativeSessionMessage{
		ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionAgentdRequest, RequestID: "qemu-health",
		Payload: json.RawMessage(`{"type":"health"}`),
	})
	responseLine, err := reader.ReadSlice('\n')
	if err != nil {
		return
	}
	response, err := guestenrollment.DecodeNativeSessionMessage(responseLine)
	if err != nil || response.Type != guestenrollment.NativeSessionAgentdResponse ||
		response.RequestID != "qemu-health" || !bytes.Contains(response.Payload, []byte(`"status":"ready"`)) {
		return
	}
	_ = connection.SetDeadline(time.Time{})
	for {
		_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return
		}
		frame, err := guestenrollment.DecodeNativeSessionMessage(line)
		if err != nil || frame.Type != guestenrollment.NativeSessionPing {
			return
		}
		writeNativeFrame(connection, guestenrollment.NativeSessionMessage{
			ContractVersion: guestenrollment.NativeSessionVersion, Type: guestenrollment.NativeSessionPong,
		})
	}
}

func authenticateNativeSession(brokerURL string, roots *x509.CertPool, credential string, value guestenrollment.Binding) bool {
	payload, _ := json.Marshal(guestenrollment.GuestSessionAuthenticateRequest{
		ContractVersion: guestenrollment.GuestSessionIdentityVersion, Binding: value, Audience: guestenrollment.NativeGuestControlAudience,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(brokerURL, "/")+guestenrollment.GuestSessionIdentityAuthenticatePath, bytes.NewReader(payload))
	if err != nil {
		return false
	}
	request.Header.Set("Authorization", "Bearer "+credential)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	client := &http.Client{Transport: &http.Transport{
		Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second,
	}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 16<<10))
	return response.StatusCode == http.StatusOK && response.Header.Get("Content-Type") == "application/json"
}

func writeNativeFrame(connection net.Conn, value guestenrollment.NativeSessionMessage) {
	encoded, err := guestenrollment.EncodeNativeSessionMessage(value)
	if err != nil {
		return
	}
	_, _ = io.Copy(connection, bytes.NewReader(encoded))
	for index := range encoded {
		encoded[index] = 0
	}
}

func handler(root string) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			response.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if request.URL.Path == "/v2/" {
			response.WriteHeader(http.StatusOK)
			return
		}
		const prefix = "/v2/nvt/host-bundle/"
		if !strings.HasPrefix(request.URL.Path, prefix) {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		path := strings.TrimPrefix(request.URL.Path, prefix)
		var digest string
		switch {
		case strings.HasPrefix(path, "manifests/"):
			digest = strings.TrimPrefix(path, "manifests/")
		case strings.HasPrefix(path, "blobs/"):
			digest = strings.TrimPrefix(path, "blobs/")
		default:
			response.WriteHeader(http.StatusNotFound)
			return
		}
		if !digestPattern.MatchString(digest) {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		content, err := os.ReadFile(filepath.Join(root, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:")))
		if err != nil || len(content) == 0 {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		if strings.HasPrefix(path, "manifests/") {
			var value struct {
				MediaType string `json:"mediaType"`
			}
			if json.Unmarshal(content, &value) != nil || value.MediaType == "" {
				response.WriteHeader(http.StatusInternalServerError)
				return
			}
			response.Header().Set("Content-Type", value.MediaType)
		} else {
			response.Header().Set("Content-Type", "application/octet-stream")
		}
		response.Header().Set("Content-Length", fmt.Sprint(len(content)))
		response.WriteHeader(http.StatusOK)
		if request.Method == http.MethodGet {
			_, _ = response.Write(content)
		}
	})
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, "nvt-host-bundle-registry-fixture: "+message)
	os.Exit(1)
}
