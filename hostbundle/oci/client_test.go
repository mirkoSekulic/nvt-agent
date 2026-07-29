package oci

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/bundle"
	"github.com/mirkoSekulic/nvt-agent/hostbundle/contract"
)

func TestPullValidArtifactByDigestWithAnonymousBearerAuthentication(t *testing.T) {
	layout, digest := buildTestLayout(t)
	server, transport := layoutServer(t, layout, func(writer http.ResponseWriter, request *http.Request) bool {
		if request.URL.Path == "/token" {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"token":"test-public-token","expires_in":300}`))
			return true
		}
		if request.Header.Get("Authorization") != "Bearer test-public-token" {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="https://registry.example.test/token",service="registry.example.test",scope="repository:nvt/host-bundle:pull"`)
			writer.WriteHeader(http.StatusUnauthorized)
			return true
		}
		return false
	})
	defer server.Close()
	client, err := NewClientWithTransport(5*time.Second, transport)
	if err != nil {
		t.Fatal(err)
	}
	layer, err := client.Pull(context.Background(), Source{
		Repository: "https://registry.example.test/nvt/host-bundle",
		Digest:     digest, OS: "linux", Architecture: "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(layer) == 0 {
		t.Fatal("empty layer")
	}
}

func TestPullRejectsSourcePlatformMediaAndCorruption(t *testing.T) {
	layout, digest := buildTestLayout(t)
	tests := []struct {
		name   string
		source Source
		mutate func(http.ResponseWriter, *http.Request) bool
	}{
		{name: "tag", source: Source{Repository: "https://registry.example.test/nvt/host-bundle", Digest: "latest", OS: "linux", Architecture: "amd64"}},
		{name: "wrong digest", source: Source{Repository: "https://registry.example.test/nvt/host-bundle", Digest: "sha256:" + strings.Repeat("f", 64), OS: "linux", Architecture: "amd64"}},
		{name: "plain HTTP", source: Source{Repository: "http://registry.example.test/nvt/host-bundle", Digest: digest, OS: "linux", Architecture: "amd64"}},
		{name: "unapproved port", source: Source{Repository: "https://registry.example.test:444/nvt/host-bundle", Digest: digest, OS: "linux", Architecture: "amd64"}},
		{name: "userinfo", source: Source{Repository: "https://user@registry.example.test/nvt/host-bundle", Digest: digest, OS: "linux", Architecture: "amd64"}},
		{name: "query", source: Source{Repository: "https://registry.example.test/nvt/host-bundle?ref=main", Digest: digest, OS: "linux", Architecture: "amd64"}},
		{name: "ip literal", source: Source{Repository: "https://127.0.0.1/nvt/host-bundle", Digest: digest, OS: "linux", Architecture: "amd64"}},
		{name: "wrong platform", source: Source{Repository: "https://registry.example.test/nvt/host-bundle", Digest: digest, OS: "linux", Architecture: "arm64"}},
		{name: "redirect", source: Source{Repository: "https://registry.example.test/nvt/host-bundle", Digest: digest, OS: "linux", Architecture: "amd64"}, mutate: func(writer http.ResponseWriter, request *http.Request) bool {
			if strings.Contains(request.URL.Path, "/manifests/") {
				writer.Header().Set("Location", "https://redirect.example.test/content")
				writer.WriteHeader(http.StatusTemporaryRedirect)
				return true
			}
			return false
		}},
		{name: "wrong media type", source: Source{Repository: "https://registry.example.test/nvt/host-bundle", Digest: digest, OS: "linux", Architecture: "amd64"}, mutate: func(writer http.ResponseWriter, request *http.Request) bool {
			if strings.Contains(request.URL.Path, "/manifests/") {
				requested := filepath.Base(request.URL.Path)
				content, _ := os.ReadFile(filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(requested, "sha256:")))
				writer.Header().Set("Content-Type", "application/octet-stream")
				_, _ = writer.Write(content)
				return true
			}
			return false
		}},
		{name: "corrupt layer", source: Source{Repository: "https://registry.example.test/nvt/host-bundle", Digest: digest, OS: "linux", Architecture: "amd64"}, mutate: func(writer http.ResponseWriter, request *http.Request) bool {
			if strings.Contains(request.URL.Path, "/blobs/") {
				requested := filepath.Base(request.URL.Path)
				content, _ := os.ReadFile(filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(requested, "sha256:")))
				if len(content) > 10 && string(content) != "{}" {
					content[len(content)/2] ^= 0xff
					_, _ = writer.Write(content)
					return true
				}
			}
			return false
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, transport := layoutServer(t, layout, test.mutate)
			defer server.Close()
			client, _ := NewClientWithTransport(5*time.Second, transport)
			if _, err := client.Pull(context.Background(), test.source); err == nil {
				t.Fatal("invalid OCI source/artifact was accepted")
			}
		})
	}
}

func TestPullTimeoutIsBoundedAndSanitized(t *testing.T) {
	_, digest := buildTestLayout(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()
	transport := mappedTransport(server)
	client, err := NewClientWithTransport(50*time.Millisecond, transport)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = client.Pull(context.Background(), Source{Repository: "https://registry.example.test/nvt/host-bundle", Digest: digest, OS: "linux", Architecture: "amd64"})
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("timeout was not bounded: %v", err)
	}
	if strings.Contains(err.Error(), "registry.example.test") || strings.Contains(err.Error(), digest) {
		t.Fatalf("error exposed source material: %v", err)
	}
}

func buildTestLayout(t *testing.T) (string, string) {
	t.Helper()
	directory := t.TempDir()
	source := filepath.Join(directory, "supervisor")
	if err := os.WriteFile(source, []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(directory, "bundle.tar.gz")
	manifest := contract.Manifest{
		ContractVersion: contract.Version, OS: "linux", Architecture: "amd64",
		BundleVersion: "0.8.33-test", BuildID: strings.Repeat("a", 40),
		NativeEntrypoint: "bin/nvt-guest-supervisor", ServiceIdentity: "nvt-agent-guest.service",
		Compatibility: contract.Compatibility{AgentdProtocol: contract.AgentdProtocolVersion, NativeSessionProtocol: contract.NativeSessionProtocolVersion},
	}
	if _, err := bundle.BuildArchive(archive, manifest, []bundle.InputFile{{Path: "bin/nvt-guest-supervisor", Source: source, Mode: 0o755}}); err != nil {
		t.Fatal(err)
	}
	layout := filepath.Join(directory, "oci")
	digest, err := BuildLayout(layout, "0.8.33-test", archive, "linux", "amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	return layout, digest
}

func layoutServer(t *testing.T, layout string, intercept func(http.ResponseWriter, *http.Request) bool) (*httptest.Server, *http.Transport) {
	t.Helper()
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if intercept != nil && intercept(writer, request) {
			return
		}
		parts := strings.Split(request.URL.Path, "/")
		if len(parts) < 2 {
			http.NotFound(writer, request)
			return
		}
		digest := parts[len(parts)-1]
		content, err := os.ReadFile(filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:")))
		if err != nil {
			http.NotFound(writer, request)
			return
		}
		if strings.Contains(request.URL.Path, "/manifests/") {
			var probe struct {
				MediaType string `json:"mediaType"`
			}
			_ = json.Unmarshal(content, &probe)
			writer.Header().Set("Content-Type", probe.MediaType)
		}
		writer.Header().Set("Content-Length", strconv.Itoa(len(content)))
		_, _ = writer.Write(content)
	})
	server := httptest.NewTLSServer(handler)
	return server, mappedTransport(server)
}

func mappedTransport(server *httptest.Server) *http.Transport {
	transport := server.Client().Transport.(*http.Transport).Clone()
	address := server.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} // test server only
	return transport
}
