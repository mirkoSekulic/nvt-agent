package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func main() {
	root := flag.String("layout", "/fixture/oci", "OCI layout root")
	certificate := flag.String("tls-cert", "/fixture/tls.crt", "TLS certificate")
	key := flag.String("tls-key", "/fixture/tls.key", "TLS private key")
	flag.Parse()
	if flag.NArg() != 0 {
		fatal("configuration is invalid")
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
