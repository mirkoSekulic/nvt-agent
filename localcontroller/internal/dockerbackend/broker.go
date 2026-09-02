package dockerbackend

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
	"gopkg.in/yaml.v3"
)

const (
	placeholder            = "NVT-PLACEHOLDER-NOT-A-KEY"
	maxBrokerResponseBytes = 1 << 20
)

type brokerPreparer struct {
	baseURL string
	client  *http.Client
}

type placeholderResponse struct {
	OK        bool              `json:"ok"`
	Files     []placeholderFile `json:"files"`
	Hosts     []string          `json:"hosts"`
	ExpiresAt *string           `json:"expires_at"`
}

type placeholderFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    string `json:"mode"`
}

type identityResponse struct {
	OK    bool   `json:"ok"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type catalogResponse struct {
	OK        bool              `json:"ok"`
	Files     []placeholderFile `json:"files"`
	Routes    []catalogRoute    `json:"routes"`
	ExpiresAt *string           `json:"expires_at"`
}

type catalogRoute struct {
	ID                   string `json:"id"`
	Host                 string `json:"host"`
	Upstream             string `json:"upstream"`
	ServerName           string `json:"server_name"`
	CAPEM                string `json:"ca_pem"`
	AllowPrivateUpstream bool   `json:"allow_private_upstream"`
}

func newBrokerPreparer(rawURL, caFile string, timeout time.Duration) (*brokerPreparer, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("broker endpoint unavailable")
	}
	transport := &http.Transport{}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, errors.New("broker endpoint unavailable")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("broker endpoint unavailable")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &brokerPreparer{
		baseURL: strings.TrimRight(rawURL, "/"),
		client: &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}, nil
}

func (preparer *brokerPreparer) prepare(ctx context.Context, run resolvedrun.ResolvedAgentRun, token string, rendered json.RawMessage) (json.RawMessage, []byte, []catalogRoute, error) {
	files := []placeholderFile{}
	routes := []catalogRoute{}
	seenPaths := map[string]bool{}
	for _, grant := range run.Broker.Grants {
		if grant.Materialization != "placeholder-file" {
			continue
		}
		payload, _ := json.Marshal(map[string]string{"provider": grant.Provider})
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, preparer.baseURL+"/v1/placeholder-files", bytes.NewReader(payload))
		if err != nil {
			return nil, nil, nil, errors.New("broker preparation unavailable")
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response, err := preparer.client.Do(request)
		if err != nil {
			return nil, nil, nil, errors.New("broker preparation unavailable")
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxBrokerResponseBytes+1))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(body) > maxBrokerResponseBytes || response.StatusCode != http.StatusOK {
			clear(body)
			return nil, nil, nil, errors.New("broker preparation unavailable")
		}
		var decoded placeholderResponse
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		decodeErr := decoder.Decode(&decoded)
		if decodeErr == nil {
			decodeErr = requireJSONEOF(decoder)
		}
		clear(body)
		if decodeErr != nil || !decoded.OK || len(decoded.Files) == 0 || len(decoded.Files) > 32 {
			return nil, nil, nil, errors.New("broker preparation unavailable")
		}
		for _, file := range decoded.Files {
			if !validPlaceholderFile(file) || seenPaths[file.Path] {
				return nil, nil, nil, errors.New("broker preparation unavailable")
			}
			seenPaths[file.Path] = true
			files = append(files, file)
		}
	}
	for _, grant := range run.Broker.Grants {
		if !containsPreparation(grant.Preparations, "catalog") {
			continue
		}
		payload, _ := json.Marshal(map[string]string{"provider": grant.Provider})
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, preparer.baseURL+"/v1/catalog", bytes.NewReader(payload))
		if err != nil {
			return nil, nil, nil, errors.New("broker preparation unavailable")
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response, err := preparer.client.Do(request)
		if err != nil {
			return nil, nil, nil, errors.New("broker preparation unavailable")
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxBrokerResponseBytes+1))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(body) > maxBrokerResponseBytes || response.StatusCode != http.StatusOK {
			clear(body)
			return nil, nil, nil, errors.New("broker preparation unavailable")
		}
		var decoded catalogResponse
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		decodeErr := decoder.Decode(&decoded)
		if decodeErr == nil {
			decodeErr = requireJSONEOF(decoder)
		}
		clear(body)
		if decodeErr != nil || !decoded.OK || len(decoded.Files) == 0 || len(decoded.Files) > 32 || len(decoded.Routes) == 0 || len(decoded.Routes) > 512 {
			return nil, nil, nil, errors.New("broker preparation unavailable")
		}
		allowedHosts := map[string]bool{}
		for _, value := range grant.EgressHosts {
			allowedHosts[strings.TrimSuffix(value, ":443")] = true
		}
		allowedResources := map[string]bool{}
		for _, value := range grant.Resources {
			allowedResources[value] = true
		}
		for _, file := range decoded.Files {
			file, err = bindCatalogFile(file, grant.Provider, decoded.Routes)
			if err != nil {
				return nil, nil, nil, errors.New("broker preparation unavailable")
			}
			if !validCatalogFile(file) || seenPaths[file.Path] {
				return nil, nil, nil, errors.New("broker preparation unavailable")
			}
			seenPaths[file.Path] = true
			files = append(files, file)
		}
		seenRouteHosts := map[string]bool{}
		for _, route := range decoded.Routes {
			if !validCatalogRoute(route) || !allowedHosts[route.Host] || !allowedResources[route.ID] || seenRouteHosts[route.Host] {
				return nil, nil, nil, errors.New("broker preparation unavailable")
			}
			seenRouteHosts[route.Host] = true
			routes = append(routes, route)
		}
		if len(seenRouteHosts) != len(allowedResources) {
			return nil, nil, nil, errors.New("broker preparation unavailable")
		}
	}
	metadata, err := preparer.prepareMetadata(ctx, run, token)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(files) == 0 {
		return append(json.RawMessage(nil), rendered...), metadata, routes, nil
	}
	var root map[string]any
	decoder := json.NewDecoder(bytes.NewReader(rendered))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil, nil, nil, errors.New("agent configuration unavailable")
	}
	preseed, _ := root["preseed"].(map[string]any)
	if preseed == nil {
		preseed = map[string]any{}
	}
	entries, _ := preseed["files"].([]any)
	for _, file := range files {
		mode := file.Mode
		if mode == "" {
			mode = "0600"
		}
		entry := map[string]any{
			"path": "$HOME/" + file.Path, "content": file.Content, "mode": mode, "overwrite": true,
		}
		if file.Path == ".kube/config" {
			entry["preserve-yaml-selection"] = map[string]string{"field": "current-context", "collection": "contexts", "item-field": "name"}
		}
		entries = append(entries, entry)
	}
	preseed["files"] = entries
	root["preseed"] = preseed
	output, err := json.Marshal(root)
	if err != nil || len(output) > resolvedrun.MaxDocumentBytes {
		return nil, nil, nil, errors.New("agent configuration unavailable")
	}
	return output, metadata, routes, nil
}

func (preparer *brokerPreparer) prepareMetadata(ctx context.Context, run resolvedrun.ResolvedAgentRun, token string) ([]byte, error) {
	providers := map[string]any{}
	for _, grant := range run.Broker.Grants {
		requested := false
		for _, operation := range grant.Preparations {
			if operation == "catalog" {
				continue
			}
			if operation != "identity" {
				return nil, errors.New("broker preparation unavailable")
			}
			requested = true
		}
		if !requested {
			continue
		}
		payload, _ := json.Marshal(map[string]string{"provider": grant.Provider})
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, preparer.baseURL+"/v1/identity", bytes.NewReader(payload))
		if err != nil {
			return nil, errors.New("broker preparation unavailable")
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response, err := preparer.client.Do(request)
		if err != nil {
			return nil, errors.New("broker preparation unavailable")
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(body) > 64<<10 || response.StatusCode != http.StatusOK {
			clear(body)
			return nil, errors.New("broker preparation unavailable")
		}
		var decoded identityResponse
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		decodeErr := decoder.Decode(&decoded)
		if decodeErr == nil {
			decodeErr = requireJSONEOF(decoder)
		}
		clear(body)
		if decodeErr != nil || !decoded.OK || !validIdentityValue(decoded.Name) || !validIdentityValue(decoded.Email) {
			return nil, errors.New("broker preparation unavailable")
		}
		providers[grant.Provider] = map[string]any{"identity": map[string]string{"name": decoded.Name, "email": decoded.Email}}
	}
	if len(providers) == 0 {
		return nil, nil
	}
	encoded, err := json.Marshal(map[string]any{"version": 1, "providers": providers})
	if err != nil || len(encoded) > 64<<10 {
		return nil, errors.New("broker preparation unavailable")
	}
	return encoded, nil
}

func containsPreparation(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func validCatalogFile(file placeholderFile) bool {
	if file.Path == "" || len(file.Path) > 4096 || strings.HasPrefix(file.Path, "/") || strings.Contains(file.Path, "\\") || len(file.Content) == 0 || len(file.Content) > 256<<10 {
		return false
	}
	for _, segment := range strings.Split(path.Clean(file.Path), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	mode := file.Mode
	if mode == "" {
		mode = "0600"
	}
	return path.Clean(file.Path) == file.Path && len(mode) == 4 && strings.Trim(mode, "01234567") == ""
}

func validCatalogRoute(route catalogRoute) bool {
	if route.ID == "" || route.Host == "" || route.Upstream == "" || route.ServerName == "" || route.CAPEM == "" ||
		strings.ContainsAny(route.Host+route.Upstream+route.ServerName, "/\\@?# \t\r\n") || !strings.Contains(route.CAPEM, "BEGIN CERTIFICATE") {
		return false
	}
	parsed, err := url.Parse("https://" + route.Host)
	return err == nil && parsed.Hostname() == route.Host && parsed.Port() == ""
}

func bindCatalogFile(file placeholderFile, provider string, routes []catalogRoute) (placeholderFile, error) {
	if file.Path != ".kube/config" {
		return file, nil
	}
	routeHosts := map[string]bool{}
	for _, route := range routes {
		routeHosts[route.Host] = true
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(file.Content), &document); err != nil {
		return placeholderFile{}, errors.New("catalog file is invalid")
	}
	clusters, ok := document["clusters"].([]any)
	if !ok || len(clusters) == 0 {
		return placeholderFile{}, errors.New("catalog file is invalid")
	}
	proxyURL, err := url.Parse("http://127.0.0.1:15002")
	if err != nil {
		return placeholderFile{}, errors.New("catalog file is invalid")
	}
	proxyURL.User = url.UserPassword(provider, "x")
	for _, raw := range clusters {
		entry, ok := raw.(map[string]any)
		if !ok {
			return placeholderFile{}, errors.New("catalog file is invalid")
		}
		cluster, ok := entry["cluster"].(map[string]any)
		server, serverOK := cluster["server"].(string)
		parsed, parseErr := url.Parse(server)
		if !ok || !serverOK || parseErr != nil || parsed.Scheme != "https" || !routeHosts[parsed.Hostname()] {
			return placeholderFile{}, errors.New("catalog file is invalid")
		}
		cluster["proxy-url"] = proxyURL.String()
	}
	encoded, err := yaml.Marshal(document)
	if err != nil || len(encoded) > 256<<10 {
		return placeholderFile{}, errors.New("catalog file is invalid")
	}
	file.Content = string(encoded)
	return file, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func validIdentityValue(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len([]byte(value)) > 512 {
		return false
	}
	for _, character := range value {
		if character < 32 || character == 127 {
			return false
		}
	}
	return true
}

func validPlaceholderFile(file placeholderFile) bool {
	if file.Path == "" || len(file.Path) > 4096 || strings.HasPrefix(file.Path, "/") || strings.Contains(file.Path, "\\") ||
		len(file.Content) > 256<<10 || !strings.Contains(file.Content, placeholder) {
		return false
	}
	for _, segment := range strings.Split(path.Clean(file.Path), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	if path.Clean(file.Path) != file.Path {
		return false
	}
	mode := file.Mode
	if mode == "" {
		mode = "0600"
	}
	return len(mode) == 4 && strings.Trim(mode, "01234567") == ""
}
