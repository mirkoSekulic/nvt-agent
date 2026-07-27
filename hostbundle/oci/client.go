package oci

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/contract"
)

const maxMetadataBytes = 1024 * 1024

var (
	repositorySegmentPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	bearerParameterPattern   = regexp.MustCompile(`^\s*([a-z_]+)="([^"]*)"\s*$`)
)

type Source struct {
	Repository   string
	Digest       string
	OS           string
	Architecture string
}

type Client struct {
	http *http.Client
}

type repositoryLocation struct {
	base       *url.URL
	repository string
}

func NewClient(timeout time.Duration) (*Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return NewClientWithTransport(timeout, transport)
}

// NewClientWithTransport preserves the production source validation while
// allowing a caller to supply explicit CA/dial behavior. The bootstrap CLI uses
// NewClient and therefore the system trust store.
func NewClientWithTransport(timeout time.Duration, transport http.RoundTripper) (*Client, error) {
	if timeout <= 0 || timeout > 30*time.Minute || transport == nil {
		return nil, errors.New("host-bundle acquisition timeout is invalid")
	}
	return &Client{http: &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (client *Client) Pull(ctx context.Context, source Source) ([]byte, error) {
	location, err := client.validateSource(source)
	if err != nil {
		return nil, err
	}
	token := ""
	rootBytes, contentType, token, err := client.getRegistry(ctx, location, "manifests/"+source.Digest, contract.OCIIndexMediaType, token, maxMetadataBytes)
	if err != nil {
		return nil, err
	}
	if contentType != contract.OCIIndexMediaType || contract.Digest(rootBytes) != source.Digest {
		return nil, errors.New("host-bundle OCI index is invalid")
	}
	var index Index
	if err := contract.DecodeStrict(rootBytes, maxMetadataBytes, &index); err != nil || index.SchemaVersion != 2 || index.MediaType != contract.OCIIndexMediaType || index.ArtifactType != contract.ArtifactType {
		return nil, errors.New("host-bundle OCI index is invalid")
	}
	selected, err := selectPlatform(index.Manifests, source.OS, source.Architecture)
	if err != nil {
		return nil, err
	}
	manifestBytes, manifestType, token, err := client.getRegistry(ctx, location, "manifests/"+selected.Digest, contract.OCIManifestMediaType, token, maxMetadataBytes)
	if err != nil {
		return nil, err
	}
	if manifestType != contract.OCIManifestMediaType || int64(len(manifestBytes)) != selected.Size || contract.Digest(manifestBytes) != selected.Digest {
		return nil, errors.New("host-bundle OCI manifest is invalid")
	}
	var manifest Manifest
	if err := contract.DecodeStrict(manifestBytes, maxMetadataBytes, &manifest); err != nil || manifest.SchemaVersion != 2 || manifest.MediaType != contract.OCIManifestMediaType || manifest.ArtifactType != contract.ArtifactType {
		return nil, errors.New("host-bundle OCI manifest is invalid")
	}
	if err := validateDescriptor(manifest.Config, contract.OCIEmptyConfigMediaType, maxMetadataBytes); err != nil || len(manifest.Layers) != 1 {
		return nil, errors.New("host-bundle OCI manifest descriptors are invalid")
	}
	if err := validateDescriptor(manifest.Layers[0], contract.LayerMediaType, contract.MaxBundleBytes); err != nil {
		return nil, errors.New("host-bundle OCI layer descriptor is invalid")
	}
	configBytes, _, token, err := client.getRegistry(ctx, location, "blobs/"+manifest.Config.Digest, "", token, maxMetadataBytes)
	if err != nil {
		return nil, err
	}
	if int64(len(configBytes)) != manifest.Config.Size || contract.Digest(configBytes) != manifest.Config.Digest || !bytes.Equal(configBytes, []byte("{}")) {
		return nil, errors.New("host-bundle OCI config is invalid")
	}
	layer := manifest.Layers[0]
	layerBytes, _, _, err := client.getRegistry(ctx, location, "blobs/"+layer.Digest, "", token, contract.MaxBundleBytes)
	if err != nil {
		return nil, err
	}
	if int64(len(layerBytes)) != layer.Size || contract.Digest(layerBytes) != layer.Digest {
		return nil, errors.New("host-bundle OCI layer content is invalid")
	}
	return layerBytes, nil
}

func (client *Client) validateSource(source Source) (repositoryLocation, error) {
	if err := contract.ValidateDigest(source.Digest); err != nil || source.OS != "linux" || (source.Architecture != "amd64" && source.Architecture != "arm64") {
		return repositoryLocation{}, errors.New("host-bundle source is invalid")
	}
	parsed, err := url.Parse(source.Repository)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || parsed.Hostname() == "" {
		return repositoryLocation{}, errors.New("host-bundle repository is invalid")
	}
	if parsed.Port() != "" && parsed.Port() != "443" {
		return repositoryLocation{}, errors.New("host-bundle repository port is invalid")
	}
	if ip := net.ParseIP(parsed.Hostname()); ip != nil || strings.EqualFold(parsed.Hostname(), "localhost") {
		return repositoryLocation{}, errors.New("host-bundle repository host is invalid")
	}
	if !validDNSName(parsed.Hostname()) || parsed.Hostname() != strings.ToLower(parsed.Hostname()) {
		return repositoryLocation{}, errors.New("host-bundle repository host is invalid")
	}
	repository := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if repository == "" || strings.HasSuffix(repository, "/") || strings.Contains(repository, "//") {
		return repositoryLocation{}, errors.New("host-bundle repository path is invalid")
	}
	for _, segment := range strings.Split(repository, "/") {
		if !repositorySegmentPattern.MatchString(segment) {
			return repositoryLocation{}, errors.New("host-bundle repository path is invalid")
		}
	}
	base := &url.URL{Scheme: "https", Host: parsed.Host}
	return repositoryLocation{base: base, repository: repository}, nil
}

func selectPlatform(descriptors []Descriptor, operatingSystem, architecture string) (Descriptor, error) {
	var selected *Descriptor
	for index := range descriptors {
		descriptor := descriptors[index]
		if err := validateDescriptor(descriptor, contract.OCIManifestMediaType, maxMetadataBytes); err != nil || descriptor.ArtifactType != contract.ArtifactType || descriptor.Platform == nil {
			return Descriptor{}, errors.New("host-bundle OCI platform descriptor is invalid")
		}
		if descriptor.Platform.OS == operatingSystem && descriptor.Platform.Architecture == architecture {
			if selected != nil {
				return Descriptor{}, errors.New("host-bundle OCI platform is ambiguous")
			}
			copy := descriptor
			selected = &copy
		}
	}
	if selected == nil {
		return Descriptor{}, errors.New("host-bundle OCI platform is unavailable")
	}
	return *selected, nil
}

func validateDescriptor(descriptor Descriptor, mediaType string, maximum int64) error {
	if descriptor.MediaType != mediaType || contract.ValidateDigest(descriptor.Digest) != nil || descriptor.Size <= 0 || descriptor.Size > maximum {
		return errors.New("OCI descriptor is invalid")
	}
	return nil
}

func (client *Client) getRegistry(ctx context.Context, location repositoryLocation, suffix, accept, token string, maximum int64) ([]byte, string, string, error) {
	endpoint := *location.base
	endpoint.Path = "/v2/" + location.repository + "/" + suffix
	body, contentType, responseToken, status, challenge, err := client.request(ctx, endpoint.String(), accept, token, maximum)
	if err != nil {
		return nil, "", token, err
	}
	if status == http.StatusUnauthorized && token == "" {
		acquired, tokenErr := client.acquireAnonymousToken(ctx, location, challenge)
		if tokenErr != nil {
			return nil, "", token, tokenErr
		}
		body, contentType, responseToken, status, _, err = client.request(ctx, endpoint.String(), accept, acquired, maximum)
		if err != nil {
			return nil, "", token, err
		}
		token = acquired
	}
	if responseToken != "" {
		token = responseToken
	}
	if status != http.StatusOK {
		return nil, "", token, errors.New("host-bundle registry request was rejected")
	}
	return body, contentType, token, nil
}

func (client *Client) request(ctx context.Context, endpoint, accept, token string, maximum int64) ([]byte, string, string, int, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "", token, 0, "", errors.New("host-bundle registry request is invalid")
	}
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, "", token, 0, "", errors.New("host-bundle registry is unavailable")
	}
	limited := io.LimitReader(response.Body, maximum+1)
	body, readErr := io.ReadAll(limited)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || int64(len(body)) > maximum {
		return nil, "", token, 0, "", errors.New("host-bundle registry response exceeds the bound")
	}
	contentType := strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])
	return body, contentType, token, response.StatusCode, response.Header.Get("WWW-Authenticate"), nil
}

func (client *Client) acquireAnonymousToken(ctx context.Context, location repositoryLocation, challenge string) (string, error) {
	if !strings.HasPrefix(challenge, "Bearer ") || len(challenge) > 4096 {
		return "", errors.New("host-bundle registry authentication challenge is invalid")
	}
	parameters := map[string]string{}
	for _, raw := range strings.Split(strings.TrimPrefix(challenge, "Bearer "), ",") {
		match := bearerParameterPattern.FindStringSubmatch(raw)
		if len(match) != 3 || (match[1] != "realm" && match[1] != "service" && match[1] != "scope") {
			return "", errors.New("host-bundle registry authentication challenge is invalid")
		}
		if _, duplicate := parameters[match[1]]; duplicate {
			return "", errors.New("host-bundle registry authentication challenge is invalid")
		}
		parameters[match[1]] = match[2]
	}
	realm, err := url.Parse(parameters["realm"])
	expectedScope := "repository:" + location.repository + ":pull"
	if err != nil || realm.Scheme != "https" || realm.User != nil || !strings.EqualFold(realm.Host, location.base.Host) || realm.RawQuery != "" || realm.Fragment != "" || parameters["scope"] != expectedScope || parameters["service"] == "" {
		return "", errors.New("host-bundle registry authentication challenge is invalid")
	}
	query := realm.Query()
	query.Set("service", parameters["service"])
	query.Set("scope", expectedScope)
	realm.RawQuery = query.Encode()
	body, _, _, status, _, err := client.request(ctx, realm.String(), "application/json", "", 64*1024)
	if err != nil || status != http.StatusOK {
		return "", errors.New("host-bundle anonymous registry authentication failed")
	}
	var response struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in,omitempty"`
		IssuedAt    string `json:"issued_at,omitempty"`
	}
	if contract.DecodeStrict(body, 64*1024, &response) != nil {
		return "", errors.New("host-bundle anonymous registry authentication failed")
	}
	token := response.Token
	if token == "" {
		token = response.AccessToken
	}
	if token == "" || len(token) > 16*1024 || strings.ContainsAny(token, "\r\n") {
		return "", errors.New("host-bundle anonymous registry authentication failed")
	}
	return token, nil
}

func validDNSName(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}
