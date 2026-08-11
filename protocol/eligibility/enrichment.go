package eligibility

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	defaultTimeoutSeconds      = 5
	defaultMaxResponseBytes    = 64 * 1024
	defaultMaxDepth            = 8
	defaultMaxArrayItems       = 64
	defaultMaxObjectProperties = 64
	defaultMaxTotalNodes       = 1024
	defaultMaxStringBytes      = 1024

	hardMaxTimeoutSeconds   = 30
	hardMaxResponseBytes    = 1024 * 1024
	hardMaxDepth            = 16
	hardMaxArrayItems       = 256
	hardMaxObjectProperties = 256
	hardMaxTotalNodes       = 4096
	hardMaxStringBytes      = 8192
	maxSources              = 8
	maxAllowedHosts         = 32
)

const MaxAllowedHosts = maxAllowedHosts

var (
	claimNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	dnsHostPattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
)

type EnrichmentConfig struct {
	AllowedHosts   []string       `json:"allowedHosts"`
	TimeoutSeconds int            `json:"timeoutSeconds,omitempty"`
	Limits         ResponseLimits `json:"limits,omitempty"`
	Sources        []ClaimSource  `json:"sources"`
}

type ClaimSource struct {
	Endpoint    string `json:"endpoint"`
	OutputClaim string `json:"outputClaim"`
	ValuePath   string `json:"valuePath"`
}

type ResponseLimits struct {
	MaxResponseBytes    int64 `json:"maxResponseBytes,omitempty"`
	MaxDepth            int   `json:"maxDepth,omitempty"`
	MaxArrayItems       int   `json:"maxArrayItems,omitempty"`
	MaxObjectProperties int   `json:"maxObjectProperties,omitempty"`
	MaxTotalNodes       int   `json:"maxTotalNodes,omitempty"`
	MaxStringBytes      int   `json:"maxStringBytes,omitempty"`
}

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type EnrichOptions struct {
	Client    HTTPClient
	UserAgent string
	// TimeoutOverride is test-only consumer plumbing. Deployment behavior uses
	// the declarative timeoutSeconds value.
	TimeoutOverride time.Duration
}

func (c EnrichmentConfig) effectiveLimits() ResponseLimits {
	limits := c.Limits
	if limits.MaxResponseBytes == 0 {
		limits.MaxResponseBytes = defaultMaxResponseBytes
	}
	if limits.MaxDepth == 0 {
		limits.MaxDepth = defaultMaxDepth
	}
	if limits.MaxArrayItems == 0 {
		limits.MaxArrayItems = defaultMaxArrayItems
	}
	if limits.MaxObjectProperties == 0 {
		limits.MaxObjectProperties = defaultMaxObjectProperties
	}
	if limits.MaxTotalNodes == 0 {
		limits.MaxTotalNodes = defaultMaxTotalNodes
	}
	if limits.MaxStringBytes == 0 {
		limits.MaxStringBytes = defaultMaxStringBytes
	}
	return limits
}

func (c EnrichmentConfig) timeout() time.Duration {
	seconds := c.TimeoutSeconds
	if seconds == 0 {
		seconds = defaultTimeoutSeconds
	}
	return time.Duration(seconds) * time.Second
}

func (c EnrichmentConfig) Validate(prefix string) error {
	if prefix == "" {
		prefix = "claimEnrichment"
	}
	if len(c.Sources) > maxSources {
		return fmt.Errorf("%s.sources must contain at most %d entries", prefix, maxSources)
	}
	if len(c.AllowedHosts) > maxAllowedHosts {
		return fmt.Errorf("%s.allowedHosts must contain at most %d entries", prefix, maxAllowedHosts)
	}
	if c.TimeoutSeconds < 0 || c.TimeoutSeconds > hardMaxTimeoutSeconds {
		return fmt.Errorf("%s.timeoutSeconds must be between 1 and %d when set", prefix, hardMaxTimeoutSeconds)
	}
	limits := c.effectiveLimits()
	if limits.MaxResponseBytes < 1 || limits.MaxResponseBytes > hardMaxResponseBytes ||
		limits.MaxDepth < 1 || limits.MaxDepth > hardMaxDepth ||
		limits.MaxArrayItems < 1 || limits.MaxArrayItems > hardMaxArrayItems ||
		limits.MaxObjectProperties < 1 || limits.MaxObjectProperties > hardMaxObjectProperties ||
		limits.MaxTotalNodes < 1 || limits.MaxTotalNodes > hardMaxTotalNodes ||
		limits.MaxStringBytes < 1 || limits.MaxStringBytes > hardMaxStringBytes {
		return fmt.Errorf("%s.limits exceed safe bounds", prefix)
	}
	allowed := make(map[string]struct{}, len(c.AllowedHosts))
	for index, host := range c.AllowedHosts {
		if !validHost(host) {
			return fmt.Errorf("%s.allowedHosts[%d] must be a normalized lowercase DNS hostname or IPv4 address without a port", prefix, index)
		}
		if _, exists := allowed[host]; exists {
			return fmt.Errorf("%s.allowedHosts[%d] is duplicated", prefix, index)
		}
		allowed[host] = struct{}{}
	}
	seenClaims := make(map[string]struct{}, len(c.Sources))
	for index, source := range c.Sources {
		parsed, err := url.Parse(source.Endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("%s.sources[%d].endpoint must be an absolute HTTPS URL without credentials, query, or fragment", prefix, index)
		}
		if _, exists := allowed[strings.ToLower(parsed.Hostname())]; !exists {
			return fmt.Errorf("%s.sources[%d].endpoint host is not allowed", prefix, index)
		}
		if !claimNamePattern.MatchString(source.OutputClaim) || sensitiveEnrichmentPath(source.OutputClaim) {
			return fmt.Errorf("%s.sources[%d].outputClaim must be a safe non-sensitive top-level claim name", prefix, index)
		}
		if _, exists := seenClaims[source.OutputClaim]; exists {
			return fmt.Errorf("%s.sources[%d].outputClaim is duplicated", prefix, index)
		}
		seenClaims[source.OutputClaim] = struct{}{}
		if source.ValuePath != "$" && !validClaimPath(source.ValuePath) || sensitiveEnrichmentPath(source.ValuePath) {
			return fmt.Errorf("%s.sources[%d].valuePath must be $ or a safe non-sensitive JSON path", prefix, index)
		}
	}
	if len(c.Sources) > 0 && len(allowed) == 0 {
		return fmt.Errorf("%s.allowedHosts is required when sources are configured", prefix)
	}
	return nil
}

func validHost(host string) bool {
	if host == "" || host != strings.TrimSpace(host) || host != strings.ToLower(host) || strings.ContainsAny(host, "/@?#:") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if !dnsHostPattern.MatchString(host) || strings.Contains(host, "..") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

func ValidHost(host string) bool { return validHost(host) }

func sensitiveEnrichmentPath(path string) bool {
	if isSensitivePath(path) {
		return true
	}
	for _, segment := range strings.Split(path, ".") {
		if sensitiveDataKey(strings.TrimSuffix(segment, "[]")) {
			return true
		}
	}
	return false
}

func SensitiveEnrichmentPath(path string) bool { return sensitiveEnrichmentPath(path) }

func Enrich(ctx context.Context, config EnrichmentConfig, accessToken string, claims map[string]any, options EnrichOptions) (map[string]any, error) {
	enriched := make(map[string]any, len(claims)+len(config.Sources))
	for key, value := range claims {
		enriched[key] = value
	}
	if len(config.Sources) == 0 {
		return enriched, nil
	}
	if accessToken == "" || options.Client == nil {
		return nil, errors.New("OAuth access token is unavailable for configured claim enrichment")
	}
	timeout := config.timeout()
	if options.TimeoutOverride > 0 {
		timeout = options.TimeoutOverride
	}
	for _, source := range config.Sources {
		if _, exists := enriched[source.OutputClaim]; exists {
			return nil, errors.New("configured claim enrichment output collides with an authenticated claim")
		}
		requestContext, cancel := context.WithTimeout(ctx, timeout)
		value, err := fetchClaim(requestContext, config, source, accessToken, options)
		cancel()
		if err != nil {
			return nil, err
		}
		enriched[source.OutputClaim] = value
	}
	return enriched, nil
}

func fetchClaim(ctx context.Context, config EnrichmentConfig, source ClaimSource, accessToken string, options EnrichOptions) (any, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.Endpoint, nil)
	if err != nil {
		return nil, errors.New("build OAuth claim source request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+accessToken)
	if options.UserAgent != "" {
		request.Header.Set("User-Agent", options.UserAgent)
	}
	response, err := options.Client.Do(request)
	request.Header.Del("Authorization")
	if err != nil {
		return nil, errors.New("request OAuth claim source")
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, errors.New("OAuth claim source rejected request")
	}
	if response.Request != nil && response.Request.URL.String() != source.Endpoint {
		return nil, errors.New("OAuth claim source redirected request")
	}
	limits := config.effectiveLimits()
	body, err := io.ReadAll(io.LimitReader(response.Body, limits.MaxResponseBytes+1))
	if err != nil || int64(len(body)) > limits.MaxResponseBytes {
		return nil, errors.New("read OAuth claim source response")
	}
	defer clear(body)
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	nodes := 0
	document, err := decodeBoundedJSON(decoder, 1, limits, &nodes)
	if err != nil {
		return nil, errors.New("decode OAuth claim source response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode OAuth claim source response")
	}
	selected, ok := Select(document, source.ValuePath)
	if !ok || len(selected) != 1 || selected[0] == nil {
		return nil, errors.New("OAuth claim source value is missing or ambiguous")
	}
	if containsSensitiveData(selected[0]) || containsToken(selected[0], accessToken) {
		return nil, errors.New("OAuth claim source value is invalid")
	}
	return selected[0], nil
}

// sensitiveDataKey rejects secret-bearing or stable personal identifiers at
// every depth of a selected enrichment result. The two authorization-structure
// names are explicitly data, not credentials, and remain valid policy inputs.
func sensitiveDataKey(key string) bool {
	compact := strings.NewReplacer(".", "", "[", "", "]", "", "-", "", "_", "").
		Replace(strings.ToLower(strings.ReplaceAll(key, "ø", "o")))
	if compact == "authorizationdetails" || compact == "authorizedparties" {
		return false
	}
	switch compact {
	case "pid", "ssn", "fodselsnummer", "foedselsnummer", "authorization":
		return true
	}
	return strings.HasSuffix(compact, "token") ||
		strings.Contains(compact, "secret") ||
		strings.Contains(compact, "password") ||
		strings.Contains(compact, "credential")
}

func containsSensitiveData(value any) bool {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if containsSensitiveData(item) {
				return true
			}
		}
	case map[string]any:
		for key, item := range typed {
			if sensitiveDataKey(key) || containsSensitiveData(item) {
				return true
			}
		}
	}
	return false
}

func decodeBoundedJSON(decoder *json.Decoder, depth int, limits ResponseLimits, nodes *int) (any, error) {
	if depth > limits.MaxDepth {
		return nil, errors.New("maximum JSON depth exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	(*nodes)++
	if *nodes > limits.MaxTotalNodes {
		return nil, errors.New("maximum JSON nodes exceeded")
	}
	switch typed := token.(type) {
	case json.Delim:
		switch typed {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				if len(object) >= limits.MaxObjectProperties {
					return nil, errors.New("maximum JSON object size exceeded")
				}
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return nil, keyErr
				}
				key, keyOK := keyToken.(string)
				if !keyOK || len(key) > limits.MaxStringBytes {
					return nil, errors.New("invalid JSON object key")
				}
				if _, duplicate := object[key]; duplicate {
					return nil, errors.New("duplicate JSON object key")
				}
				value, valueErr := decodeBoundedJSON(decoder, depth+1, limits, nodes)
				if valueErr != nil {
					return nil, valueErr
				}
				object[key] = value
			}
			if end, endErr := decoder.Token(); endErr != nil || end != json.Delim('}') {
				return nil, errors.New("invalid JSON object")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				if len(array) >= limits.MaxArrayItems {
					return nil, errors.New("maximum JSON array size exceeded")
				}
				value, valueErr := decodeBoundedJSON(decoder, depth+1, limits, nodes)
				if valueErr != nil {
					return nil, valueErr
				}
				array = append(array, value)
			}
			if end, endErr := decoder.Token(); endErr != nil || end != json.Delim(']') {
				return nil, errors.New("invalid JSON array")
			}
			return array, nil
		default:
			return nil, errors.New("invalid JSON delimiter")
		}
	case string:
		if len(typed) > limits.MaxStringBytes {
			return nil, errors.New("maximum JSON string size exceeded")
		}
		return typed, nil
	case json.Number, bool, nil:
		return typed, nil
	default:
		return nil, errors.New("unsupported JSON value")
	}
}

func containsToken(value any, token string) bool {
	switch typed := value.(type) {
	case string:
		return strings.Contains(typed, token)
	case []any:
		for _, item := range typed {
			if containsToken(item, token) {
				return true
			}
		}
	case map[string]any:
		for key, item := range typed {
			if strings.Contains(key, token) || containsToken(item, token) {
				return true
			}
		}
	}
	return false
}

func ParseEnrichmentConfig(raw, prefix string) (EnrichmentConfig, error) {
	if strings.TrimSpace(raw) == "" {
		return EnrichmentConfig{}, nil
	}
	var config EnrichmentConfig
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return EnrichmentConfig{}, fmt.Errorf("parse %s: %w", prefix, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return EnrichmentConfig{}, fmt.Errorf("parse %s: trailing JSON value", prefix)
	}
	if err := config.Validate(prefix); err != nil {
		return EnrichmentConfig{}, err
	}
	return config, nil
}
