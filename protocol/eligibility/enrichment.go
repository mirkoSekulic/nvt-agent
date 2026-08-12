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
	hardMaxPaginationPages  = 10
	maxPaginationLinkBytes  = 16 * 1024
	maxPaginationURLBytes   = 8 * 1024
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
	Endpoint    string            `json:"endpoint"`
	OutputClaim string            `json:"outputClaim"`
	ValuePath   string            `json:"valuePath"`
	Pagination  *PaginationConfig `json:"pagination,omitempty"`
}

type PaginationConfig struct {
	Mode     string `json:"mode"`
	MaxPages int    `json:"maxPages"`
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
		if source.Pagination != nil {
			if source.Pagination.Mode != "link" || source.Pagination.MaxPages < 2 ||
				source.Pagination.MaxPages > hardMaxPaginationPages {
				return fmt.Errorf("%s.sources[%d].pagination must use link mode with maxPages between 2 and %d", prefix, index, hardMaxPaginationPages)
			}
			if source.ValuePath != "$" {
				return fmt.Errorf("%s.sources[%d].valuePath must be $ when pagination is configured", prefix, index)
			}
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
	if source.Pagination != nil {
		if source.Pagination.Mode != "link" || source.Pagination.MaxPages < 2 ||
			source.Pagination.MaxPages > hardMaxPaginationPages || source.ValuePath != "$" {
			return nil, errors.New("OAuth claim source pagination configuration is invalid")
		}
		return fetchPaginatedClaim(ctx, config, source, accessToken, options)
	}
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

func fetchPaginatedClaim(
	ctx context.Context,
	config EnrichmentConfig,
	source ClaimSource,
	accessToken string,
	options EnrichOptions,
) (any, error) {
	original, err := url.Parse(source.Endpoint)
	if err != nil {
		return nil, errors.New("build OAuth claim source request")
	}
	current := original
	visited := map[string]struct{}{current.String(): {}}
	combined := make([]any, 0)
	limits := config.effectiveLimits()
	remainingBytes := limits.MaxResponseBytes
	nodes := 0

	for page := 1; page <= source.Pagination.MaxPages; page++ {
		document, links, bytesRead, fetchErr := fetchPaginatedPage(
			ctx, current, accessToken, options, limits, remainingBytes, &nodes,
		)
		if fetchErr != nil {
			return nil, fetchErr
		}
		remainingBytes -= bytesRead
		items, ok := document.([]any)
		if !ok {
			return nil, errors.New("OAuth claim source paginated response must be an array")
		}
		if containsSensitiveData(items) || containsToken(items, accessToken) {
			return nil, errors.New("OAuth claim source value is invalid")
		}
		if len(items) > limits.MaxArrayItems-len(combined) {
			return nil, errors.New("OAuth claim source paginated response exceeds array limit")
		}
		combined = append(combined, items...)

		next, nextErr := nextLink(links, current, original)
		if nextErr != nil {
			return nil, errors.New("OAuth claim source pagination link is invalid")
		}
		if ctx.Err() != nil {
			return nil, errors.New("request OAuth claim source")
		}
		if next == nil {
			return combined, nil
		}
		if page == source.Pagination.MaxPages {
			return nil, errors.New("OAuth claim source pagination exceeds page limit")
		}
		canonical := next.String()
		if _, exists := visited[canonical]; exists {
			return nil, errors.New("OAuth claim source pagination loop")
		}
		visited[canonical] = struct{}{}
		current = next
	}
	return nil, errors.New("OAuth claim source pagination exceeds page limit")
}

func fetchPaginatedPage(
	ctx context.Context,
	endpoint *url.URL,
	accessToken string,
	options EnrichOptions,
	limits ResponseLimits,
	remainingBytes int64,
	nodes *int,
) (any, []string, int64, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, nil, 0, errors.New("build OAuth claim source request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+accessToken)
	if options.UserAgent != "" {
		request.Header.Set("User-Agent", options.UserAgent)
	}
	response, err := options.Client.Do(request)
	request.Header.Del("Authorization")
	if err != nil {
		return nil, nil, 0, errors.New("request OAuth claim source")
	}
	if response == nil || response.Body == nil {
		return nil, nil, 0, errors.New("read OAuth claim source response")
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, remainingBytes+1))
	closeErr := response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		clear(body)
		return nil, nil, 0, errors.New("OAuth claim source rejected request")
	}
	if response.Request != nil && response.Request.URL.String() != endpoint.String() {
		clear(body)
		return nil, nil, 0, errors.New("OAuth claim source redirected request")
	}
	if readErr != nil || closeErr != nil || int64(len(body)) > remainingBytes {
		clear(body)
		return nil, nil, 0, errors.New("read OAuth claim source response")
	}
	bytesRead := int64(len(body))
	defer clear(body)
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	document, err := decodeBoundedJSON(decoder, 1, limits, nodes)
	if err != nil {
		return nil, nil, 0, errors.New("decode OAuth claim source response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, nil, 0, errors.New("decode OAuth claim source response")
	}
	if ctx.Err() != nil {
		return nil, nil, 0, errors.New("request OAuth claim source")
	}
	return document, response.Header.Values("Link"), bytesRead, nil
}

func nextLink(headers []string, current, original *url.URL) (*url.URL, error) {
	if len(headers) == 0 {
		return nil, nil
	}
	var next *url.URL
	headerBytes := 0
	for _, header := range headers {
		if len(header) > maxPaginationLinkBytes-headerBytes {
			return nil, errors.New("link header exceeds limit")
		}
		headerBytes += len(header)
		values, err := splitLinkHeader(header)
		if err != nil {
			return nil, err
		}
		for _, value := range values {
			target, relations, parseErr := parseLinkValue(value)
			if parseErr != nil {
				return nil, parseErr
			}
			nextRelations := 0
			for _, relation := range relations {
				if strings.EqualFold(relation, "next") {
					nextRelations++
				}
			}
			if nextRelations == 0 {
				continue
			}
			if nextRelations != 1 || next != nil {
				return nil, errors.New("ambiguous next link")
			}
			if strings.Contains(target, "#") {
				return nil, errors.New("unsafe next link")
			}
			reference, err := url.Parse(target)
			if err != nil {
				return nil, err
			}
			candidate := current.ResolveReference(reference)
			if len(candidate.String()) > maxPaginationURLBytes || !safePaginationURL(candidate, original) {
				return nil, errors.New("unsafe next link")
			}
			next = candidate
		}
	}
	return next, nil
}

func safePaginationURL(candidate, original *url.URL) bool {
	return candidate != nil && candidate.Scheme == "https" && candidate.Opaque == "" &&
		candidate.User == nil && candidate.Fragment == "" &&
		strings.EqualFold(candidate.Hostname(), original.Hostname()) &&
		effectiveHTTPSPort(candidate) == effectiveHTTPSPort(original) &&
		candidate.EscapedPath() == original.EscapedPath()
}

func effectiveHTTPSPort(value *url.URL) string {
	if value.Port() != "" {
		return value.Port()
	}
	return "443"
}

func splitLinkHeader(header string) ([]string, error) {
	var values []string
	start, angleDepth := 0, 0
	quoted, escaped := false, false
	for index, character := range header {
		switch {
		case escaped:
			escaped = false
		case quoted && character == '\\':
			escaped = true
		case character == '"':
			quoted = !quoted
		case !quoted && character == '<':
			if angleDepth != 0 {
				return nil, errors.New("nested link target")
			}
			angleDepth = 1
		case !quoted && character == '>':
			if angleDepth != 1 {
				return nil, errors.New("unexpected link target end")
			}
			angleDepth = 0
		case !quoted && angleDepth == 0 && character == ',':
			value := strings.TrimSpace(header[start:index])
			if value == "" {
				return nil, errors.New("empty link value")
			}
			values = append(values, value)
			start = index + 1
		}
	}
	if quoted || escaped || angleDepth != 0 {
		return nil, errors.New("unterminated link value")
	}
	value := strings.TrimSpace(header[start:])
	if value == "" {
		return nil, errors.New("empty link value")
	}
	return append(values, value), nil
}

func parseLinkValue(value string) (string, []string, error) {
	if !strings.HasPrefix(value, "<") {
		return "", nil, errors.New("missing link target")
	}
	end := strings.IndexByte(value, '>')
	if end < 1 {
		return "", nil, errors.New("invalid link target")
	}
	target := value[1:end]
	remainder := strings.TrimSpace(value[end+1:])
	var relations []string
	relSeen := false
	for remainder != "" {
		if remainder[0] != ';' {
			return "", nil, errors.New("invalid link parameter")
		}
		remainder = strings.TrimSpace(remainder[1:])
		nameEnd := strings.IndexByte(remainder, '=')
		if nameEnd <= 0 {
			return "", nil, errors.New("invalid link parameter")
		}
		name := strings.TrimSpace(remainder[:nameEnd])
		if !validLinkToken(name) {
			return "", nil, errors.New("invalid link parameter name")
		}
		remainder = strings.TrimSpace(remainder[nameEnd+1:])
		parameter, rest, err := consumeLinkParameter(remainder)
		if err != nil {
			return "", nil, err
		}
		remainder = strings.TrimSpace(rest)
		if strings.EqualFold(name, "rel") {
			if relSeen {
				return "", nil, errors.New("duplicate rel parameter")
			}
			relSeen = true
			relations = strings.Fields(parameter)
			if len(relations) == 0 {
				return "", nil, errors.New("empty rel parameter")
			}
		}
	}
	return target, relations, nil
}

func consumeLinkParameter(value string) (string, string, error) {
	if value == "" {
		return "", "", errors.New("missing link parameter value")
	}
	if value[0] != '"' {
		end := strings.IndexByte(value, ';')
		if end < 0 {
			end = len(value)
		}
		parameter := strings.TrimSpace(value[:end])
		if !validLinkParameterToken(parameter) {
			return "", "", errors.New("invalid link parameter value")
		}
		return parameter, value[end:], nil
	}
	var result strings.Builder
	escaped := false
	for index := 1; index < len(value); index++ {
		character := value[index]
		if escaped {
			result.WriteByte(character)
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character == '"' {
			return result.String(), value[index+1:], nil
		}
		if character < 0x20 || character == 0x7f {
			return "", "", errors.New("invalid quoted link parameter")
		}
		result.WriteByte(character)
	}
	return "", "", errors.New("unterminated quoted link parameter")
}

func validLinkToken(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", character)) {
			return false
		}
	}
	return true
}

func validLinkParameterToken(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f || strings.ContainsRune("\",;\\", character) {
			return false
		}
	}
	return true
}

// sensitiveDataKey rejects secret-bearing or stable personal identifiers at
// every depth of a selected enrichment result. The two authorization-structure
// names are explicitly data, not credentials, and remain valid policy inputs.
func sensitiveDataKey(key string) bool {
	if isSensitivePath(key) {
		return true
	}
	compact := strings.NewReplacer(".", "", "[", "", "]", "", "-", "", "_", "").
		Replace(strings.ToLower(strings.ReplaceAll(key, "ø", "o")))
	if compact == "authorizationdetails" || compact == "authorizedparties" {
		return false
	}
	switch compact {
	case "pid", "ssn", "fodselsnummer", "foedselsnummer":
		return true
	}
	return strings.Contains(compact, "token") ||
		strings.Contains(compact, "secret") ||
		strings.Contains(compact, "password") ||
		strings.Contains(compact, "credential") ||
		strings.Contains(compact, "authorization")
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
