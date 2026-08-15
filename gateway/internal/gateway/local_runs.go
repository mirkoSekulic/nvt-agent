package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/localroutes"
)

const localRouteRequestLimit = localroutes.MaxDocumentBytes

type LocalRunsConfig struct {
	Enabled           bool
	ControllerURL     string
	ProxyURL          string
	BaseDomain        string
	PathPrefix        string
	Timeout           time.Duration
	DisableKubernetes bool
}

type LocalRunSource interface {
	Get(context.Context, string) (localroutes.Run, error)
	List(context.Context) ([]localroutes.Run, error)
}

type httpLocalRunSource struct {
	base    *url.URL
	client  *http.Client
	timeout time.Duration
}

func (config *LocalRunsConfig) applyDefaults() {
	if config.BaseDomain == "" {
		config.BaseDomain = "agent.localhost"
	}
	if config.PathPrefix == "" {
		config.PathPrefix = "/agents"
	}
	if config.Timeout == 0 {
		config.Timeout = 2 * time.Second
	}
}

func (config LocalRunsConfig) validate() error {
	if !config.Enabled {
		if config.DisableKubernetes {
			return fmt.Errorf("localRuns.disableKubernetes requires localRuns.enabled")
		}
		return nil
	}
	config.applyDefaults()
	controller, controllerErr := canonicalLocalOrigin(config.ControllerURL)
	proxy, proxyErr := canonicalLocalOrigin(config.ProxyURL)
	if controllerErr != nil || proxyErr != nil || controller.String() == proxy.String() ||
		!validLocalBaseDomain(config.BaseDomain) || !validLocalPathPrefix(config.PathPrefix) ||
		config.Timeout < 100*time.Millisecond || config.Timeout > 10*time.Second {
		return fmt.Errorf("localRuns requires bounded controller/proxy origins, route names, and timeout")
	}
	return nil
}

func canonicalLocalOrigin(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid local origin")
	}
	parsed.Path = ""
	return parsed, nil
}

func validLocalBaseDomain(value string) bool {
	if len(value) == 0 || len(value) > 190 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !validLocalLabel(label) {
			return false
		}
	}
	return true
}

func validLocalPathPrefix(value string) bool {
	if len(value) < 2 || len(value) > 256 || value[0] != '/' || strings.HasSuffix(value, "/") || strings.Contains(value, "//") || strings.ContainsAny(value, "%\\?#\x00\r\n") {
		return false
	}
	for _, label := range strings.Split(strings.TrimPrefix(value, "/"), "/") {
		if !validLocalLabel(label) {
			return false
		}
	}
	return true
}

func validLocalLabel(value string) bool {
	if len(value) == 0 || len(value) > 63 || !localAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if value[index] != '-' && !localAlphaNumeric(value[index]) {
			return false
		}
	}
	return value[len(value)-1] != '-'
}

func localAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func newHTTPLocalRunSource(config LocalRunsConfig) (LocalRunSource, *url.URL, error) {
	config.applyDefaults()
	if err := config.validate(); err != nil {
		return nil, nil, err
	}
	base, _ := canonicalLocalOrigin(config.ControllerURL)
	proxy, _ := canonicalLocalOrigin(config.ProxyURL)
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: config.Timeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, ResponseHeaderTimeout: config.Timeout, DisableCompression: true,
	}
	client := &http.Client{
		Transport: transport, Timeout: config.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("local controller redirect denied") },
	}
	return &httpLocalRunSource{base: base, client: client, timeout: config.Timeout}, proxy, nil
}

func (source *httpLocalRunSource) Get(ctx context.Context, runID string) (localroutes.Run, error) {
	if !validLocalLabel(runID) {
		return localroutes.Run{}, errors.New("local route unavailable")
	}
	data, status, err := source.get(ctx, "/v1/routes/"+url.PathEscape(runID))
	if err != nil || status != http.StatusOK {
		return localroutes.Run{}, errors.New("local route unavailable")
	}
	defer clear(data)
	return localroutes.DecodeRun(data)
}

func (source *httpLocalRunSource) List(ctx context.Context) ([]localroutes.Run, error) {
	operationContext, cancel := context.WithTimeout(ctx, source.timeout)
	defer cancel()
	result := make([]localroutes.Run, 0, localroutes.MaxRunsPerPage)
	after := ""
	for page := 0; page < 64; page++ {
		path := "/v1/routes?limit=" + strconv.Itoa(localroutes.MaxRunsPerPage)
		if after != "" {
			path += "&after=" + url.QueryEscape(after)
		}
		data, status, err := source.get(operationContext, path)
		if err != nil || status != http.StatusOK {
			clear(data)
			return nil, errors.New("local routes unavailable")
		}
		decoded, decodeErr := localroutes.DecodeList(data)
		clear(data)
		if decodeErr != nil || len(result)+len(decoded.Runs) > localroutes.MaxRuns || decoded.NextAfter != "" && decoded.NextAfter <= after {
			return nil, errors.New("local routes unavailable")
		}
		for _, run := range decoded.Runs {
			if after != "" && run.RunID <= after || len(result) > 0 && run.RunID <= result[len(result)-1].RunID {
				return nil, errors.New("local routes unavailable")
			}
		}
		if decoded.NextAfter != "" && len(decoded.Runs) > 0 && decoded.NextAfter < decoded.Runs[len(decoded.Runs)-1].RunID {
			return nil, errors.New("local routes unavailable")
		}
		result = append(result, decoded.Runs...)
		if decoded.NextAfter == "" {
			return result, nil
		}
		after = decoded.NextAfter
	}
	return nil, errors.New("local routes unavailable")
}

func (source *httpLocalRunSource) get(ctx context.Context, path string) ([]byte, int, error) {
	target := *source.base
	target.Path = path
	if strings.Contains(path, "?") {
		parts := strings.SplitN(path, "?", 2)
		target.Path, target.RawQuery = parts[0], parts[1]
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := source.client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, localRouteRequestLimit+1))
	if err != nil || len(data) > localRouteRequestLimit {
		clear(data)
		return nil, response.StatusCode, errors.New("local route response unavailable")
	}
	return data, response.StatusCode, nil
}

func ParseLocalRoute(requestURL *url.URL, host string, config LocalRunsConfig) route {
	if !config.Enabled {
		return route{kind: routeNotFound}
	}
	config.applyDefaults()
	normalizedHost := strings.ToLower(strings.TrimSuffix(stripPort(host), "."))
	if normalizedHost == config.BaseDomain {
		return route{kind: routeNotFound}
	}
	suffix := "." + config.BaseDomain
	if strings.HasSuffix(normalizedHost, suffix) {
		labels := strings.Split(strings.TrimSuffix(normalizedHost, suffix), ".")
		switch {
		case len(labels) == 1 && validLocalLabel(labels[0]):
			return route{kind: routeLocalSession, accessKey: labels[0]}
		case len(labels) == 2 && validLocalLabel(labels[0]) && validLocalLabel(labels[1]):
			return route{kind: routeLocalExposure, accessKey: labels[1], exposure: labels[0]}
		default:
			return route{kind: routeNotFound}
		}
	}
	path, _, ok := pathBelowBase(requestURL, config.PathPrefix)
	if !ok {
		return route{kind: routeNotFound}
	}
	if path == "/" {
		return route{kind: routeDashboard}
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) < 1 || !validLocalLabel(segments[0]) {
		return route{kind: routeNotFound}
	}
	return route{kind: routeLocalSession, accessKey: segments[0], localPath: true}
}

func (s *Server) serveAuthorizedLocalRun(w http.ResponseWriter, r *http.Request, parsed route) {
	var principal *Principal
	if s.auth != nil {
		value, ok := s.authenticate(w, r)
		if !ok {
			return
		}
		principal = value
	}
	localRun, err := s.localRuns.Get(r.Context(), parsed.accessKey)
	if err != nil || !localRunMatchesConfig(localRun, s.config.LocalRuns) {
		http.NotFound(w, r)
		return
	}
	if principal != nil {
		decision := EvaluateAuthorizationForOwner(s.config.Auth.Authorization, *principal, localRun.Principal.Issuer, localRun.Principal.Subject)
		logAuthorizationDecision(decision, parsed.accessKey, *principal)
		if !decision.Allowed {
			http.NotFound(w, r)
			return
		}
	}
	if !localRun.Ready {
		http.Error(w, "local session unavailable", http.StatusServiceUnavailable)
		return
	}
	upstreamHost := localRun.Session.Host
	if parsed.kind == routeLocalExposure {
		upstreamHost = ""
		for _, exposure := range localRun.Exposures {
			if exposure.Name == parsed.exposure {
				upstreamHost = exposure.Host
				break
			}
		}
		if upstreamHost == "" {
			http.NotFound(w, r)
			return
		}
	}
	s.proxyLocalRun(w, r, localRun, parsed, upstreamHost)
}

func localRunMatchesConfig(run localroutes.Run, config LocalRunsConfig) bool {
	config.applyDefaults()
	if localroutes.ValidateRun(run) != nil || run.Session.Host != run.RunID+"."+config.BaseDomain ||
		run.Session.Path != config.PathPrefix+"/"+run.RunID+"/" {
		return false
	}
	for _, exposure := range run.Exposures {
		if exposure.Host != exposure.Name+"."+run.RunID+"."+config.BaseDomain {
			return false
		}
	}
	return true
}

func (s *Server) proxyLocalRun(w http.ResponseWriter, r *http.Request, localRun localroutes.Run, parsed route, upstreamHost string) {
	proxy := httputil.NewSingleHostReverseProxy(s.localProxyURL)
	proxy.Transport = s.localProxyTransport
	ownedCookies := gatewayCookieNames(s.config.Auth.Session.CookieName)
	responseCookiePath := ""
	if parsed.localPath {
		responseCookiePath = strings.TrimSuffix(localRun.Session.Path, "/")
	}
	originalDirector := proxy.Director
	proxy.Director = func(request *http.Request) {
		originalDirector(request)
		filterUpstreamRequestCookies(request.Header, ownedCookies)
		removeForwardingHeaders(request.Header)
		if parsed.localPath {
			prefix := strings.TrimSuffix(localRun.Session.Path, "/")
			request.URL.Path = strings.TrimPrefix(request.URL.Path, prefix)
			if request.URL.Path == "" {
				request.URL.Path = "/"
			}
			if request.URL.RawPath != "" {
				request.URL.RawPath = strings.TrimPrefix(request.URL.RawPath, prefix)
			}
			request.Header.Set("X-Forwarded-Prefix", prefix)
		}
		request.Header.Set("X-Forwarded-Host", r.Host)
		request.Header.Set("X-Forwarded-Proto", requestScheme(r))
		request.Header.Set("X-Forwarded-Port", requestForwardedPort(r))
		request.Host = upstreamHost
		request.URL.Scheme = s.localProxyURL.Scheme
		request.URL.Host = s.localProxyURL.Host
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		filterUpstreamResponseCookies(response, ownedCookies, responseCookiePath)
		return nil
	}
	proxy.ErrorHandler = func(response http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(response, "proxy local session", http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, r)
}

func requestScheme(request *http.Request) string {
	if request.TLS != nil {
		return "https"
	}
	return "http"
}

func requestForwardedPort(request *http.Request) string {
	if _, port, err := net.SplitHostPort(request.Host); err == nil {
		return port
	}
	if request.TLS != nil {
		return "443"
	}
	return "80"
}
