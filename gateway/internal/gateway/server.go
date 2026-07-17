package gateway

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	AccessKeyAnnotation   = "nvt.dev/access-key"
	DisplayNameAnnotation = "nvt.dev/display-name"
	SourceURLAnnotation   = "nvt.dev/source-url"
	RequestedByAnnotation = "nvt.dev/requested-by"
	AccessPortAnnotation  = "nvt.dev/access-port"

	AgentRunPodLabel  = "nvt.dev/agentrun"
	AgentRunRoleLabel = "nvt.dev/role"
	AgentRunRoleAgent = "agent"
)

type Config struct {
	BaseDomain        string
	PublicURL         string
	ListenAddr        string
	DefaultTargetPort int
	Routing           RoutingConfig
	Auth              AuthConfig
	basePathValue     string
	publicOriginValue string
	publicURLParsed   bool
}

type RoutingConfig struct {
	Mode string
}

type AuthConfig struct {
	Mode            string
	Session         SessionConfig
	OIDC            OIDCConfig
	OAuth2          OAuth2Config
	Admission       *AdmissionConfig
	ClaimEnrichment ClaimEnrichmentConfig
	Authorization   AuthorizationConfig
}

type SessionConfig struct {
	Secret        string
	CookieName    string
	CookieDomain  string
	MaxAgeSeconds int
	Secure        bool
}

type OIDCConfig struct {
	IssuerURL            string
	ClientID             string
	ClientSecret         string
	Scopes               []string
	CallbackPath         string
	ACRValues            string
	ValidIssuer          string
	ExtraAuthParams      map[string]string
	AuthorizationDetails string
	ClientAuthMethod     string
}

type OAuth2Config struct {
	ClientID         string
	ClientSecret     string
	CallbackPath     string
	Issuer           string
	AuthorizationURL string
	TokenURL         string
	Scopes           []string
	ClientAuthMethod string
	Identity         OAuth2IdentityConfig
}

type OAuth2IdentityConfig struct {
	Endpoint        string
	AllowedHosts    []string
	SubjectPath     string
	DisplayNamePath string
}

func (c Config) Validate() error {
	routingMode := c.routingMode()
	switch routingMode {
	case routingModeSubdomain:
		if strings.TrimSpace(c.BaseDomain) == "" {
			return fmt.Errorf("baseDomain is required when routing.mode=subdomain")
		}
		if strings.Contains(c.BaseDomain, "://") {
			return fmt.Errorf("baseDomain must be a host name, got %q", c.BaseDomain)
		}
	case routingModePath:
	default:
		return fmt.Errorf("routing.mode must be %q or %q", routingModeSubdomain, routingModePath)
	}
	if c.PublicURL != "" {
		_, basePath, err := publicURLParts(c.PublicURL)
		rawParsed, rawErr := url.Parse(c.PublicURL)
		if err != nil || rawErr != nil || (routingMode == routingModeSubdomain && (basePath != "" || rawParsed.Path != "")) {
			return fmt.Errorf("publicURL must be an absolute root URL without credentials, query, fragment, or non-canonical escaping when routing.mode=subdomain")
		}
	}
	if routingMode == routingModePath {
		parsed, _, err := publicURLParts(c.PublicURL)
		if err != nil || parsed.Scheme != "https" {
			return fmt.Errorf("publicURL must be an absolute HTTPS URL with a canonical optional base path when routing.mode=path")
		}
		if (c.Auth.Mode == authModeOIDC || c.Auth.Mode == authModeOAuth2) && !c.Auth.Session.Secure {
			return fmt.Errorf("auth.session.secure must be true when routing.mode=path")
		}
		if c.Auth.Session.CookieDomain != "" {
			return fmt.Errorf("auth.session.cookieDomain must be empty when routing.mode=path")
		}
		oidcCallbackPath := c.Auth.OIDC.CallbackPath
		if oidcCallbackPath == "" {
			oidcCallbackPath = defaultCallbackPath
		}
		oauth2CallbackPath := c.Auth.OAuth2.CallbackPath
		if oauth2CallbackPath == "" {
			oauth2CallbackPath = defaultCallbackPath
		}
		if !validOAuthCallbackPath(oidcCallbackPath) {
			return fmt.Errorf("auth.oidc.callbackPath must be an unambiguous path below /oauth2/ when routing.mode=path")
		}
		if !validOAuthCallbackPath(oauth2CallbackPath) {
			return fmt.Errorf("auth.oauth2.callbackPath must be an unambiguous path below /oauth2/ when routing.mode=path")
		}
	}
	if c.ListenAddr == "" {
		return fmt.Errorf("listenAddr is required")
	}
	if c.DefaultTargetPort <= 0 || c.DefaultTargetPort > 65535 {
		return fmt.Errorf("defaultTargetPort must be between 1 and 65535")
	}
	authMode := c.Auth.Mode
	if authMode == "" {
		authMode = authModeNone
	}
	switch authMode {
	case authModeNone:
		if c.Auth.Admission != nil || len(c.Auth.ClaimEnrichment.Sources) > 0 || len(c.Auth.ClaimEnrichment.AllowedHosts) > 0 {
			return fmt.Errorf("auth.admission and auth.claimEnrichment require authentication")
		}
	case authModeOIDC:
		if err := c.Auth.validateOIDC(); err != nil {
			return err
		}
	case authModeOAuth2:
		if err := c.Auth.validateOAuth2(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported auth.mode %q", c.Auth.Mode)
	}
	return nil
}

func (c Config) routingMode() string {
	if c.Routing.Mode == "" {
		return routingModeSubdomain
	}
	return c.Routing.Mode
}

func (c Config) basePath() string {
	if c.routingMode() != routingModePath {
		return ""
	}
	if c.publicURLParsed {
		return c.basePathValue
	}
	_, basePath, err := publicURLParts(c.PublicURL)
	if err != nil {
		return ""
	}
	return basePath
}

func (c Config) publicOrigin() string {
	if c.publicURLParsed {
		return c.publicOriginValue
	}
	parsed, _, err := publicURLParts(c.PublicURL)
	if err != nil {
		return ""
	}
	parsed.Path = ""
	return parsed.String()
}

func (c Config) mountedPath(relative string) string {
	return c.basePath() + relative
}

func (c Config) withParsedPublicURL() Config {
	if c.publicURLParsed || c.PublicURL == "" {
		return c
	}
	parsed, basePath, err := publicURLParts(c.PublicURL)
	if err != nil {
		return c
	}
	origin := *parsed
	origin.Path = ""
	c.PublicURL = parsed.String()
	c.basePathValue = basePath
	c.publicOriginValue = origin.String()
	c.publicURLParsed = true
	return c
}

func (c AuthConfig) validateCommonAuthenticated() error {
	if strings.TrimSpace(c.Session.Secret) == "" {
		return fmt.Errorf("auth.session.secret is required when authentication is enabled")
	}
	if _, err := sessionSecretBytes(c.Session.Secret); err != nil {
		return err
	}
	if err := c.Authorization.validate(); err != nil {
		return err
	}
	if c.Admission != nil {
		if err := c.Admission.validate(); err != nil {
			return err
		}
	}
	return c.ClaimEnrichment.validate()
}

func (c AuthConfig) validateOIDC() error {
	if err := c.validateCommonAuthenticated(); err != nil {
		return err
	}
	if strings.TrimSpace(c.OIDC.IssuerURL) == "" {
		return fmt.Errorf("auth.oidc.issuerURL is required when auth.mode=oidc")
	}
	if strings.TrimSpace(c.OIDC.ClientID) == "" {
		return fmt.Errorf("auth.oidc.clientID is required when auth.mode=oidc")
	}
	if strings.TrimSpace(c.OIDC.ClientSecret) == "" {
		return fmt.Errorf("auth.oidc.clientSecret is required when auth.mode=oidc")
	}
	if c.OIDC.ClientAuthMethod != "" && c.OIDC.ClientAuthMethod != oidcClientSecretPost {
		return fmt.Errorf("unsupported auth.oidc.clientAuthMethod %q", c.OIDC.ClientAuthMethod)
	}
	return nil
}

func (c AuthConfig) validateOAuth2() error {
	if err := c.validateCommonAuthenticated(); err != nil {
		return err
	}
	if strings.TrimSpace(c.OAuth2.ClientID) == "" {
		return fmt.Errorf("auth.oauth2.clientID is required when auth.mode=oauth2")
	}
	if strings.TrimSpace(c.OAuth2.ClientSecret) == "" {
		return fmt.Errorf("auth.oauth2.clientSecret is required when auth.mode=oauth2")
	}
	if len(c.OAuth2.Scopes) > 32 {
		return fmt.Errorf("auth.oauth2.scopes must contain at most 32 entries")
	}
	for index, scope := range c.OAuth2.Scopes {
		if scope == "" || len(scope) > 128 || strings.TrimSpace(scope) != scope || strings.ContainsAny(scope, "\x00\r\n\t ") {
			return fmt.Errorf("auth.oauth2.scopes[%d] must be a non-empty bounded OAuth2 scope", index)
		}
	}
	clientAuthMethod := c.OAuth2.ClientAuthMethod
	if clientAuthMethod == "" {
		clientAuthMethod = oauth2ClientSecretPost
	}
	if clientAuthMethod != oauth2ClientSecretPost && clientAuthMethod != oauth2ClientSecretBasic {
		return fmt.Errorf("auth.oauth2.clientAuthMethod must be %q or %q", oauth2ClientSecretPost, oauth2ClientSecretBasic)
	}
	callbackPath := c.OAuth2.CallbackPath
	if callbackPath == "" {
		callbackPath = defaultCallbackPath
	}
	if !strings.HasPrefix(callbackPath, "/") || strings.HasPrefix(callbackPath, "//") || strings.ContainsAny(callbackPath, "?#%\\") || path.Clean(callbackPath) != callbackPath {
		return fmt.Errorf("auth.oauth2.callbackPath must be an absolute unambiguous path without query or fragment")
	}
	if len(c.OAuth2.Identity.AllowedHosts) == 0 {
		return fmt.Errorf("auth.oauth2.identity.allowedHosts is required")
	}
	if len(c.OAuth2.Identity.AllowedHosts) > maxClaimSourceHosts {
		return fmt.Errorf("auth.oauth2.identity.allowedHosts must contain at most %d entries", maxClaimSourceHosts)
	}
	allowed := map[string]struct{}{}
	for index, host := range c.OAuth2.Identity.AllowedHosts {
		if !validClaimSourceHost(host) {
			return fmt.Errorf("auth.oauth2.identity.allowedHosts[%d] must be a normalized lowercase DNS hostname or IP address without a port", index)
		}
		if _, exists := allowed[host]; exists {
			return fmt.Errorf("auth.oauth2.identity.allowedHosts[%d] is duplicated", index)
		}
		allowed[host] = struct{}{}
	}
	for _, endpoint := range []struct {
		field string
		value string
	}{
		{field: "issuer", value: c.OAuth2.Issuer},
		{field: "authorizationURL", value: c.OAuth2.AuthorizationURL},
		{field: "tokenURL", value: c.OAuth2.TokenURL},
		{field: "identity.endpoint", value: c.OAuth2.Identity.Endpoint},
	} {
		field, value := endpoint.field, endpoint.value
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			return fmt.Errorf("auth.oauth2.%s must be an absolute HTTP(S) URL without credentials, query, or fragment", field)
		}
		if field == "issuer" && parsed.Scheme != "https" {
			return fmt.Errorf("auth.oauth2.issuer must use HTTPS")
		}
		if field != "issuer" && parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
			return fmt.Errorf("auth.oauth2.%s must use HTTPS except for loopback tests", field)
		}
		if field == "identity.endpoint" {
			if _, ok := allowed[strings.ToLower(parsed.Hostname())]; !ok {
				return fmt.Errorf("auth.oauth2.identity.endpoint host is not allowed")
			}
		}
	}
	for _, identityPath := range []struct {
		field string
		path  string
	}{
		{field: "subjectPath", path: c.OAuth2.Identity.SubjectPath},
		{field: "displayNamePath", path: c.OAuth2.Identity.DisplayNamePath},
	} {
		field, path := identityPath.field, identityPath.path
		if field == "displayNamePath" && path == "" {
			continue
		}
		if !claimPathPattern.MatchString(path) || isSensitiveEnrichmentPath(path) {
			return fmt.Errorf("auth.oauth2.identity.%s must be a safe non-sensitive JSON path", field)
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type Server struct {
	config    Config
	client    ctrlclient.Client
	namespace string
	auth      *Authenticator
}

type routeKind int

const (
	routeDashboard routeKind = iota
	routeAgentRun
	routeNotFound
)

type route struct {
	kind      routeKind
	accessKey string
}

func NewServer(config Config, client ctrlclient.Client, namespace string) (*Server, error) {
	if config.Routing.Mode == "" {
		config.Routing.Mode = routingModeSubdomain
	}
	if config.Auth.Mode == "" {
		config.Auth.Mode = authModeNone
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	config = config.withParsedPublicURL()
	auth, err := NewAuthenticator(context.Background(), config)
	if err != nil {
		return nil, err
	}
	return &Server{config: config, client: client, namespace: namespace, auth: auth}, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.config.routingMode() == routingModePath {
		if _, ok := unambiguousPath(r.URL); !ok {
			http.NotFound(w, r)
			return
		}
	}
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
		return
	}
	if s.config.routingMode() == routingModePath {
		mountedPath, mountedEscapedPath, ok := pathBelowBase(r.URL, s.config.basePath())
		if !ok || (strings.HasPrefix(mountedPath, "/oauth2/") && mountedEscapedPath != mountedPath) {
			http.NotFound(w, r)
			return
		}
	}
	if s.config.routingMode() == routingModePath && !requestMatchesPublicOrigin(r, s.config.PublicURL) {
		http.NotFound(w, r)
		return
	}
	if s.auth != nil && s.auth.HandlePublic(w, r) {
		return
	}

	route := s.parseRoute(r)
	switch route.kind {
	case routeDashboard:
		principal, ok := s.authenticate(w, r)
		if !ok {
			return
		}
		s.serveDashboard(w, r, principal)
	case routeAgentRun:
		if s.auth == nil {
			s.proxyAgentRun(w, r, route.accessKey)
		} else {
			s.serveAuthorizedAgentRun(w, r, route.accessKey)
		}
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) parseRoute(r *http.Request) route {
	if s.config.routingMode() == routingModePath {
		return ParsePathAtBase(r.URL, s.config.basePath())
	}
	return ParseHost(r.Host, s.config.BaseDomain)
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*Principal, bool) {
	if s.auth == nil {
		return nil, true
	}
	principal, ok := s.auth.Authenticate(w, r)
	return &principal, ok
}

func (s *Server) serveAuthorizedAgentRun(w http.ResponseWriter, r *http.Request, accessKey string) {
	principal, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	run, err := s.resolveAgentRun(r.Context(), accessKey)
	if errors.IsNotFound(err) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "resolve AgentRun", http.StatusInternalServerError)
		return
	}
	decision := EvaluateAuthorization(s.config.Auth.Authorization, *principal, &run)
	logAuthorizationDecision(decision, accessKey, *principal)
	if !decision.Allowed {
		http.NotFound(w, r)
		return
	}
	s.proxyResolvedAgentRun(w, r, run, accessKey)
}

func ParseHost(host, baseDomain string) route {
	host = strings.ToLower(strings.TrimSuffix(stripPort(host), "."))
	baseDomain = strings.ToLower(strings.TrimSuffix(baseDomain, "."))
	if host == baseDomain {
		return route{kind: routeDashboard}
	}
	suffix := "." + baseDomain
	if strings.HasSuffix(host, suffix) {
		key := strings.TrimSuffix(host, suffix)
		if key != "" && !strings.Contains(key, ".") {
			return route{kind: routeAgentRun, accessKey: key}
		}
	}
	return route{kind: routeNotFound}
}

func stripPort(host string) string {
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return parsedHost
	}
	return host
}

func (s *Server) proxyAgentRun(w http.ResponseWriter, r *http.Request, accessKey string) {
	run, err := s.resolveAgentRun(r.Context(), accessKey)
	if errors.IsNotFound(err) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "resolve AgentRun target", http.StatusInternalServerError)
		return
	}
	s.proxyResolvedAgentRun(w, r, run, accessKey)
}

func (s *Server) proxyResolvedAgentRun(w http.ResponseWriter, r *http.Request, run nvtv1alpha1.AgentRun, accessKey string) {
	target, err := s.resolveTargetForRun(r.Context(), run)
	if err == errNoRunningPod {
		http.Error(w, "AgentRun has no ready running pod with a pod IP", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		http.Error(w, "resolve AgentRun target", http.StatusInternalServerError)
		return
	}

	targetURL := &url.URL{Scheme: "http", Host: net.JoinHostPort(target.PodIP, strconv.Itoa(target.Port))}
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	ownedCookies := gatewayCookieNames(s.config.Auth.Session.CookieName)
	responseCookiePath := ""
	if s.config.routingMode() == routingModePath {
		responseCookiePath = pathCookiePrefix(s.config.basePath(), accessKey)
	}
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		filterUpstreamRequestCookies(req.Header, ownedCookies)
		removeForwardingHeaders(req.Header)
		if s.config.routingMode() == routingModePath {
			stripPathRoutePrefix(req.URL, s.config.basePath(), accessKey)
			publicOrigin, _ := url.Parse(s.config.PublicURL)
			req.Header.Set("X-Forwarded-Host", publicOrigin.Host)
			req.Header.Set("X-Forwarded-Proto", publicOrigin.Scheme)
			req.Header.Set("X-Forwarded-Port", publicForwardedPort(publicOrigin))
			req.Header.Set("X-Forwarded-Prefix", s.config.basePath()+"/"+url.PathEscape(accessKey))
		}
		req.Host = targetURL.Host
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		filterUpstreamResponseCookies(response, ownedCookies, responseCookiePath)
		return nil
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
		http.Error(rw, "proxy AgentRun session", http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, r)
}

var errNoRunningPod = fmt.Errorf("no running pod")

type target struct {
	AgentRun nvtv1alpha1.AgentRun
	PodIP    string
	Port     int
}

func (s *Server) resolveTarget(ctx context.Context, accessKey string) (target, error) {
	run, err := s.resolveAgentRun(ctx, accessKey)
	if err != nil {
		return target{}, err
	}
	return s.resolveTargetForRun(ctx, run)
}

func (s *Server) resolveTargetForRun(ctx context.Context, run nvtv1alpha1.AgentRun) (target, error) {
	pod, ok, err := s.runningPodForAgentRun(ctx, run.Name)
	if err != nil {
		return target{}, err
	}
	if !ok {
		return target{}, errNoRunningPod
	}
	return target{AgentRun: run, PodIP: pod.Status.PodIP, Port: targetPort(run, s.config.DefaultTargetPort)}, nil
}

func (s *Server) resolveAgentRun(ctx context.Context, accessKey string) (nvtv1alpha1.AgentRun, error) {
	var runs nvtv1alpha1.AgentRunList
	if err := s.client.List(ctx, &runs, ctrlclient.InNamespace(s.namespace)); err != nil {
		return nvtv1alpha1.AgentRun{}, fmt.Errorf("list AgentRuns: %w", err)
	}
	for _, run := range runs.Items {
		if run.Annotations[AccessKeyAnnotation] == accessKey {
			return run, nil
		}
	}
	return nvtv1alpha1.AgentRun{}, errors.NewNotFound(nvtv1alpha1.GroupVersion.WithResource("agentruns").GroupResource(), accessKey)
}

func (s *Server) runningPodForAgentRun(ctx context.Context, agentRunName string) (corev1.Pod, bool, error) {
	var pods corev1.PodList
	if err := s.client.List(ctx, &pods, ctrlclient.InNamespace(s.namespace), ctrlclient.MatchingLabels{
		AgentRunPodLabel:  agentRunName,
		AgentRunRoleLabel: AgentRunRoleAgent,
	}); err != nil {
		return corev1.Pod{}, false, fmt.Errorf("list AgentRun pods: %w", err)
	}
	sort.Slice(pods.Items, func(i, j int) bool {
		return pods.Items[i].CreationTimestamp.Before(&pods.Items[j].CreationTimestamp)
	})
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" && podReady(pod) {
			return pod, true, nil
		}
	}
	return corev1.Pod{}, false, nil
}

func podReady(pod corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func targetPort(run nvtv1alpha1.AgentRun, fallback int) int {
	raw := run.Annotations[AccessPortAnnotation]
	if raw == "" {
		return fallback
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port <= 0 || port > 65535 {
		return fallback
	}
	return port
}

func (s *Server) serveDashboard(w http.ResponseWriter, r *http.Request, principal *Principal) {
	var runs nvtv1alpha1.AgentRunList
	if err := s.client.List(r.Context(), &runs, ctrlclient.InNamespace(s.namespace)); err != nil {
		http.Error(w, "list AgentRuns", http.StatusInternalServerError)
		return
	}
	items := make([]dashboardItem, 0, len(runs.Items))
	for _, run := range runs.Items {
		key := run.Annotations[AccessKeyAnnotation]
		if key == "" {
			continue
		}
		if s.config.routingMode() == routingModePath && (!validAccessKey(key) || reservedGatewayPath(key)) {
			continue
		}
		if principal != nil && !EvaluateAuthorization(s.config.Auth.Authorization, *principal, &run).Allowed {
			continue
		}
		_, routable, err := s.runningPodForAgentRun(r.Context(), run.Name)
		if err != nil {
			http.Error(w, "list AgentRun pods", http.StatusInternalServerError)
			return
		}
		openURL := s.openURL(r, key, routable)
		if routable && openURL == "" {
			continue
		}
		items = append(items, dashboardItem{
			DisplayName: displayName(run),
			Phase:       string(run.Status.Phase),
			RequestedBy: run.Annotations[RequestedByAnnotation],
			CreatedAt:   run.CreationTimestamp.Time,
			SourceURL:   run.Annotations[SourceURLAnnotation],
			OpenURL:     openURL,
			Routable:    routable,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardTemplate.Execute(w, dashboardData{Items: items}); err != nil {
		http.Error(w, "render dashboard", http.StatusInternalServerError)
	}
}

type dashboardData struct {
	Items []dashboardItem
}

type dashboardItem struct {
	DisplayName string
	Phase       string
	RequestedBy string
	CreatedAt   time.Time
	SourceURL   string
	OpenURL     string
	Routable    bool
}

func displayName(run nvtv1alpha1.AgentRun) string {
	if value := run.Annotations[DisplayNameAnnotation]; value != "" {
		return value
	}
	return run.Name
}

func (s *Server) openURL(r *http.Request, key string, routable bool) string {
	if !routable {
		return ""
	}
	if s.config.routingMode() == routingModePath {
		if !validAccessKey(key) || reservedGatewayPath(key) {
			return ""
		}
		return s.config.PublicURL + "/" + url.PathEscape(key) + "/"
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	port := ""
	if _, rawPort, err := net.SplitHostPort(r.Host); err == nil {
		port = ":" + rawPort
	}
	return fmt.Sprintf("%s://%s.%s%s/", scheme, key, s.config.BaseDomain, port)
}

var dashboardTemplate = template.Must(template.New("dashboard").Funcs(template.FuncMap{
	"created": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Format(time.RFC3339)
	},
}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>nvt AgentRuns</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; color: #17202a; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border-bottom: 1px solid #d7dde5; padding: .65rem; text-align: left; vertical-align: top; }
    th { font-size: .85rem; color: #4d5b6a; }
    a { color: #0b66c3; }
    .empty { color: #687789; }
  </style>
</head>
<body>
  <h1>AgentRuns</h1>
  {{ if .Items }}
  <table>
    <thead>
      <tr><th>Name</th><th>Status</th><th>Requested by</th><th>Created</th><th>Source</th><th>Session</th></tr>
    </thead>
    <tbody>
    {{ range .Items }}
      <tr>
        <td>{{ .DisplayName }}</td>
        <td>{{ .Phase }}</td>
        <td>{{ .RequestedBy }}</td>
        <td>{{ created .CreatedAt }}</td>
        <td>{{ if .SourceURL }}<a href="{{ .SourceURL }}">Source</a>{{ end }}</td>
        <td>{{ if .Routable }}<a href="{{ .OpenURL }}">Open Session</a>{{ else }}<span class="empty">Not running</span>{{ end }}</td>
      </tr>
    {{ end }}
    </tbody>
  </table>
  {{ else }}
  <p class="empty">No AgentRuns with access metadata found.</p>
  {{ end }}
</body>
</html>`))
