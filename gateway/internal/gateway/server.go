package gateway

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
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

	AgentRunPodLabel = "nvt.dev/agentrun"
)

type Config struct {
	BaseDomain        string
	ListenAddr        string
	DefaultTargetPort int
	Auth              AuthConfig
}

type AuthConfig struct {
	Mode string
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.BaseDomain) == "" {
		return fmt.Errorf("baseDomain is required")
	}
	if strings.Contains(c.BaseDomain, "://") {
		return fmt.Errorf("baseDomain must be a host name, got %q", c.BaseDomain)
	}
	if c.ListenAddr == "" {
		return fmt.Errorf("listenAddr is required")
	}
	if c.DefaultTargetPort <= 0 || c.DefaultTargetPort > 65535 {
		return fmt.Errorf("defaultTargetPort must be between 1 and 65535")
	}
	if c.Auth.Mode == "" {
		c.Auth.Mode = "none"
	}
	if c.Auth.Mode != "none" {
		return fmt.Errorf("unsupported auth.mode %q", c.Auth.Mode)
	}
	return nil
}

type Server struct {
	config    Config
	client    ctrlclient.Client
	namespace string
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

func NewServer(config Config, client ctrlclient.Client, namespace string) *Server {
	if config.Auth.Mode == "" {
		config.Auth.Mode = "none"
	}
	return &Server{config: config, client: client, namespace: namespace}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
		return
	}

	route := ParseHost(r.Host, s.config.BaseDomain)
	switch route.kind {
	case routeDashboard:
		s.serveDashboard(w, r)
	case routeAgentRun:
		s.proxyAgentRun(w, r, route.accessKey)
	default:
		http.NotFound(w, r)
	}
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
	target, err := s.resolveTarget(r.Context(), accessKey)
	if errors.IsNotFound(err) {
		http.NotFound(w, r)
		return
	}
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
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = targetURL.Host
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
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
	if err := s.client.List(ctx, &pods, ctrlclient.InNamespace(s.namespace), ctrlclient.MatchingLabels{AgentRunPodLabel: agentRunName}); err != nil {
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

func (s *Server) serveDashboard(w http.ResponseWriter, r *http.Request) {
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
		_, routable, err := s.runningPodForAgentRun(r.Context(), run.Name)
		if err != nil {
			http.Error(w, "list AgentRun pods", http.StatusInternalServerError)
			return
		}
		items = append(items, dashboardItem{
			DisplayName: displayName(run),
			Phase:       string(run.Status.Phase),
			RequestedBy: run.Annotations[RequestedByAnnotation],
			CreatedAt:   run.CreationTimestamp.Time,
			SourceURL:   run.Annotations[SourceURLAnnotation],
			OpenURL:     openURL(r, key, s.config.BaseDomain, routable),
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

func openURL(r *http.Request, key, baseDomain string, routable bool) string {
	if !routable {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	port := ""
	if _, rawPort, err := net.SplitHostPort(r.Host); err == nil {
		port = ":" + rawPort
	}
	return fmt.Sprintf("%s://%s.%s%s/", scheme, key, baseDomain, port)
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
