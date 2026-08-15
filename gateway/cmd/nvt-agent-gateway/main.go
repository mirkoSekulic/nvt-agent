package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mirkoSekulic/nvt-agent/gateway/internal/gateway"
	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func main() {
	var cfg gateway.Config
	var kubeconfig string
	var authorizationRaw string
	var admissionRaw string
	var claimEnrichmentRaw string
	var nativeSessionAuthenticationTimeoutSeconds int
	var nativeSessionRevalidationIntervalSeconds int
	var localRunTimeoutSeconds int
	flag.StringVar(&cfg.BaseDomain, "base-domain", envString("NVT_GATEWAY_BASE_DOMAIN", "agents.localhost"), "base DNS domain for AgentRun access")
	flag.StringVar(&cfg.PublicURL, "public-url", envString("NVT_GATEWAY_PUBLIC_URL", ""), "externally visible base URL for dashboard and OAuth callbacks")
	flag.StringVar(&cfg.Routing.Mode, "routing-mode", envString("NVT_GATEWAY_ROUTING_MODE", "subdomain"), "routing mode: subdomain or path")
	flag.StringVar(&cfg.ListenAddr, "listen-addr", envString("NVT_GATEWAY_LISTEN_ADDR", ":8080"), "HTTP listen address")
	flag.IntVar(&cfg.DefaultTargetPort, "default-target-port", envInt("NVT_GATEWAY_DEFAULT_TARGET_PORT", 4090), "default AgentRun code-server target port")
	flag.StringVar(&cfg.CredentialPortal.URL, "credential-portal-url", envString("NVT_GATEWAY_CREDENTIAL_PORTAL_URL", ""), "optional credential portal dashboard link")
	flag.StringVar(&cfg.CredentialPortal.Label, "credential-portal-label", envString("NVT_GATEWAY_CREDENTIAL_PORTAL_LABEL", "Manage credentials"), "credential portal dashboard link label")
	flag.StringVar(&cfg.BrandingDir, "branding-dir", envString("NVT_GATEWAY_BRANDING_DIR", ""), "optional directory containing the fixed NVT branding asset set")
	flag.BoolVar(&cfg.LocalRuns.Enabled, "local-runs-enabled", strictEnvBool("NVT_GATEWAY_LOCAL_RUNS_ENABLED", false), "enable the bounded local-controller route source")
	flag.StringVar(&cfg.LocalRuns.ControllerURL, "local-runs-controller-url", envString("NVT_GATEWAY_LOCAL_RUNS_CONTROLLER_URL", ""), "canonical local-controller origin")
	flag.StringVar(&cfg.LocalRuns.TokenFile, "local-runs-token-file", envString("NVT_GATEWAY_LOCAL_RUNS_TOKEN_FILE", ""), "private local-controller route bearer file")
	flag.StringVar(&cfg.LocalRuns.BaseDomain, "local-runs-base-domain", envString("NVT_GATEWAY_LOCAL_RUNS_BASE_DOMAIN", ""), "local run host-route base domain")
	flag.StringVar(&cfg.LocalRuns.PathPrefix, "local-runs-path-prefix", envString("NVT_GATEWAY_LOCAL_RUNS_PATH_PREFIX", ""), "local run path-route prefix")
	flag.BoolVar(&cfg.LocalRuns.DisableKubernetes, "local-runs-disable-kubernetes", strictEnvBool("NVT_GATEWAY_LOCAL_RUNS_DISABLE_KUBERNETES", false), "disable Kubernetes AgentRun discovery for a local-only gateway")
	flag.IntVar(&localRunTimeoutSeconds, "local-runs-timeout-seconds", strictEnvInt("NVT_GATEWAY_LOCAL_RUNS_TIMEOUT_SECONDS", 2), "complete local route lookup timeout")
	flag.StringVar(&cfg.Auth.Mode, "auth-mode", envString("NVT_GATEWAY_AUTH_MODE", "none"), "auth mode: none, oidc, or oauth2")
	flag.StringVar(&cfg.Auth.Session.Secret, "session-secret", envString("NVT_GATEWAY_SESSION_SECRET", ""), "session cookie secret")
	flag.StringVar(&cfg.Auth.Session.CookieName, "session-cookie-name", envString("NVT_GATEWAY_SESSION_COOKIE_NAME", ""), "session cookie name")
	flag.StringVar(&cfg.Auth.Session.CookieDomain, "session-cookie-domain", envString("NVT_GATEWAY_SESSION_COOKIE_DOMAIN", ""), "session cookie domain")
	flag.IntVar(&cfg.Auth.Session.MaxAgeSeconds, "session-max-age-seconds", envInt("NVT_GATEWAY_SESSION_MAX_AGE_SECONDS", 0), "session max age in seconds")
	flag.BoolVar(&cfg.Auth.Session.Secure, "session-secure", envBool("NVT_GATEWAY_SESSION_COOKIE_SECURE", true), "set Secure on session cookies")
	flag.StringVar(&cfg.Auth.OIDC.IssuerURL, "oidc-issuer-url", envString("NVT_GATEWAY_OIDC_ISSUER_URL", ""), "OIDC issuer URL")
	flag.StringVar(&cfg.Auth.OIDC.ClientID, "oidc-client-id", envString("NVT_GATEWAY_OIDC_CLIENT_ID", ""), "OIDC client ID")
	flag.StringVar(&cfg.Auth.OIDC.ClientSecret, "oidc-client-secret", envString("NVT_GATEWAY_OIDC_CLIENT_SECRET", ""), "OIDC client secret")
	flag.StringVar(&cfg.Auth.OIDC.CallbackPath, "oidc-callback-path", envString("NVT_GATEWAY_OIDC_CALLBACK_PATH", ""), "OIDC callback path")
	flag.StringVar(&cfg.Auth.OIDC.ACRValues, "oidc-acr-values", envString("NVT_GATEWAY_OIDC_ACR_VALUES", ""), "OIDC acr_values")
	flag.StringVar(&cfg.Auth.OIDC.ValidIssuer, "oidc-valid-issuer", envString("NVT_GATEWAY_OIDC_VALID_ISSUER", ""), "expected ID token issuer override")
	flag.StringVar(&cfg.Auth.OIDC.AuthorizationDetails, "oidc-authorization-details", envString("NVT_GATEWAY_OIDC_AUTHORIZATION_DETAILS", ""), "OIDC authorization_details JSON")
	flag.StringVar(&cfg.Auth.OIDC.ClientAuthMethod, "oidc-client-auth-method", envString("NVT_GATEWAY_OIDC_CLIENT_AUTH_METHOD", ""), "OIDC token endpoint client auth method")
	flag.StringVar(&cfg.Auth.OAuth2.ClientID, "oauth2-client-id", envString("NVT_GATEWAY_OAUTH2_CLIENT_ID", ""), "OAuth2 client ID")
	flag.StringVar(&cfg.Auth.OAuth2.ClientSecret, "oauth2-client-secret", envString("NVT_GATEWAY_OAUTH2_CLIENT_SECRET", ""), "OAuth2 client secret")
	flag.StringVar(&cfg.Auth.OAuth2.CallbackPath, "oauth2-callback-path", envString("NVT_GATEWAY_OAUTH2_CALLBACK_PATH", ""), "OAuth2 callback path")
	flag.StringVar(&cfg.Auth.OAuth2.Issuer, "oauth2-issuer", envString("NVT_GATEWAY_OAUTH2_ISSUER", ""), "operator-defined OAuth2 principal issuer namespace")
	flag.StringVar(&cfg.Auth.OAuth2.AuthorizationURL, "oauth2-authorization-url", envString("NVT_GATEWAY_OAUTH2_AUTHORIZATION_URL", ""), "OAuth2 authorization endpoint")
	flag.StringVar(&cfg.Auth.OAuth2.TokenURL, "oauth2-token-url", envString("NVT_GATEWAY_OAUTH2_TOKEN_URL", ""), "OAuth2 token endpoint")
	flag.StringVar(&cfg.Auth.OAuth2.ClientAuthMethod, "oauth2-client-auth-method", envString("NVT_GATEWAY_OAUTH2_CLIENT_AUTH_METHOD", ""), "OAuth2 token endpoint client auth method")
	flag.StringVar(&cfg.Auth.OAuth2.Identity.Endpoint, "oauth2-identity-endpoint", envString("NVT_GATEWAY_OAUTH2_IDENTITY_ENDPOINT", ""), "OAuth2 identity endpoint")
	flag.StringVar(&cfg.Auth.OAuth2.Identity.SubjectPath, "oauth2-identity-subject-path", envString("NVT_GATEWAY_OAUTH2_IDENTITY_SUBJECT_PATH", ""), "OAuth2 identity subject JSON path")
	flag.StringVar(&cfg.Auth.OAuth2.Identity.DisplayNamePath, "oauth2-identity-display-name-path", envString("NVT_GATEWAY_OAUTH2_IDENTITY_DISPLAY_NAME_PATH", ""), "OAuth2 identity display-name JSON path")
	flag.StringVar(&authorizationRaw, "authorization", envString("NVT_GATEWAY_AUTHORIZATION", ""), "gateway authorization policy JSON")
	flag.StringVar(&admissionRaw, "admission", envString("NVT_GATEWAY_ADMISSION", ""), "gateway login admission policy JSON")
	flag.StringVar(&claimEnrichmentRaw, "claim-enrichment", envString("NVT_GATEWAY_CLAIM_ENRICHMENT", ""), "gateway OAuth claim enrichment JSON")
	flag.BoolVar(&cfg.NativeSession.Enabled, "native-session-enabled", strictEnvBool("NVT_GATEWAY_NATIVE_SESSION_ENABLED", false), "enable the native guest session TLS listener")
	flag.StringVar(&cfg.NativeSession.ListenAddr, "native-session-listen-addr", envString("NVT_GATEWAY_NATIVE_SESSION_LISTEN_ADDR", ":7443"), "native guest session TLS listen address")
	flag.StringVar(&cfg.NativeSession.TLSCertificateFile, "native-session-tls-certificate-file", envString("NVT_GATEWAY_NATIVE_SESSION_TLS_CERTIFICATE_FILE", ""), "native guest session TLS certificate file")
	flag.StringVar(&cfg.NativeSession.TLSKeyFile, "native-session-tls-key-file", envString("NVT_GATEWAY_NATIVE_SESSION_TLS_KEY_FILE", ""), "native guest session TLS key file")
	flag.StringVar(&cfg.NativeSession.BrokerURL, "native-session-broker-url", envString("NVT_GATEWAY_NATIVE_SESSION_BROKER_URL", ""), "canonical HTTPS broker origin for native session authentication")
	flag.StringVar(&cfg.NativeSession.BrokerServerName, "native-session-broker-server-name", envString("NVT_GATEWAY_NATIVE_SESSION_BROKER_SERVER_NAME", ""), "exact broker TLS DNS server name")
	flag.StringVar(&cfg.NativeSession.BrokerCAFile, "native-session-broker-ca-file", envString("NVT_GATEWAY_NATIVE_SESSION_BROKER_CA_FILE", ""), "explicit broker CA file")
	flag.IntVar(&nativeSessionAuthenticationTimeoutSeconds, "native-session-authentication-timeout-seconds", strictEnvInt("NVT_GATEWAY_NATIVE_SESSION_AUTHENTICATION_TIMEOUT_SECONDS", 5), "native session broker authentication timeout")
	flag.IntVar(&nativeSessionRevalidationIntervalSeconds, "native-session-revalidation-interval-seconds", strictEnvInt("NVT_GATEWAY_NATIVE_SESSION_REVALIDATION_INTERVAL_SECONDS", 30), "maximum native session trust interval before broker reauthentication")
	flag.BoolVar(&cfg.NativeWorkspace.Enabled, "native-workspace-enabled", strictEnvBool("NVT_GATEWAY_NATIVE_WORKSPACE_ENABLED", false), "enable the native workspace TLS/yamux listener")
	flag.StringVar(&cfg.NativeWorkspace.ListenAddr, "native-workspace-listen-addr", envString("NVT_GATEWAY_NATIVE_WORKSPACE_LISTEN_ADDR", ":7444"), "native workspace TLS listen address")
	flag.StringVar(&kubeconfig, "kubeconfig", envString("KUBECONFIG", ""), "path to kubeconfig, optional")
	flag.Parse()
	cfg.NativeSession.AuthenticationTimeout = time.Duration(nativeSessionAuthenticationTimeoutSeconds) * time.Second
	cfg.NativeSession.RevalidationInterval = time.Duration(nativeSessionRevalidationIntervalSeconds) * time.Second
	cfg.LocalRuns.Timeout = time.Duration(localRunTimeoutSeconds) * time.Second

	cfg.Auth.OIDC.Scopes = gateway.SplitScopes(envString("NVT_GATEWAY_OIDC_SCOPES", ""))
	cfg.Auth.OAuth2.Scopes = gateway.SplitScopes(envString("NVT_GATEWAY_OAUTH2_SCOPES", ""))
	cfg.Auth.OAuth2.Identity.AllowedHosts = gateway.SplitScopes(envString("NVT_GATEWAY_OAUTH2_IDENTITY_ALLOWED_HOSTS", ""))
	extraAuthParams, err := gateway.ParseExtraAuthParams(envString("NVT_GATEWAY_OIDC_EXTRA_AUTH_PARAMS", ""))
	if err != nil {
		log.Fatalf("invalid config: %v", err)
	}
	cfg.Auth.OIDC.ExtraAuthParams = extraAuthParams
	authorization, err := gateway.ParseAuthorizationConfig(authorizationRaw)
	if err != nil {
		log.Fatalf("invalid config: %v", err)
	}
	cfg.Auth.Authorization = authorization
	admission, err := gateway.ParseAdmissionConfig(admissionRaw)
	if err != nil {
		log.Fatalf("invalid config: %v", err)
	}
	cfg.Auth.Admission = admission
	claimEnrichment, err := gateway.ParseClaimEnrichmentConfig(claimEnrichmentRaw)
	if err != nil {
		log.Fatalf("invalid config: %v", err)
	}
	cfg.Auth.ClaimEnrichment = claimEnrichment
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	var client ctrlclient.Client
	namespace := corev1.NamespaceDefault
	if !cfg.LocalRuns.DisableKubernetes {
		client, namespace, err = kubernetesClient(kubeconfig)
		if err != nil {
			log.Fatalf("create kubernetes client: %v", err)
		}
	}
	nativeSessionServer, err := gateway.NewNativeSessionServer(cfg.NativeSession)
	if err != nil {
		log.Fatalf("create native session listener: %v", err)
	}
	nativeWorkspaceServer, err := gateway.NewNativeWorkspaceServer(cfg.NativeWorkspace, cfg.NativeSession)
	if err != nil {
		log.Fatalf("create native workspace listener: %v", err)
	}
	var nativeWorkspaceResolver gateway.NativeWorkspaceResolver
	if nativeSessionServer != nil && nativeWorkspaceServer != nil {
		nativeWorkspaceResolver = gateway.NewNativeWorkspaceResolver(nativeSessionServer.Registry(), nativeWorkspaceServer.Registry())
	}
	server, err := gateway.NewServerWithNativeWorkspaceResolver(cfg, client, namespace, nativeWorkspaceResolver)
	if err != nil {
		log.Fatalf("create gateway server: %v", err)
	}
	if err := serve(cfg, namespace, server, nativeSessionServer, nativeWorkspaceServer); err != nil {
		log.Fatalf("serve gateway: %v", err)
	}
}

func serve(cfg gateway.Config, namespace string, handler http.Handler, nativeSessionServer *gateway.NativeSessionServer, nativeWorkspaceServer *gateway.NativeWorkspaceServer) error {
	lifetime, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	httpServer := &http.Server{Addr: cfg.ListenAddr, Handler: handler}
	errorCount := 1
	if nativeSessionServer != nil {
		errorCount++
	}
	if nativeWorkspaceServer != nil {
		errorCount++
	}
	errorsChannel := make(chan error, errorCount)
	go func() {
		log.Printf("nvt-agent-gateway listening on %s with routing mode %s in namespace %s", cfg.ListenAddr, cfg.Routing.Mode, namespace)
		errorsChannel <- httpServer.ListenAndServe()
	}()
	if nativeSessionServer != nil {
		go func() {
			log.Printf("nvt-agent-gateway native session listener enabled on %s", cfg.NativeSession.ListenAddr)
			errorsChannel <- nativeSessionServer.ListenAndServe()
		}()
	}
	if nativeWorkspaceServer != nil {
		go func() {
			log.Printf("nvt-agent-gateway native workspace listener enabled on %s", cfg.NativeWorkspace.ListenAddr)
			errorsChannel <- nativeWorkspaceServer.ListenAndServe()
		}()
	}
	var serveError error
	select {
	case <-lifetime.Done():
	case serveError = <-errorsChannel:
		if errors.Is(serveError, http.ErrServerClosed) {
			serveError = nil
		}
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	shutdownErrors := make(chan error, 3)
	shutdownCount := 1
	go func() { shutdownErrors <- httpServer.Shutdown(shutdownContext) }()
	if nativeSessionServer != nil {
		shutdownCount++
		go func() { shutdownErrors <- nativeSessionServer.Shutdown(shutdownContext) }()
	}
	if nativeWorkspaceServer != nil {
		shutdownCount++
		go func() { shutdownErrors <- nativeWorkspaceServer.Shutdown(shutdownContext) }()
	}
	for range shutdownCount {
		if err := <-shutdownErrors; err != nil && serveError == nil {
			serveError = errors.New("gateway shutdown failed")
		}
	}
	return serveError
}

func kubernetesClient(kubeconfig string) (ctrlclient.Client, string, error) {
	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil {
		return nil, "", fmt.Errorf("add kubernetes scheme: %w", err)
	}
	if err := nvtv1alpha1.AddToScheme(s); err != nil {
		return nil, "", fmt.Errorf("add nvt scheme: %w", err)
	}

	namespace := os.Getenv("POD_NAMESPACE")
	var restConfig *rest.Config
	var err error
	if kubeconfig != "" {
		restConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if namespace == "" {
			namespace = "default"
		}
	} else {
		restConfig, err = rest.InClusterConfig()
		if err == nil && namespace == "" {
			namespaceBytes, readErr := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
			if readErr == nil {
				namespace = strings.TrimSpace(string(namespaceBytes))
			}
		}
	}
	if err != nil {
		return nil, "", fmt.Errorf("load kubernetes config: %w", err)
	}
	if namespace == "" {
		namespace = corev1.NamespaceDefault
	}
	client, err := ctrlclient.New(restConfig, ctrlclient.Options{Scheme: s})
	if err != nil {
		return nil, "", err
	}
	return client, namespace, nil
}

func envString(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envBool(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func strictEnvInt(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		log.Fatalf("invalid config: %s must be an integer", name)
	}
	return parsed
}

func strictEnvBool(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		log.Fatalf("invalid config: %s must be a boolean", name)
	}
	return parsed
}
