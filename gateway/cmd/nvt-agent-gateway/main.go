package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

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
	flag.StringVar(&cfg.BaseDomain, "base-domain", envString("NVT_GATEWAY_BASE_DOMAIN", "agents.localhost"), "base DNS domain for AgentRun access")
	flag.StringVar(&cfg.PublicURL, "public-url", envString("NVT_GATEWAY_PUBLIC_URL", ""), "externally visible base URL for dashboard and OAuth callbacks")
	flag.StringVar(&cfg.Routing.Mode, "routing-mode", envString("NVT_GATEWAY_ROUTING_MODE", "subdomain"), "routing mode: subdomain or path")
	flag.StringVar(&cfg.ListenAddr, "listen-addr", envString("NVT_GATEWAY_LISTEN_ADDR", ":8080"), "HTTP listen address")
	flag.IntVar(&cfg.DefaultTargetPort, "default-target-port", envInt("NVT_GATEWAY_DEFAULT_TARGET_PORT", 4090), "default AgentRun code-server target port")
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
	flag.StringVar(&kubeconfig, "kubeconfig", envString("KUBECONFIG", ""), "path to kubeconfig, optional")
	flag.Parse()

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

	client, namespace, err := kubernetesClient(kubeconfig)
	if err != nil {
		log.Fatalf("create kubernetes client: %v", err)
	}
	server, err := gateway.NewServer(cfg, client, namespace)
	if err != nil {
		log.Fatalf("create gateway server: %v", err)
	}
	log.Printf("nvt-agent-gateway listening on %s with routing mode %s in namespace %s", cfg.ListenAddr, cfg.Routing.Mode, namespace)
	if err := http.ListenAndServe(cfg.ListenAddr, server); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve gateway: %v", err)
	}
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
