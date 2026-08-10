package portal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"
)

const (
	AdapterCodexOAuthFile  = "codex-oauth-file"
	AdapterClaudeOAuthFile = "claude-oauth-file"
	maxSlots               = 128
)

var (
	dnsNamePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)*$`)
	dataKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	slotPattern    = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
)

type Config struct {
	PublicURL      string     `json:"publicURL"`
	ListenAddr     string     `json:"listenAddr"`
	Namespace      string     `json:"namespace"`
	MaxUploadBytes int64      `json:"maxUploadBytes"`
	Auth           AuthConfig `json:"auth"`
	Slots          []Slot     `json:"slots"`
	basePath       string
	publicOrigin   string
}

type AuthConfig struct {
	Mode    string        `json:"mode"`
	Session SessionConfig `json:"session"`
	OIDC    OIDCConfig    `json:"oidc"`
	OAuth2  OAuth2Config  `json:"oauth2"`
}

type SessionConfig struct {
	CookieName    string `json:"cookieName"`
	MaxAgeSeconds int    `json:"maxAgeSeconds"`
	Secure        bool   `json:"secure"`
}

type OIDCConfig struct {
	IssuerURL        string   `json:"issuerURL"`
	ClientID         string   `json:"clientID"`
	Scopes           []string `json:"scopes"`
	CallbackPath     string   `json:"callbackPath"`
	ClientAuthMethod string   `json:"clientAuthMethod"`
}

type OAuth2Config struct {
	Issuer           string   `json:"issuer"`
	AuthorizationURL string   `json:"authorizationURL"`
	TokenURL         string   `json:"tokenURL"`
	Scopes           []string `json:"scopes"`
	CallbackPath     string   `json:"callbackPath"`
	IdentityEndpoint string   `json:"identityEndpoint"`
	AllowedHosts     []string `json:"allowedHosts"`
	SubjectPath      string   `json:"subjectPath"`
	DisplayNamePath  string   `json:"displayNamePath"`
	ClientAuthMethod string   `json:"clientAuthMethod"`
}

type Slot struct {
	Name           string    `json:"name"`
	Label          string    `json:"label"`
	Owner          Principal `json:"owner"`
	Adapter        string    `json:"adapter"`
	BrokerProvider string    `json:"brokerProvider"`
	SecretName     string    `json:"secretName"`
	DataKey        string    `json:"dataKey"`
}

type Principal struct {
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	DisplayName string `json:"displayName,omitempty"`
}

func (p Principal) Owns(slot Slot) bool {
	return p.Issuer == slot.Owner.Issuer && p.Subject == slot.Owner.Subject
}

func (c *Config) Validate() error {
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("publicURL must be one absolute HTTPS URL")
	}
	cleanPath := strings.TrimSuffix(u.EscapedPath(), "/")
	if cleanPath == "." || cleanPath == "/" {
		cleanPath = ""
	}
	if u.RawPath != "" || path.Clean("/"+strings.TrimPrefix(cleanPath, "/")) != "/"+strings.TrimPrefix(cleanPath, "/") || strings.Contains(cleanPath, "\\") {
		return fmt.Errorf("publicURL path must be canonical")
	}
	c.basePath = cleanPath
	c.publicOrigin = u.Scheme + "://" + u.Host
	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}
	if !dnsNamePattern.MatchString(c.Namespace) || len(c.Namespace) > 63 {
		return fmt.Errorf("namespace must be a DNS label")
	}
	if c.MaxUploadBytes < 1024 || c.MaxUploadBytes > 1024*1024 {
		return fmt.Errorf("maxUploadBytes must be between 1024 and 1048576")
	}
	if c.Auth.Mode != "oidc" && c.Auth.Mode != "oauth2" {
		return fmt.Errorf("auth.mode must be oidc or oauth2")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(c.Auth.Session.CookieName) {
		return fmt.Errorf("auth.session.cookieName is invalid")
	}
	if !c.Auth.Session.Secure || c.Auth.Session.MaxAgeSeconds < 300 || c.Auth.Session.MaxAgeSeconds > 86400 {
		return fmt.Errorf("auth.session must use a secure cookie with a 300..86400 second lifetime")
	}
	callback := c.Auth.OIDC.CallbackPath
	if c.Auth.Mode == "oauth2" {
		callback = c.Auth.OAuth2.CallbackPath
	}
	if callback == "" || !strings.HasPrefix(callback, "/oauth2/") || path.Clean(callback) != callback || strings.ContainsAny(callback, "%?#\\") {
		return fmt.Errorf("authentication callbackPath must be an unambiguous /oauth2/ path")
	}
	if c.Auth.Mode == "oidc" {
		if !absoluteHTTPS(c.Auth.OIDC.IssuerURL) || c.Auth.OIDC.ClientID == "" {
			return fmt.Errorf("OIDC issuerURL and clientID are required")
		}
	} else {
		if c.Auth.OAuth2.Issuer == "" || !absoluteHTTPS(c.Auth.OAuth2.AuthorizationURL) || !absoluteHTTPS(c.Auth.OAuth2.TokenURL) || !absoluteHTTPS(c.Auth.OAuth2.IdentityEndpoint) || c.Auth.OAuth2.SubjectPath == "" {
			return fmt.Errorf("OAuth2 issuer, endpoints, and subjectPath are required")
		}
		identityURL, _ := url.Parse(c.Auth.OAuth2.IdentityEndpoint)
		allowed := false
		for _, host := range c.Auth.OAuth2.AllowedHosts {
			if strings.EqualFold(host, identityURL.Hostname()) {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("OAuth2 identity endpoint host must be explicitly allowed")
		}
	}
	for _, method := range []string{c.Auth.OIDC.ClientAuthMethod, c.Auth.OAuth2.ClientAuthMethod} {
		if method != "" && method != "client_secret_basic" && method != "client_secret_post" {
			return fmt.Errorf("clientAuthMethod must be client_secret_basic or client_secret_post")
		}
	}
	if len(c.Slots) == 0 || len(c.Slots) > maxSlots {
		return fmt.Errorf("slots must contain 1..%d entries", maxSlots)
	}
	seen := map[string]bool{}
	for i, slot := range c.Slots {
		if !slotPattern.MatchString(slot.Name) || len(slot.Name) > 63 || seen[slot.Name] {
			return fmt.Errorf("slots[%d].name must be a unique DNS label", i)
		}
		seen[slot.Name] = true
		if strings.TrimSpace(slot.Label) == "" || len(slot.Label) > 128 || strings.ContainsAny(slot.Label, "\r\n") || slot.Owner.Issuer == "" || slot.Owner.Subject == "" || len(slot.Owner.Issuer) > 2048 || len(slot.Owner.Subject) > 512 {
			return fmt.Errorf("slot %s requires a bounded label and exact owner issuer/subject", slot.Name)
		}
		if slot.Adapter != AdapterCodexOAuthFile && slot.Adapter != AdapterClaudeOAuthFile {
			return fmt.Errorf("slot %s adapter is unsupported", slot.Name)
		}
		if strings.TrimSpace(slot.BrokerProvider) == "" || len(slot.BrokerProvider) > 128 || strings.ContainsAny(slot.BrokerProvider, "\r\n") {
			return fmt.Errorf("slot %s brokerProvider is required", slot.Name)
		}
		if !dnsNamePattern.MatchString(slot.SecretName) || len(slot.SecretName) > 253 || !dataKeyPattern.MatchString(slot.DataKey) || len(slot.DataKey) > 253 {
			return fmt.Errorf("slot %s Secret destination is invalid", slot.Name)
		}
	}
	return nil
}

func DecodeConfig(reader io.Reader) (Config, error) {
	body, err := io.ReadAll(io.LimitReader(reader, 1024*1024+1))
	if err != nil || len(body) > 1024*1024 || !json.Valid(body) || rejectDuplicateJSONKeys(body) != nil {
		return Config{}, fmt.Errorf("configuration must be one bounded duplicate-free JSON object")
	}
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func absoluteHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

func (c Config) Path(suffix string) string { return c.basePath + suffix }
func (c Config) PublicOrigin() string      { return c.publicOrigin }
