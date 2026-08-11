package portal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/mirkoSekulic/nvt-agent/protocol/eligibility"
)

const (
	AdapterCodexOAuthFile  = "codex-oauth-file"
	AdapterClaudeOAuthFile = "claude-oauth-file"
	authModeOIDC           = "oidc"
	authModeOAuth2         = "oauth2"
	jsonContentType        = "application/json"
	httpsScheme            = "https"
	csrfHeader             = "X-Csrf-Token"
	confirmHeader          = "X-Nvt-Confirm"
	maxSlots               = 128
)

var (
	errInvalidConfig = errors.New("invalid credential portal configuration")
	dnsNamePattern   = regexp.MustCompile(
		`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)*$`,
	)
	dataKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	slotPattern    = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
)

type Config struct {
	Auth           AuthConfig `json:"auth"`
	PublicURL      string     `json:"publicURL"`
	ListenAddr     string     `json:"listenAddr"`
	Namespace      string     `json:"namespace"`
	basePath       string
	publicOrigin   string
	Slots          []Slot               `json:"slots"`
	Enrollment     EnrollmentConfig     `json:"enrollment"`
	MaxUploadBytes int64                `json:"maxUploadBytes"`
	RecoveryUpload RecoveryUploadConfig `json:"recoveryUpload"`
}

type EnrollmentConfig struct {
	MaxSessions                 int  `json:"maxSessions"`
	MaxConcurrent               int  `json:"maxConcurrent"`
	TimeoutSeconds              int  `json:"timeoutSeconds"`
	MaxOutputBytes              int  `json:"maxOutputBytes"`
	ExperimentalCodexDeviceAuth bool `json:"experimentalCodexDeviceAuth"`
}

type RecoveryUploadConfig struct {
	Enabled bool `json:"enabled"`
}

//nolint:govet // JSON contract fields stay grouped for reviewability.
type AuthConfig struct {
	OAuth2          OAuth2Config                 `json:"oauth2"`
	OIDC            OIDCConfig                   `json:"oidc"`
	Mode            string                       `json:"mode"`
	Session         SessionConfig                `json:"session"`
	Eligibility     *eligibility.Policy          `json:"eligibility"`
	ClaimEnrichment eligibility.EnrichmentConfig `json:"claimEnrichment"`
}

type SessionConfig struct {
	CookieName    string `json:"cookieName"`
	MaxAgeSeconds int    `json:"maxAgeSeconds"`
	Secure        bool   `json:"secure"`
}

type OIDCConfig struct {
	IssuerURL        string   `json:"issuerURL"`
	ClientID         string   `json:"clientID"`
	CallbackPath     string   `json:"callbackPath"`
	ClientAuthMethod string   `json:"clientAuthMethod"`
	Scopes           []string `json:"scopes"`
}

type OAuth2Config struct {
	Issuer           string   `json:"issuer"`
	AuthorizationURL string   `json:"authorizationURL"`
	TokenURL         string   `json:"tokenURL"`
	CallbackPath     string   `json:"callbackPath"`
	IdentityEndpoint string   `json:"identityEndpoint"`
	SubjectPath      string   `json:"subjectPath"`
	DisplayNamePath  string   `json:"displayNamePath"`
	ClientAuthMethod string   `json:"clientAuthMethod"`
	Scopes           []string `json:"scopes"`
	AllowedHosts     []string `json:"allowedHosts"`
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

//nolint:cyclop,funlen,gocognit,gocyclo,maintidx,nestif // Validation keeps policy in one fail-closed pass.
func (c *Config) Validate() error {
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme != httpsScheme || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: publicURL must be one absolute HTTPS URL", errInvalidConfig)
	}
	cleanPath := strings.TrimSuffix(u.EscapedPath(), "/")
	if cleanPath == "." || cleanPath == "/" {
		cleanPath = ""
	}
	if u.RawPath != "" ||
		path.Clean("/"+strings.TrimPrefix(cleanPath, "/")) != "/"+strings.TrimPrefix(cleanPath, "/") ||
		strings.Contains(cleanPath, "\\") {
		return fmt.Errorf("%w: publicURL path must be canonical", errInvalidConfig)
	}
	c.basePath = cleanPath
	c.publicOrigin = u.Scheme + "://" + u.Host
	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}
	if !dnsNamePattern.MatchString(c.Namespace) || len(c.Namespace) > 63 {
		return fmt.Errorf("%w: namespace must be a DNS label", errInvalidConfig)
	}
	if c.MaxUploadBytes < 1024 || c.MaxUploadBytes > 1024*1024 {
		return fmt.Errorf("%w: maxUploadBytes must be between 1024 and 1048576", errInvalidConfig)
	}
	if c.Enrollment.MaxSessions == 0 {
		c.Enrollment.MaxSessions = 64
	}
	if c.Enrollment.MaxConcurrent == 0 {
		c.Enrollment.MaxConcurrent = 2
	}
	if c.Enrollment.TimeoutSeconds == 0 {
		c.Enrollment.TimeoutSeconds = 600
	}
	if c.Enrollment.MaxOutputBytes == 0 {
		c.Enrollment.MaxOutputBytes = 64 * 1024
	}
	if c.Enrollment.MaxSessions < 1 || c.Enrollment.MaxSessions > 256 || c.Enrollment.MaxConcurrent < 1 ||
		c.Enrollment.MaxConcurrent > 8 ||
		c.Enrollment.MaxConcurrent > c.Enrollment.MaxSessions {
		return fmt.Errorf("%w: enrollment session limits are invalid", errInvalidConfig)
	}
	if c.Enrollment.TimeoutSeconds < 60 || c.Enrollment.TimeoutSeconds > 1800 ||
		c.Enrollment.TimeoutSeconds > c.Auth.Session.MaxAgeSeconds {
		return fmt.Errorf(
			"%w: enrollment timeout must be 60..1800 seconds and no longer than the portal session",
			errInvalidConfig,
		)
	}
	if c.Enrollment.MaxOutputBytes < 4096 || c.Enrollment.MaxOutputBytes > 1024*1024 {
		return fmt.Errorf("%w: enrollment maxOutputBytes must be between 4096 and 1048576", errInvalidConfig)
	}
	if c.Auth.Mode != authModeOIDC && c.Auth.Mode != authModeOAuth2 {
		return fmt.Errorf("%w: auth.mode must be oidc or oauth2", errInvalidConfig)
	}
	if c.Auth.Eligibility != nil {
		if err := c.Auth.Eligibility.Validate("auth.eligibility"); err != nil {
			return fmt.Errorf("%w: %w", errInvalidConfig, err)
		}
	}
	if err := c.Auth.ClaimEnrichment.Validate("auth.claimEnrichment"); err != nil {
		return fmt.Errorf("%w: %w", errInvalidConfig, err)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(c.Auth.Session.CookieName) {
		return fmt.Errorf("%w: auth.session.cookieName is invalid", errInvalidConfig)
	}
	if !c.Auth.Session.Secure || c.Auth.Session.MaxAgeSeconds < 300 || c.Auth.Session.MaxAgeSeconds > 86400 {
		return fmt.Errorf(
			"%w: auth.session must use a secure cookie with a 300..86400 second lifetime",
			errInvalidConfig,
		)
	}
	callback := c.Auth.OIDC.CallbackPath
	if c.Auth.Mode == authModeOAuth2 {
		callback = c.Auth.OAuth2.CallbackPath
	}
	if callback == "" || !strings.HasPrefix(callback, "/oauth2/") || path.Clean(callback) != callback ||
		strings.ContainsAny(callback, "%?#\\") {
		return fmt.Errorf("%w: authentication callbackPath must be an unambiguous /oauth2/ path", errInvalidConfig)
	}
	if c.Auth.Mode == authModeOIDC {
		if !absoluteHTTPS(c.Auth.OIDC.IssuerURL) || c.Auth.OIDC.ClientID == "" {
			return fmt.Errorf("%w: OIDC issuerURL and clientID are required", errInvalidConfig)
		}
	} else {
		if c.Auth.OAuth2.Issuer == "" || !absoluteHTTPS(c.Auth.OAuth2.AuthorizationURL) ||
			!absoluteHTTPS(c.Auth.OAuth2.TokenURL) ||
			!absoluteHTTPS(c.Auth.OAuth2.IdentityEndpoint) ||
			c.Auth.OAuth2.SubjectPath == "" {
			return fmt.Errorf("%w: OAuth2 issuer, endpoints, and subjectPath are required", errInvalidConfig)
		}
		identityURL, parseErr := url.Parse(c.Auth.OAuth2.IdentityEndpoint)
		if parseErr != nil {
			return fmt.Errorf("%w: parse OAuth2 identity endpoint", errInvalidConfig)
		}
		allowed := false
		for _, host := range c.Auth.OAuth2.AllowedHosts {
			if strings.EqualFold(host, identityURL.Hostname()) {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("%w: OAuth2 identity endpoint host must be explicitly allowed", errInvalidConfig)
		}
	}
	for _, method := range []string{c.Auth.OIDC.ClientAuthMethod, c.Auth.OAuth2.ClientAuthMethod} {
		if method != "" && method != "client_secret_basic" && method != "client_secret_post" {
			return fmt.Errorf(
				"%w: clientAuthMethod must be client_secret_basic or client_secret_post",
				errInvalidConfig,
			)
		}
	}
	if len(c.Slots) == 0 || len(c.Slots) > maxSlots {
		return fmt.Errorf("%w: slots must contain 1..%d entries", errInvalidConfig, maxSlots)
	}
	seen := map[string]bool{}
	seenDestinations := map[string]bool{}
	for i, slot := range c.Slots {
		if !slotPattern.MatchString(slot.Name) || len(slot.Name) > 63 || seen[slot.Name] {
			return fmt.Errorf("%w: slots[%d].name must be a unique DNS label", errInvalidConfig, i)
		}
		seen[slot.Name] = true
		if strings.TrimSpace(slot.Label) == "" || len(slot.Label) > 128 || strings.ContainsAny(slot.Label, "\r\n") ||
			slot.Owner.Issuer == "" ||
			slot.Owner.Subject == "" ||
			len(slot.Owner.Issuer) > 2048 ||
			len(slot.Owner.Subject) > 512 {
			return fmt.Errorf(
				"%w: slot %s requires a bounded label and exact owner issuer/subject",
				errInvalidConfig,
				slot.Name,
			)
		}
		if slot.Adapter != AdapterCodexOAuthFile && slot.Adapter != AdapterClaudeOAuthFile {
			return fmt.Errorf("%w: slot %s adapter is unsupported", errInvalidConfig, slot.Name)
		}
		if slot.Adapter == AdapterCodexOAuthFile && !c.Enrollment.ExperimentalCodexDeviceAuth {
			return fmt.Errorf(
				"%w: slot %s requires explicit experimental Codex device authorization opt-in",
				errInvalidConfig,
				slot.Name,
			)
		}
		if strings.TrimSpace(slot.BrokerProvider) == "" || len(slot.BrokerProvider) > 128 ||
			strings.ContainsAny(slot.BrokerProvider, "\r\n") {
			return fmt.Errorf("%w: slot %s brokerProvider is required", errInvalidConfig, slot.Name)
		}
		if !dnsNamePattern.MatchString(slot.SecretName) || len(slot.SecretName) > 253 ||
			!dataKeyPattern.MatchString(slot.DataKey) ||
			len(slot.DataKey) > 253 {
			return fmt.Errorf("%w: slot %s Secret destination is invalid", errInvalidConfig, slot.Name)
		}
		destination := slot.SecretName + "\x00" + slot.DataKey
		if seenDestinations[destination] {
			return fmt.Errorf(
				"%w: slot %s Secret destination is already assigned to another slot",
				errInvalidConfig,
				slot.Name,
			)
		}
		seenDestinations[destination] = true
	}
	return nil
}

func DecodeConfig(reader io.Reader) (Config, error) {
	body, err := io.ReadAll(io.LimitReader(reader, 1024*1024+1))
	if err != nil || len(body) > 1024*1024 || !json.Valid(body) || rejectDuplicateJSONKeys(body) != nil {
		return Config{}, fmt.Errorf(
			"%w: configuration must be one bounded duplicate-free JSON object",
			errInvalidConfig,
		)
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
	return err == nil && u.Scheme == httpsScheme && u.Host != "" && u.User == nil && u.RawQuery == "" &&
		u.Fragment == ""
}

func (c *Config) Path(suffix string) string { return c.basePath + suffix }
func (c *Config) PublicOrigin() string      { return c.publicOrigin }
