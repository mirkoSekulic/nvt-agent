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
	authModeLocal          = "local"
	jsonContentType        = "application/json"
	httpsScheme            = "https"
	csrfHeader             = "X-Csrf-Token"
	confirmHeader          = "X-Nvt-Confirm"
	confirmationReplace    = "replace"
	accountStateRevoked    = "revoked"
	reasonAccountNotFound  = "account-not-found"
	maxSlots               = 128
	maxDynamicTemplates    = 64
	defaultBrokerTimeout   = 10
	defaultAssertionTTL    = 60
	defaultBrokerResponse  = 64 * 1024
	maxBrokerCredential    = 768 * 1024
)

var (
	errInvalidConfig = errors.New("invalid credential portal configuration")
	dnsNamePattern   = regexp.MustCompile(
		`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)*$`,
	)
	dataKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	slotPattern    = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
)

const httpScheme = "http"

//nolint:govet // JSON contract fields stay grouped for reviewability.
type Config struct {
	Auth           AuthConfig `json:"auth"`
	PublicURL      string     `json:"publicURL"`
	ReturnURL      string     `json:"returnURL"`
	ListenAddr     string     `json:"listenAddr"`
	Namespace      string     `json:"namespace"`
	basePath       string
	publicOrigin   string
	Slots          []Slot               `json:"slots"`
	Enrollment     EnrollmentConfig     `json:"enrollment"`
	MaxUploadBytes int64                `json:"maxUploadBytes"`
	RecoveryUpload RecoveryUploadConfig `json:"recoveryUpload"`
	Dynamic        DynamicConfig        `json:"dynamic"`
	Persistence    PersistenceConfig    `json:"persistence"`
}

type PersistenceConfig struct {
	Mode  string                 `json:"mode"`
	Local LocalPersistenceConfig `json:"local"`
}

type LocalPersistenceConfig struct {
	Directory string `json:"directory"`
}

//nolint:govet // JSON contract fields stay grouped for reviewability.
type DynamicConfig struct {
	Enabled        bool                        `json:"enabled"`
	Broker         DynamicBrokerConfig         `json:"broker"`
	TemplateSwitch TemplateSwitchConfig        `json:"templateSwitch"`
	Templates      []DynamicCredentialTemplate `json:"templates"`
}

type TemplateSwitchConfig struct {
	CoordinatorURL        string `json:"coordinatorURL"`
	RequestTimeoutSeconds int    `json:"requestTimeoutSeconds"`
	MaxResponseBytes      int    `json:"maxResponseBytes"`
	Enabled               bool   `json:"enabled"`
}

type DynamicBrokerConfig struct {
	URL                     string `json:"url"`
	CAFile                  string `json:"caFile"`
	AssertionKeyFile        string `json:"assertionKeyFile"`
	AssertionTTLSeconds     int    `json:"assertionTTLSeconds"`
	EligibilityLeaseSeconds int    `json:"eligibilityLeaseSeconds"`
	RequestTimeoutSeconds   int    `json:"requestTimeoutSeconds"`
	MaxResponseBytes        int    `json:"maxResponseBytes"`
}

type DynamicCredentialTemplate struct {
	Name    string `json:"name"`
	Label   string `json:"label"`
	Adapter string `json:"adapter"`
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
	Local           LocalAuthConfig              `json:"local"`
}

type LocalAuthConfig struct {
	Principal Principal `json:"principal"`
}

type SessionConfig struct {
	CookieName    string `json:"cookieName"`
	MaxAgeSeconds int    `json:"maxAgeSeconds"`
	Secure        bool   `json:"secure"`
}

//nolint:govet // JSON contract fields stay grouped for reviewability.
type OIDCConfig struct {
	IssuerURL              string   `json:"issuerURL"`
	ClientID               string   `json:"clientID"`
	CallbackPath           string   `json:"callbackPath"`
	ClientAuthMethod       string   `json:"clientAuthMethod"`
	Scopes                 []string `json:"scopes"`
	EligibilityClaimSource string   `json:"eligibilityClaimSource"`
	AccessTokenAudience    string   `json:"accessTokenAudience"`
}

type OAuth2Config struct {
	Issuer                      string   `json:"issuer"`
	AuthorizationResponseIssuer string   `json:"authorizationResponseIssuer"`
	AuthorizationURL            string   `json:"authorizationURL"`
	TokenURL                    string   `json:"tokenURL"`
	CallbackPath                string   `json:"callbackPath"`
	IdentityEndpoint            string   `json:"identityEndpoint"`
	SubjectPath                 string   `json:"subjectPath"`
	DisplayNamePath             string   `json:"displayNamePath"`
	ClientAuthMethod            string   `json:"clientAuthMethod"`
	Scopes                      []string `json:"scopes"`
	AllowedHosts                []string `json:"allowedHosts"`
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
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: publicURL must be one absolute URL", errInvalidConfig)
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
	if c.ReturnURL != "" && (!strings.HasPrefix(c.ReturnURL, "/") || path.Clean(c.ReturnURL) != c.ReturnURL ||
		strings.ContainsAny(c.ReturnURL, "%?#\\")) {
		return fmt.Errorf("%w: returnURL must be one canonical root-relative path", errInvalidConfig)
	}
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
	if c.Auth.Mode != authModeOIDC && c.Auth.Mode != authModeOAuth2 && c.Auth.Mode != authModeLocal {
		return fmt.Errorf("%w: auth.mode must be oidc, oauth2, or local", errInvalidConfig)
	}
	if c.Auth.Mode == authModeLocal {
		if u.Scheme != httpScheme || !strings.EqualFold(u.Hostname(), "localhost") ||
			c.Auth.Session.Secure || !validPrincipalIdentity(c.Auth.Local.Principal.Issuer, c.Auth.Local.Principal.Subject) ||
			c.Auth.Eligibility != nil || !emptyEnrichment(c.Auth.ClaimEnrichment) {
			return fmt.Errorf("%w: local auth requires an HTTP localhost URL, insecure localhost-only cookie, one principal, and no OAuth eligibility", errInvalidConfig)
		}
	} else if u.Scheme != httpsScheme || c.Auth.Local != (LocalAuthConfig{}) {
		return fmt.Errorf("%w: OAuth authentication requires HTTPS and no local principal", errInvalidConfig)
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
	if (c.Auth.Mode != authModeLocal && !c.Auth.Session.Secure) ||
		c.Auth.Session.MaxAgeSeconds < 300 || c.Auth.Session.MaxAgeSeconds > 86400 {
		return fmt.Errorf(
			"%w: auth.session must use a secure cookie with a 300..86400 second lifetime",
			errInvalidConfig,
		)
	}
	callback := c.Auth.OIDC.CallbackPath
	if c.Auth.Mode == authModeOAuth2 {
		callback = c.Auth.OAuth2.CallbackPath
	}
	if c.Auth.Mode != authModeLocal && (callback == "" || !strings.HasPrefix(callback, "/oauth2/") || path.Clean(callback) != callback ||
		strings.ContainsAny(callback, "%?#\\")) {
		return fmt.Errorf("%w: authentication callbackPath must be an unambiguous /oauth2/ path", errInvalidConfig)
	}
	if c.Auth.Mode == authModeOIDC {
		if !absoluteHTTPS(c.Auth.OIDC.IssuerURL) || c.Auth.OIDC.ClientID == "" {
			return fmt.Errorf("%w: OIDC issuerURL and clientID are required", errInvalidConfig)
		}
		claimSource := c.Auth.OIDC.EligibilityClaimSource
		if claimSource == "" {
			claimSource = eligibility.ClaimSourceIDToken
		}
		if !eligibility.ValidClaimSource(claimSource) {
			return fmt.Errorf(
				"%w: OIDC eligibilityClaimSource must be id_token, access_token, or userinfo",
				errInvalidConfig,
			)
		}
		if len(c.Auth.OIDC.AccessTokenAudience) > 512 ||
			strings.ContainsAny(c.Auth.OIDC.AccessTokenAudience, "\x00\r\n") {
			return fmt.Errorf("%w: OIDC accessTokenAudience must be a bounded string", errInvalidConfig)
		}
	} else if c.Auth.Mode == authModeOAuth2 {
		if c.Auth.OAuth2.Issuer == "" || !absoluteHTTPS(c.Auth.OAuth2.AuthorizationURL) ||
			!absoluteHTTPS(c.Auth.OAuth2.TokenURL) ||
			!absoluteHTTPS(c.Auth.OAuth2.IdentityEndpoint) ||
			c.Auth.OAuth2.SubjectPath == "" {
			return fmt.Errorf("%w: OAuth2 issuer, endpoints, and subjectPath are required", errInvalidConfig)
		}
		if c.Auth.OAuth2.AuthorizationResponseIssuer != "" &&
			!absoluteHTTPS(c.Auth.OAuth2.AuthorizationResponseIssuer) {
			return fmt.Errorf("%w: OAuth2 authorizationResponseIssuer must be an absolute HTTPS URL", errInvalidConfig)
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
	if c.Persistence.Mode == "" {
		c.Persistence.Mode = "kubernetes"
	}
	if c.Persistence.Mode == "local" {
		if c.Auth.Mode != authModeLocal || !path.IsAbs(c.Persistence.Local.Directory) ||
			path.Clean(c.Persistence.Local.Directory) != c.Persistence.Local.Directory || containsASCIIControl(c.Persistence.Local.Directory) ||
			c.basePath != "/agents/credentials" || c.Enrollment.MaxOutputBytes > maxBrokerCredential ||
			c.MaxUploadBytes > maxBrokerCredential {
			return fmt.Errorf("%w: local persistence requires local auth and one canonical absolute directory", errInvalidConfig)
		}
	} else if c.Persistence.Mode != "kubernetes" || c.Persistence.Local != (LocalPersistenceConfig{}) {
		return fmt.Errorf("%w: persistence.mode must be kubernetes or local", errInvalidConfig)
	}
	for _, method := range []string{c.Auth.OIDC.ClientAuthMethod, c.Auth.OAuth2.ClientAuthMethod} {
		if method != "" && method != "client_secret_basic" && method != "client_secret_post" {
			return fmt.Errorf(
				"%w: clientAuthMethod must be client_secret_basic or client_secret_post",
				errInvalidConfig,
			)
		}
	}
	if c.Dynamic.Enabled {
		return c.validateDynamic()
	}
	if len(c.Dynamic.Templates) != 0 || c.Dynamic.Broker != (DynamicBrokerConfig{}) {
		return fmt.Errorf("%w: disabled dynamic mode must not carry broker or template configuration", errInvalidConfig)
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

//nolint:cyclop,gocognit,gocyclo // Dynamic validation intentionally remains one linear fail-closed policy pass.
func (c *Config) validateDynamic() error {
	if len(c.Slots) != 0 {
		return fmt.Errorf("%w: static slots and dynamic templates are mutually exclusive", errInvalidConfig)
	}
	if c.Auth.Eligibility == nil {
		return fmt.Errorf("%w: dynamic mode requires an explicit eligibility policy", errInvalidConfig)
	}
	if c.basePath != "/agents/credentials" {
		return fmt.Errorf("%w: dynamic publicURL path must be /agents/credentials", errInvalidConfig)
	}
	if len(c.Dynamic.Templates) == 0 || len(c.Dynamic.Templates) > maxDynamicTemplates {
		return fmt.Errorf(
			"%w: dynamic.templates must contain 1..%d entries",
			errInvalidConfig,
			maxDynamicTemplates,
		)
	}
	if c.Enrollment.MaxOutputBytes > maxBrokerCredential {
		return fmt.Errorf("%w: dynamic enrollment output exceeds the broker credential limit", errInvalidConfig)
	}
	if c.RecoveryUpload.Enabled && c.MaxUploadBytes > maxBrokerCredential {
		return fmt.Errorf("%w: dynamic recovery upload exceeds the broker credential limit", errInvalidConfig)
	}
	brokerURL, err := url.Parse(c.Dynamic.Broker.URL)
	if err != nil || brokerURL.Scheme != httpsScheme || brokerURL.Host == "" || brokerURL.User != nil ||
		brokerURL.Path != "" || brokerURL.RawPath != "" || brokerURL.RawQuery != "" || brokerURL.Fragment != "" {
		return fmt.Errorf("%w: dynamic broker URL must be an HTTPS origin without a path", errInvalidConfig)
	}
	for _, file := range []struct {
		name  string
		value string
	}{
		{name: "caFile", value: c.Dynamic.Broker.CAFile},
		{name: "assertionKeyFile", value: c.Dynamic.Broker.AssertionKeyFile},
	} {
		if file.value == "" || !path.IsAbs(file.value) || path.Clean(file.value) != file.value ||
			containsASCIIControl(file.value) {
			return fmt.Errorf(
				"%w: dynamic broker %s must be a canonical absolute file path",
				errInvalidConfig,
				file.name,
			)
		}
	}
	if err := c.validateDynamicBrokerBounds(); err != nil {
		return err
	}
	if err := c.validateTemplateSwitch(); err != nil {
		return err
	}
	seen := map[string]bool{}
	for index, template := range c.Dynamic.Templates {
		if !slotPattern.MatchString(template.Name) || len(template.Name) > 63 || seen[template.Name] {
			return fmt.Errorf(
				"%w: dynamic.templates[%d].name must be a unique DNS label",
				errInvalidConfig,
				index,
			)
		}
		seen[template.Name] = true
		if strings.TrimSpace(template.Label) == "" || len(template.Label) > 128 ||
			containsASCIIControl(template.Label) {
			return fmt.Errorf("%w: dynamic template %s label is invalid", errInvalidConfig, template.Name)
		}
		if template.Adapter != AdapterCodexOAuthFile && template.Adapter != AdapterClaudeOAuthFile {
			return fmt.Errorf("%w: dynamic template %s adapter is unsupported", errInvalidConfig, template.Name)
		}
		if template.Adapter == AdapterCodexOAuthFile && !c.Enrollment.ExperimentalCodexDeviceAuth {
			return fmt.Errorf(
				"%w: dynamic template %s requires explicit experimental Codex device authorization opt-in",
				errInvalidConfig,
				template.Name,
			)
		}
	}

	return nil
}

func (c *Config) validateTemplateSwitch() error {
	config := &c.Dynamic.TemplateSwitch
	if !config.Enabled {
		if config.CoordinatorURL != "" || config.RequestTimeoutSeconds != 0 || config.MaxResponseBytes != 0 {
			return fmt.Errorf("%w: disabled template switch coordination must be empty", errInvalidConfig)
		}
		return nil
	}
	return validateEnabledTemplateSwitch(config)
}

func validateEnabledTemplateSwitch(config *TemplateSwitchConfig) error {
	coordinator, err := url.Parse(config.CoordinatorURL)
	if err != nil || coordinator.Scheme != httpScheme || coordinator.Host == "" ||
		coordinator.User != nil || coordinator.Path != "" || coordinator.RawQuery != "" ||
		coordinator.Fragment != "" || config.CoordinatorURL != coordinator.String() {
		return fmt.Errorf(
			"%w: template switch coordinator must be one canonical internal HTTP origin",
			errInvalidConfig,
		)
	}
	if config.RequestTimeoutSeconds == 0 {
		config.RequestTimeoutSeconds = 10
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = 4096
	}
	if config.RequestTimeoutSeconds < 1 || config.RequestTimeoutSeconds > 30 ||
		config.MaxResponseBytes < 512 || config.MaxResponseBytes > 16*1024 {
		return fmt.Errorf("%w: template switch coordinator bounds are invalid", errInvalidConfig)
	}
	return nil
}

func (c *Config) validateDynamicBrokerBounds() error {
	if c.Dynamic.Broker.AssertionTTLSeconds == 0 {
		c.Dynamic.Broker.AssertionTTLSeconds = defaultAssertionTTL
	}
	if c.Dynamic.Broker.EligibilityLeaseSeconds == 0 {
		c.Dynamic.Broker.EligibilityLeaseSeconds = c.Auth.Session.MaxAgeSeconds
	}
	if c.Dynamic.Broker.RequestTimeoutSeconds == 0 {
		c.Dynamic.Broker.RequestTimeoutSeconds = defaultBrokerTimeout
	}
	if c.Dynamic.Broker.MaxResponseBytes == 0 {
		c.Dynamic.Broker.MaxResponseBytes = defaultBrokerResponse
	}
	if c.Dynamic.Broker.AssertionTTLSeconds < 1 || c.Dynamic.Broker.AssertionTTLSeconds > 300 ||
		c.Dynamic.Broker.EligibilityLeaseSeconds < 300 ||
		c.Dynamic.Broker.EligibilityLeaseSeconds > c.Auth.Session.MaxAgeSeconds ||
		c.Dynamic.Broker.RequestTimeoutSeconds < 1 || c.Dynamic.Broker.RequestTimeoutSeconds > 30 ||
		c.Dynamic.Broker.MaxResponseBytes < 1024 || c.Dynamic.Broker.MaxResponseBytes > 1024*1024 {
		return fmt.Errorf("%w: dynamic broker bounds are invalid", errInvalidConfig)
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

func containsASCIIControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func emptyEnrichment(config eligibility.EnrichmentConfig) bool {
	return len(config.AllowedHosts) == 0 && config.TimeoutSeconds == 0 &&
		config.Limits == (eligibility.ResponseLimits{}) && len(config.Sources) == 0
}

func (c *Config) Path(suffix string) string { return c.basePath + suffix }
func (c *Config) PublicOrigin() string      { return c.publicOrigin }
