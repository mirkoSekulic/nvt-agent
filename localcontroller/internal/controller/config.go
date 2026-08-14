package controller

import (
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Bind                    string
	StatePath               string
	MaxActiveRuns           int
	MaxClaimLease           time.Duration
	SweepInterval           time.Duration
	ReconcileInterval       time.Duration
	DockerHost              string
	RunsDir                 string
	BrokerURL               string
	BrokerCAFile            string
	BrokerAgentsPath        string
	IdentityKeyPath         string
	ControllerOwner         string
	ExternalNetwork         string
	ProxyPort               int
	ProtectedCIDRs          string
	DindImage               string
	EgressdImage            string
	CapturedImage           string
	SeedImage               string
	BackendOperationTimeout time.Duration
}

func ConfigFromEnvironment() (Config, error) {
	config := Config{
		Bind:                    environmentOrDefault("NVT_LOCAL_CONTROLLER_BIND", "0.0.0.0:7480"),
		StatePath:               environmentOrDefault("NVT_LOCAL_CONTROLLER_STATE", "/state/controller/local-controller.sqlite3"),
		MaxActiveRuns:           32,
		MaxClaimLease:           30 * time.Second,
		SweepInterval:           time.Second,
		ReconcileInterval:       time.Second,
		DockerHost:              environmentOrDefault("NVT_LOCAL_CONTROLLER_DOCKER_HOST", "unix:///var/run/docker.sock"),
		RunsDir:                 environmentOrDefault("NVT_LOCAL_CONTROLLER_RUNS_DIR", "/state/controller/runs"),
		BrokerURL:               environmentOrDefault("NVT_LOCAL_CONTROLLER_BROKER_URL", "http://broker:7347"),
		BrokerCAFile:            environmentOrDefault("NVT_LOCAL_CONTROLLER_BROKER_CA_FILE", ""),
		BrokerAgentsPath:        environmentOrDefault("NVT_LOCAL_CONTROLLER_BROKER_AGENTS", "/broker-state/agents.yaml"),
		IdentityKeyPath:         environmentOrDefault("NVT_LOCAL_CONTROLLER_IDENTITY_KEY_FILE", "/broker-state/local-controller.key"),
		ControllerOwner:         environmentOrDefault("NVT_LOCAL_CONTROLLER_OWNER", "nvt-local-controller"),
		ExternalNetwork:         environmentOrDefault("NVT_LOCAL_CONTROLLER_EXTERNAL_NETWORK", "agents-proxy"),
		ProxyPort:               4090,
		ProtectedCIDRs:          environmentOrDefault("NVT_LOCAL_CONTROLLER_DIND_PROTECTED_CIDRS", "127.0.0.0/8 169.254.0.0/16"),
		DindImage:               environmentOrDefault("NVT_LOCAL_CONTROLLER_DIND_IMAGE", "nvt-dind:latest"),
		EgressdImage:            environmentOrDefault("NVT_LOCAL_CONTROLLER_EGRESSD_IMAGE", "nvt-egressd:latest"),
		CapturedImage:           environmentOrDefault("NVT_LOCAL_CONTROLLER_CAPTURED_IMAGE", "nvt-captured:latest"),
		SeedImage:               environmentOrDefault("NVT_LOCAL_CONTROLLER_SEED_IMAGE", "nvt-agent-runtime:latest"),
		BackendOperationTimeout: 2 * time.Minute,
	}
	maxActiveRuns, err := environmentInteger("NVT_LOCAL_CONTROLLER_MAX_ACTIVE_RUNS", config.MaxActiveRuns)
	if err != nil {
		return Config{}, err
	}
	config.MaxActiveRuns = maxActiveRuns
	maxClaimLeaseSeconds, err := environmentInteger("NVT_LOCAL_CONTROLLER_MAX_CLAIM_LEASE_SECONDS", int(config.MaxClaimLease/time.Second))
	if err != nil {
		return Config{}, err
	}
	config.MaxClaimLease = time.Duration(maxClaimLeaseSeconds) * time.Second
	sweepSeconds, err := environmentInteger("NVT_LOCAL_CONTROLLER_SWEEP_SECONDS", int(config.SweepInterval/time.Second))
	if err != nil {
		return Config{}, err
	}
	config.SweepInterval = time.Duration(sweepSeconds) * time.Second
	reconcileSeconds, err := environmentInteger("NVT_LOCAL_CONTROLLER_RECONCILE_SECONDS", int(config.ReconcileInterval/time.Second))
	if err != nil {
		return Config{}, err
	}
	config.ReconcileInterval = time.Duration(reconcileSeconds) * time.Second
	operationSeconds, err := environmentInteger("NVT_LOCAL_CONTROLLER_BACKEND_TIMEOUT_SECONDS", int(config.BackendOperationTimeout/time.Second))
	if err != nil {
		return Config{}, err
	}
	config.BackendOperationTimeout = time.Duration(operationSeconds) * time.Second
	proxyPort, err := environmentInteger("NVT_LOCAL_CONTROLLER_PROXY_PORT", config.ProxyPort)
	if err != nil {
		return Config{}, err
	}
	config.ProxyPort = proxyPort
	if err := ValidateConfig(config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func ValidateConfig(config Config) error {
	if config.Bind == "" || len(config.Bind) > 512 || strings.ContainsAny(config.Bind, "\x00\r\n") {
		return ErrInvalidRequest
	}
	host, port, err := net.SplitHostPort(config.Bind)
	if err != nil || host == "" || port == "" {
		return ErrInvalidRequest
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return ErrInvalidRequest
	}
	brokerURL, brokerURLErr := url.Parse(config.BrokerURL)
	if config.StatePath == "" || !strings.HasSuffix(config.StatePath, ".sqlite3") || strings.ContainsAny(config.StatePath, "\x00\r\n") ||
		!filepath.IsAbs(config.StatePath) || filepath.Clean(config.StatePath) != config.StatePath || filepath.Dir(config.StatePath) == string(filepath.Separator) ||
		config.MaxActiveRuns < 1 || config.MaxActiveRuns > 10_000 ||
		config.MaxClaimLease < time.Second || config.MaxClaimLease > time.Hour ||
		config.SweepInterval < time.Second || config.SweepInterval > time.Minute ||
		config.ReconcileInterval < time.Second || config.ReconcileInterval > time.Minute ||
		config.BackendOperationTimeout < time.Second || config.BackendOperationTimeout > 5*time.Minute ||
		config.DockerHost == "" || strings.ContainsAny(config.DockerHost, "\x00\r\n") ||
		config.RunsDir == "" || !filepath.IsAbs(config.RunsDir) || filepath.Clean(config.RunsDir) != config.RunsDir ||
		brokerURLErr != nil || brokerURL.Host == "" || brokerURL.User != nil || brokerURL.RawQuery != "" || brokerURL.Fragment != "" ||
		(brokerURL.Scheme != "http" && brokerURL.Scheme != "https") || config.BrokerAgentsPath == "" || !filepath.IsAbs(config.BrokerAgentsPath) ||
		config.IdentityKeyPath == "" || !filepath.IsAbs(config.IdentityKeyPath) ||
		config.BrokerCAFile != "" && !filepath.IsAbs(config.BrokerCAFile) ||
		config.ControllerOwner == "" || len(config.ControllerOwner) > 63 || config.ExternalNetwork == "" || config.ProxyPort < 1 || config.ProxyPort > 65535 || config.ProtectedCIDRs == "" || len(config.ProtectedCIDRs) > 4096 ||
		config.DindImage == "" || config.EgressdImage == "" || config.CapturedImage == "" || config.SeedImage == "" ||
		strings.ContainsAny(config.ControllerOwner+config.ExternalNetwork+config.ProtectedCIDRs+config.DindImage+config.EgressdImage+config.CapturedImage+config.SeedImage, "\x00\r\n") {
		return ErrInvalidRequest
	}
	return nil
}

func environmentOrDefault(name, fallback string) string {
	value, exists := os.LookupEnv(name)
	if !exists {
		return fallback
	}
	return strings.TrimSpace(value)
}

func environmentInteger(name string, fallback int) (int, error) {
	value, exists := os.LookupEnv(name)
	if !exists {
		return fallback, nil
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, ErrInvalidRequest
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, ErrInvalidRequest
	}
	return parsed, nil
}
