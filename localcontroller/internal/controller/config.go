package controller

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Bind          string
	StatePath     string
	MaxActiveRuns int
	MaxClaimLease time.Duration
	SweepInterval time.Duration
}

func ConfigFromEnvironment() (Config, error) {
	config := Config{
		Bind:          environmentOrDefault("NVT_LOCAL_CONTROLLER_BIND", "0.0.0.0:7480"),
		StatePath:     environmentOrDefault("NVT_LOCAL_CONTROLLER_STATE", "/state/controller/local-controller.sqlite3"),
		MaxActiveRuns: 32,
		MaxClaimLease: 30 * time.Second,
		SweepInterval: time.Second,
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
	if config.StatePath == "" || !strings.HasSuffix(config.StatePath, ".sqlite3") || strings.ContainsAny(config.StatePath, "\x00\r\n") ||
		!filepath.IsAbs(config.StatePath) || filepath.Clean(config.StatePath) != config.StatePath || filepath.Dir(config.StatePath) == string(filepath.Separator) ||
		config.MaxActiveRuns < 1 || config.MaxActiveRuns > 10_000 ||
		config.MaxClaimLease < time.Second || config.MaxClaimLease > time.Hour ||
		config.SweepInterval < time.Second || config.SweepInterval > time.Minute {
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
