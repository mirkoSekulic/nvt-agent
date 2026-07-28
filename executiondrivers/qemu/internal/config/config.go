package config

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
)

const (
	Version        = "nvt.qemu-driver/v1"
	MaxConfigBytes = 64 << 10
	// Leave headroom inside the generic driver host's two-minute operation
	// deadline so transport shutdown remains authoritative.
	MaxBootTimeoutSeconds = 110
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Configuration struct {
	ContractVersion string     `json:"contract_version"`
	GuestImage      GuestImage `json:"guest_image"`
	HostBundle      Artifact   `json:"host_bundle"`
	RegistryCAPEM   string     `json:"registry_ca_pem,omitempty"`
	EnrollmentCAPEM string     `json:"enrollment_ca_pem"`
	CPUs            int        `json:"cpus"`
	MemoryMiB       int        `json:"memory_mib"`
	Acceleration    string     `json:"acceleration"`
	BootTimeoutSec  int        `json:"boot_timeout_seconds"`
}

type GuestImage struct {
	Digest string `json:"digest"`
}

type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
}

func Decode(raw json.RawMessage) (Configuration, error) {
	var value Configuration
	if len(raw) == 0 || len(raw) > MaxConfigBytes || executiondriver.DecodeStrictJSON(raw, &value) != nil || Validate(value) != nil {
		return Configuration{}, errors.New("QEMU execution class configuration is invalid")
	}
	return value, nil
}

func Validate(value Configuration) error {
	if value.ContractVersion != Version || !digestPattern.MatchString(value.GuestImage.Digest) ||
		ValidateArtifact(value.HostBundle) != nil {
		return errors.New("QEMU execution class artifact selection is invalid")
	}
	if value.RegistryCAPEM != "" && ValidateCAPEM(value.RegistryCAPEM) != nil {
		return errors.New("QEMU registry CA is invalid")
	}
	if ValidateCAPEM(value.EnrollmentCAPEM) != nil {
		return errors.New("QEMU enrollment CA is invalid")
	}
	if value.CPUs < 1 || value.CPUs > 8 || value.MemoryMiB < 256 || value.MemoryMiB > 8192 ||
		(value.Acceleration != "auto" && value.Acceleration != "kvm" && value.Acceleration != "tcg") ||
		value.BootTimeoutSec < 10 || value.BootTimeoutSec > MaxBootTimeoutSeconds {
		return errors.New("QEMU execution class resource settings are invalid")
	}
	return nil
}

func ValidateArtifact(value Artifact) error {
	if !digestPattern.MatchString(value.Digest) || validateRepository(value.Repository) != nil {
		return errors.New("artifact is invalid")
	}
	return nil
}

func ValidateCAPEM(value string) error {
	if len(value) == 0 || len(value) > 32<<10 || strings.ContainsRune(value, 0) {
		return errors.New("CA is invalid")
	}
	rest := []byte(value)
	count := 0
	for len(rest) != 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return errors.New("CA is invalid")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return errors.New("CA is invalid")
		}
		count++
		rest = remaining
	}
	if count == 0 || count > 16 {
		return errors.New("CA is invalid")
	}
	return nil
}

func validateRepository(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.RawPath != "" || parsed.Hostname() == "" || (parsed.Port() != "" && parsed.Port() != "443") || parsed.Path == "" || strings.HasSuffix(parsed.Path, "/") {
		return errors.New("repository is invalid")
	}
	host := parsed.Hostname()
	if net.ParseIP(host) != nil || strings.EqualFold(host, "localhost") || host != strings.ToLower(host) || !strings.Contains(host, ".") {
		return errors.New("repository is invalid")
	}
	for _, segment := range strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("repository is invalid")
		}
		for _, character := range segment {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '.' && character != '_' && character != '-' {
				return errors.New("repository is invalid")
			}
		}
	}
	return nil
}
