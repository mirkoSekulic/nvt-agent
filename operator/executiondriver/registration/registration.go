// Package registration defines the administrator-owned deployment contract
// for external execution-driver hosts. It is intentionally independent from
// AgentRun and controller reconciliation.
package registration

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	MaxRegistrations       = 32
	MaxRegistrationName    = 63
	MaxCommandArguments    = 128
	MaxCommandBytes        = 16 << 10
	MaxSecretEnvironment   = 64
	MaxSecretFiles         = 32
	MaxSecretItemsPerFile  = 64
	SecretProjectionRoot   = "/var/run/secrets/nvt-execution-driver"
	PersistentStateRoot    = "/var/lib/nvt-execution-driver"
	DriverHostPort         = 9443
	DriverHostProtocolName = "nvt.execution-driver-host/v1"
)

var (
	imagePattern       = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?/)(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*@sha256:[0-9a-f]{64}$`)
	environmentPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	commandPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$`)
)

// Registration describes one isolated, credentialed driver-host workload.
// Image is a complete provider image; Command names an executable already in
// that image. Infrastructure credentials are projected only into this
// registration's workload.
type Registration struct {
	Name              string
	Image             string
	Command           []string
	Resources         corev1.ResourceRequirements
	ServiceAccount    ServiceAccount
	PassEnv           []string
	SecretEnvironment []SecretEnvironmentVariable
	SecretFiles       []SecretFile
	Storage           *PersistentStorage
}

// PersistentStorage is an optional registration-owned writable filesystem.
// It is provider-neutral: the driver decides which durable resources and
// convergence records it stores below PersistentStateRoot.
type PersistentStorage struct {
	Size             resource.Quantity
	StorageClassName string
	ExistingClaim    string
}

type ServiceAccount struct {
	Create      bool
	Name        string
	Annotations map[string]string
	PodLabels   map[string]string
}

type SecretEnvironmentVariable struct {
	Name       string
	SecretName string
	Key        string
}

type SecretFile struct {
	Name       string
	SecretName string
	Items      []SecretFileItem
}

type SecretFileItem struct {
	Key  string
	Path string
}

func ValidateAll(registrations []Registration) error {
	if len(registrations) > MaxRegistrations {
		return errors.New("execution driver registration count exceeds the supported bound")
	}
	seen := make(map[string]struct{}, len(registrations))
	seenServiceAccounts := make(map[string]struct{}, len(registrations))
	seenExistingClaims := make(map[string]struct{}, len(registrations))
	for _, registration := range registrations {
		if _, duplicate := seen[registration.Name]; duplicate {
			return errors.New("execution driver registration names must be unique")
		}
		seen[registration.Name] = struct{}{}
		if err := Validate(registration); err != nil {
			return err
		}
		serviceAccountName := registration.ServiceAccount.Name
		if registration.ServiceAccount.Create && serviceAccountName == "" {
			serviceAccountName = ResourceName(registration.Name)
		}
		if _, duplicate := seenServiceAccounts[serviceAccountName]; duplicate {
			return errors.New("execution driver registrations must use distinct ServiceAccounts")
		}
		seenServiceAccounts[serviceAccountName] = struct{}{}
		if registration.Storage != nil && registration.Storage.ExistingClaim != "" {
			if _, duplicate := seenExistingClaims[registration.Storage.ExistingClaim]; duplicate {
				return errors.New("execution driver registrations must use distinct existing storage claims")
			}
			seenExistingClaims[registration.Storage.ExistingClaim] = struct{}{}
		}
	}
	return nil
}

// ResourceName maps a logical DNS-label registration name to a stable
// Kubernetes resource name without restricting the public 63-byte name
// contract merely because the implementation adds a prefix.
func ResourceName(name string) string {
	const prefix = "nvt-execution-driver-"
	if len(prefix)+len(name) <= 63 {
		return prefix + name
	}
	digest := sha256.Sum256([]byte(name))
	return fmt.Sprintf("nvt-ed-%x", digest[:28])
}

func Validate(value Registration) error {
	if errs := validation.IsDNS1123Label(value.Name); len(errs) != 0 || len(value.Name) > MaxRegistrationName {
		return errors.New("execution driver registration name is invalid")
	}
	if !imagePattern.MatchString(value.Image) {
		return errors.New("execution driver image must be a complete repository reference pinned by lowercase sha256 digest")
	}
	if err := validateCommand(value.Command); err != nil {
		return err
	}
	if err := validateResources(value.Resources); err != nil {
		return err
	}
	if err := validateServiceAccount(value.ServiceAccount); err != nil {
		return err
	}
	if err := validateEnvironment(value.PassEnv, value.SecretEnvironment); err != nil {
		return err
	}
	if err := validateSecretFiles(value.SecretFiles); err != nil {
		return err
	}
	return validatePersistentStorage(value.Storage)
}

func validatePersistentStorage(value *PersistentStorage) error {
	if value == nil {
		return nil
	}
	if value.ExistingClaim != "" {
		if len(validation.IsDNS1123Subdomain(value.ExistingClaim)) != 0 || !value.Size.IsZero() || value.StorageClassName != "" {
			return errors.New("execution driver existing storage claim is invalid")
		}
		return nil
	}
	if value.StorageClassName != "" && len(validation.IsDNS1123Subdomain(value.StorageClassName)) != 0 {
		return errors.New("execution driver storage class is invalid")
	}
	if value.Size.IsZero() {
		return errors.New("execution driver storage requires one bounded storage request")
	}
	minimum := resource.MustParse("1Gi")
	maximum := resource.MustParse("1Ti")
	if value.Size.Cmp(minimum) < 0 || value.Size.Cmp(maximum) > 0 {
		return errors.New("execution driver storage request must be between 1Gi and 1Ti")
	}
	return nil
}

func validateCommand(command []string) error {
	if len(command) == 0 || len(command) > MaxCommandArguments || !commandPathPattern.MatchString(command[0]) {
		return errors.New("execution driver command must begin with one absolute executable path")
	}
	total := 0
	for _, argument := range command {
		if argument == "" || !utf8.ValidString(argument) || strings.IndexByte(argument, 0) >= 0 {
			return errors.New("execution driver command contains an invalid argument")
		}
		total += len(argument)
		if total > MaxCommandBytes {
			return errors.New("execution driver command exceeds the supported bound")
		}
	}
	return nil
}

func validateResources(resources corev1.ResourceRequirements) error {
	for _, name := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
		request, requested := resources.Requests[name]
		limit, limited := resources.Limits[name]
		if !requested || request.Sign() <= 0 || !limited || limit.Sign() <= 0 || request.Cmp(limit) > 0 {
			return errors.New("execution driver resources require positive cpu/memory requests and limits")
		}
	}
	return nil
}

func validateServiceAccount(value ServiceAccount) error {
	if value.Create {
		if value.Name != "" && len(validation.IsDNS1123Subdomain(value.Name)) != 0 {
			return errors.New("execution driver created ServiceAccount name is invalid")
		}
	} else if len(validation.IsDNS1123Subdomain(value.Name)) != 0 {
		return errors.New("execution driver existing ServiceAccount name is required and must be valid")
	}
	for key, item := range value.Annotations {
		if len(validation.IsQualifiedName(key)) != 0 || !utf8.ValidString(item) || len(item) > 4096 {
			return errors.New("execution driver ServiceAccount annotation is invalid")
		}
	}
	for key, item := range value.PodLabels {
		if len(validation.IsQualifiedName(key)) != 0 || len(validation.IsValidLabelValue(item)) != 0 ||
			strings.HasPrefix(key, "app.kubernetes.io/") || strings.HasPrefix(key, "nvt.dev/") {
			return errors.New("execution driver workload-identity Pod label is invalid")
		}
	}
	return nil
}

func validateEnvironment(passEnv []string, values []SecretEnvironmentVariable) error {
	if len(passEnv)+len(values) > MaxSecretEnvironment {
		return errors.New("execution driver secret environment exceeds the supported bound")
	}
	seen := make(map[string]struct{}, len(passEnv)+len(values))
	for _, name := range passEnv {
		if !environmentPattern.MatchString(name) || name == "NVT_EXECUTION_DRIVER_STATE_DIR" {
			return errors.New("execution driver environment allowlist contains an invalid name")
		}
		if _, duplicate := seen[name]; duplicate {
			return errors.New("execution driver environment allowlist names must be unique")
		}
		seen[name] = struct{}{}
	}
	for _, value := range values {
		if !environmentPattern.MatchString(value.Name) || value.Name == "NVT_EXECUTION_DRIVER_STATE_DIR" || !validSecretName(value.SecretName) || !validSecretKey(value.Key) {
			return errors.New("execution driver secret environment entry is invalid")
		}
		if _, duplicate := seen[value.Name]; duplicate {
			return errors.New("execution driver environment allowlist names must be unique")
		}
		seen[value.Name] = struct{}{}
	}
	return nil
}

func validateSecretFiles(values []SecretFile) error {
	if len(values) > MaxSecretFiles {
		return errors.New("execution driver secret file projections exceed the supported bound")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if len(validation.IsDNS1123Label(value.Name)) != 0 || !validSecretName(value.SecretName) || len(value.Items) == 0 || len(value.Items) > MaxSecretItemsPerFile {
			return errors.New("execution driver secret file projection is invalid")
		}
		if _, duplicate := seen[value.Name]; duplicate {
			return errors.New("execution driver secret file projection names must be unique")
		}
		seen[value.Name] = struct{}{}
		paths := make(map[string]struct{}, len(value.Items))
		for _, item := range value.Items {
			if !validSecretKey(item.Key) || !validRelativePath(item.Path) {
				return errors.New("execution driver secret file item is invalid")
			}
			if _, duplicate := paths[item.Path]; duplicate {
				return errors.New("execution driver secret file item paths must be unique")
			}
			paths[item.Path] = struct{}{}
		}
	}
	return nil
}

func validSecretName(value string) bool {
	return len(validation.IsDNS1123Subdomain(value)) == 0
}

func validSecretKey(value string) bool {
	return value != "" && len(value) <= 253 && utf8.ValidString(value) && !strings.ContainsAny(value, "/\\\x00")
}

func validRelativePath(value string) bool {
	return value != "" && len(value) <= 253 && utf8.ValidString(value) && !strings.Contains(value, "\\") && !strings.HasPrefix(value, "/") && path.Clean(value) == value && value != "." && !strings.HasPrefix(value, "../")
}
