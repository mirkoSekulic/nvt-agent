package registration

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func validRegistration(name string) Registration {
	return Registration{
		Name:    name,
		Image:   "registry.example.test/drivers/fake@sha256:" + strings.Repeat("a", 64),
		Command: []string{"/driver", "--serve"},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")},
			Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1"), corev1.ResourceMemory: resource.MustParse("256Mi")},
		},
		ServiceAccount:    ServiceAccount{Create: true, Annotations: map[string]string{"identity.example.test/client-id": "public-id"}, PodLabels: map[string]string{"identity.example.test/use": "true"}},
		PassEnv:           []string{"WORKLOAD_IDENTITY_TOKEN_FILE"},
		SecretEnvironment: []SecretEnvironmentVariable{{Name: "CLOUD_TOKEN", SecretName: "cloud-a", Key: "token"}},
		SecretFiles:       []SecretFile{{Name: "cloud", SecretName: "cloud-a", Items: []SecretFileItem{{Key: "config", Path: "config.json"}}}},
	}
}

func TestValidateRegistration(t *testing.T) {
	if err := Validate(validRegistration("driver-a")); err != nil {
		t.Fatalf("valid registration rejected: %v", err)
	}

	tests := map[string]func(*Registration){
		"tagged image":          func(v *Registration) { v.Image = "registry.example.test/driver:latest" },
		"uppercase digest":      func(v *Registration) { v.Image = "registry.example.test/driver@sha256:" + strings.Repeat("A", 64) },
		"relative command":      func(v *Registration) { v.Command[0] = "driver" },
		"missing resources":     func(v *Registration) { v.Resources = corev1.ResourceRequirements{} },
		"request exceeds limit": func(v *Registration) { v.Resources.Requests[corev1.ResourceCPU] = resource.MustParse("2") },
		"missing serviceaccount": func(v *Registration) {
			v.ServiceAccount = ServiceAccount{}
		},
		"reserved pod label": func(v *Registration) {
			v.ServiceAccount.PodLabels["app.kubernetes.io/name"] = "other-driver"
		},
		"duplicate env": func(v *Registration) {
			v.SecretEnvironment = append(v.SecretEnvironment, v.SecretEnvironment[0])
		},
		"duplicate injected and secret env": func(v *Registration) {
			v.PassEnv = append(v.PassEnv, "CLOUD_TOKEN")
		},
		"reserved state env": func(v *Registration) {
			v.PassEnv = append(v.PassEnv, "NVT_EXECUTION_DRIVER_STATE_DIR")
		},
		"traversal": func(v *Registration) { v.SecretFiles[0].Items[0].Path = "../token" },
		"duplicate file path": func(v *Registration) {
			v.SecretFiles[0].Items = append(v.SecretFiles[0].Items, SecretFileItem{Key: "other", Path: "config.json"})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := validRegistration("driver-a")
			mutate(&value)
			if err := Validate(value); err == nil {
				t.Fatal("invalid registration accepted")
			}
		})
	}
}

func TestValidateRegistrationPersistentStorage(t *testing.T) {
	value := validRegistration("driver-a")
	value.Storage = &PersistentStorage{Size: resource.MustParse("20Gi"), StorageClassName: "fast-state"}
	if err := Validate(value); err != nil {
		t.Fatalf("valid dynamic storage rejected: %v", err)
	}
	value.Storage = &PersistentStorage{ExistingClaim: "driver-a-state"}
	if err := Validate(value); err != nil {
		t.Fatalf("valid existing claim rejected: %v", err)
	}

	for name, storage := range map[string]*PersistentStorage{
		"too small":       {Size: resource.MustParse("512Mi")},
		"too large":       {Size: resource.MustParse("2Ti")},
		"invalid class":   {Size: resource.MustParse("20Gi"), StorageClassName: "BAD CLASS"},
		"invalid claim":   {ExistingClaim: "BAD CLAIM"},
		"ambiguous claim": {ExistingClaim: "driver-a-state", Size: resource.MustParse("20Gi")},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validRegistration("driver-a")
			candidate.Storage = storage
			if err := Validate(candidate); err == nil {
				t.Fatal("invalid persistent storage accepted")
			}
		})
	}
}

func TestValidateAllRejectsDuplicateNames(t *testing.T) {
	values := []Registration{validRegistration("driver-a"), validRegistration("driver-a")}
	if err := ValidateAll(values); err == nil {
		t.Fatal("duplicate logical registration name accepted")
	}
}

func TestValidateAllRejectsSharedServiceAccount(t *testing.T) {
	first := validRegistration("driver-a")
	second := validRegistration("driver-b")
	first.ServiceAccount = ServiceAccount{Name: "shared-driver-identity"}
	second.ServiceAccount = ServiceAccount{Name: "shared-driver-identity"}
	if err := ValidateAll([]Registration{first, second}); err == nil {
		t.Fatal("shared execution-driver ServiceAccount accepted")
	}
}

func TestValidateAllRejectsSharedExistingStorageClaim(t *testing.T) {
	first := validRegistration("driver-a")
	second := validRegistration("driver-b")
	first.Storage = &PersistentStorage{ExistingClaim: "shared-driver-state"}
	second.Storage = &PersistentStorage{ExistingClaim: "shared-driver-state"}
	if err := ValidateAll([]Registration{first, second}); err == nil {
		t.Fatal("shared execution-driver existing storage claim accepted")
	}
}

func TestResourceNamePreservesPublicLogicalNameContract(t *testing.T) {
	if got, want := ResourceName("driver-a"), "nvt-execution-driver-driver-a"; got != want {
		t.Fatalf("short resource name = %q, want %q", got, want)
	}
	logicalName := strings.Repeat("a", MaxRegistrationName)
	registration := validRegistration(logicalName)
	if err := ValidateAll([]Registration{registration}); err != nil {
		t.Fatalf("valid maximum-length logical name rejected: %v", err)
	}
	first := ResourceName(logicalName)
	second := ResourceName(strings.Repeat("b", MaxRegistrationName))
	if len(first) != 63 || !strings.HasPrefix(first, "nvt-ed-") {
		t.Fatalf("long resource name = %q, want stable 63-byte nvt-ed name", first)
	}
	if first == second {
		t.Fatal("distinct long logical names collided")
	}
}

func TestRegistrationDoesNotContainAgentRunOrSourceAcquisitionFields(t *testing.T) {
	// The type is deliberately small: source, provider config, and credentials
	// cannot arrive through AgentRun or producer payloads.
	value := validRegistration("driver-a")
	if strings.Contains(strings.ToLower(value.Image), "git") {
		t.Fatal("unexpected source acquisition field")
	}
}
