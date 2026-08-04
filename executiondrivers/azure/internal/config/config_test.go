package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestDecodeStrictImmutableAzureConfiguration(t *testing.T) {
	valid := validConfiguration(t)
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(encoded); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	mutations := map[string]func(*Configuration){
		"wrong version": func(v *Configuration) { v.ContractVersion = "nvt.azure-driver/v2" },
		"mutable image": func(v *Configuration) {
			v.VMImageResourceID = strings.TrimSuffix(v.VMImageResourceID, "1.2.3") + "latest"
		},
		"image definition": func(v *Configuration) {
			v.VMImageResourceID = strings.TrimSuffix(v.VMImageResourceID, "/versions/1.2.3")
		},
		"public image alias": func(v *Configuration) {
			v.VMImageResourceID = "Canonical:0001-com-ubuntu-server-jammy:22_04-lts:latest"
		},
		"plain registry":           func(v *Configuration) { v.HostBundle.Repository = "http://registry.example/nvt/host" },
		"plain enrollment":         func(v *Configuration) { v.EnrollmentEndpoint = "http://broker.example:7347" },
		"enrollment path":          func(v *Configuration) { v.EnrollmentEndpoint += "/v1" },
		"public IP request":        func(v *Configuration) { v.ResourceGroup += `","public_ip":true,"x":"` },
		"mutable disk":             func(v *Configuration) { v.OSDisk.StorageAccountType = "UltraSSD_LRS" },
		"unsupported architecture": func(v *Configuration) { v.GuestArchitecture = "arm64" },
		"noncanonical subnet":      func(v *Configuration) { v.SubnetResourceID += "/" },
		"unbounded timeout":        func(v *Configuration) { v.BootstrapTimeoutSec = 111 },
		"public SSH source":        func(v *Configuration) { v.Network.DriverSourceCIDR = "20.40.0.0/24" },
		"metadata DNS":             func(v *Configuration) { v.Network.DNSServer = "169.254.169.254" },
		"password host identity":   func(v *Configuration) { v.SSHHostPublicKey = "ssh-rsa bad" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			copy := valid
			mutate(&copy)
			raw, _ := json.Marshal(copy)
			if _, err := Decode(raw); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	unknown := append(encoded[:len(encoded)-1], []byte(`,"client_secret":"provider-canary"}`)...)
	if _, err := Decode(unknown); err == nil {
		t.Fatal("unknown secret-shaped field accepted")
	}
	duplicate := []byte(strings.Replace(string(encoded), `"vm_size":"Standard_D2s_v5"`, `"vm_size":"Standard_D2s_v5","vm_size":"Standard_D4s_v5"`, 1))
	if _, err := Decode(duplicate); err == nil {
		t.Fatal("duplicate field accepted")
	}
}

func TestConfigurationContainsOnlyBoundedPublicTrust(t *testing.T) {
	value := validConfiguration(t)
	encoded, _ := json.Marshal(value)
	for _, forbidden := range []string{"private_key", "client_secret", "enrollment_token", "nvt_eg1_", "nvt_ri1_", "public_ip"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("configuration contains %q", forbidden)
		}
	}
	if len(encoded) > MaxConfigBytes {
		t.Fatal("valid configuration exceeds bound")
	}
}

func validConfiguration(t *testing.T) Configuration {
	t.Helper()
	return Configuration{
		ContractVersion: Version, SubscriptionID: "11111111-1111-4111-8111-111111111111", ResourceGroup: "nvt-azure-rg", Location: "westeurope",
		SubnetResourceID:  "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/network-rg/providers/Microsoft.Network/virtualNetworks/nvt-vnet/subnets/agents",
		VMImageResourceID: "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/image-rg/providers/Microsoft.Compute/galleries/nvtgallery/images/nvtguest/versions/1.2.3",
		GuestArchitecture: "amd64", VMSize: "Standard_D2s_v5", OSDisk: OSDisk{SizeGiB: 64, StorageAccountType: "Premium_LRS"},
		HostBundle:         Artifact{Repository: "https://registry.example/nvt/host-bundle", Digest: "sha256:" + strings.Repeat("a", 64)},
		EnrollmentEndpoint: "https://broker.example:7347", EnrollmentCAPEM: testCAPEM(t), NativeSessionEndpoint: "tls://gateway.example:7443", NativeSessionCAPEM: testCAPEM(t),
		SSHHostPublicKey: testSSHPublicKey(t), Network: BootstrapNetwork{DriverSourceCIDR: "10.40.0.0/24", DNSServer: "168.63.129.16"}, BootstrapTimeoutSec: 90,
	}
}

func testCAPEM(t *testing.T) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
func testSSHPublicKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}
