package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/qemu/internal/wire"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
	"github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment"
)

func TestLocateNamedVirtioControlDeviceWithoutUdevSymlink(t *testing.T) {
	sysfs := t.TempDir()
	entry := filepath.Join(sysfs, "null")
	if err := os.Mkdir(entry, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(entry, "name"), []byte("org.nvt.control\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path, err := locateControlDeviceAt(sysfs, "/dev")
	if err != nil || path != "/dev/null" {
		t.Fatalf("kernel-named control device = %q, %v", path, err)
	}
}

func TestNativeEgressCAPersistencePrecedesSingleUseEnrollment(t *testing.T) {
	caPEM := testPublicCAPEM(t)
	token, err := guestenrollment.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	binding := guestenrollment.Binding{
		AgentRunUID: "11111111-1111-1111-1111-111111111111", ExecutionID: "exec-1",
		DriverRegistration: "qemu", DesiredGeneration: 1, GuestInstanceID: "guest-1",
	}
	now := time.Now().UTC().Truncate(time.Second)
	envelope := guestenrollment.BootstrapEnvelope{
		ContractVersion: guestenrollment.Version, Binding: binding,
		ExchangeURL: "https://broker.example/v1/guest-enrollment/exchange", Token: token,
		IssuedAt: guestenrollment.FormatTimestamp(now), ExpiresAt: guestenrollment.FormatTimestamp(now.Add(4 * time.Minute)),
	}
	configuration := &wire.BootConfiguration{
		Binding: binding, NativeEgressAttachment: &executiondriver.NativeEgressAttachment{},
	}
	guest := &guest{configuration: configuration, bootstrap: make(chan struct{}, 1)}
	oldPersist, oldAccept := persistNativeEgressCA, acceptEnrollmentCall
	defer func() { persistNativeEgressCA, acceptEnrollmentCall = oldPersist, oldAccept }()
	persisted := 0
	accepted := 0
	persistNativeEgressCA = func(string) error {
		persisted++
		if persisted == 1 {
			return os.ErrPermission
		}
		return nil
	}
	acceptEnrollmentCall = func(guestenrollment.BootstrapEnvelope, string) error {
		accepted++
		return nil
	}

	first := guest.deliver(&envelope, caPEM)
	if first.Error != "trust-unavailable" || accepted != 0 || guest.enrolled {
		t.Fatalf("CA failure consumed enrollment: response=%#v accepted=%d enrolled=%v", first, accepted, guest.enrolled)
	}
	if envelope.Token == "" {
		t.Fatal("CA failure consumed the retryable enrollment envelope")
	}
	second := guest.deliver(&envelope, caPEM)
	if second.State == wire.StateFailed || accepted != 1 || !guest.enrolled {
		t.Fatalf("retry did not complete enrollment: response=%#v accepted=%d enrolled=%v", second, accepted, guest.enrolled)
	}
}

func testPublicCAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Minute)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: now, NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
