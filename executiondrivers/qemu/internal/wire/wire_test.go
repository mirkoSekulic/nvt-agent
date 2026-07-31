package wire

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
)

func TestNativeEgressHostAliasesPinServingNameToRelayForward(t *testing.T) {
	attachment, err := executiondriver.SealNativeEgressAttachment(executiondriver.NativeEgressAttachment{
		ContractVersion: executiondriver.NativeEgressAttachmentVersion,
		Generation:      1,
		Relay: executiondriver.NativeEgressRelayAttachment{
			Host: "8.8.8.8", Port: 7444, ServerName: "relay.example", CAPEM: testCA(t),
		},
		RequiredDestinations: []executiondriver.NativeEgressRequiredDestination{
			{Purpose: executiondriver.NativeEgressDestinationBootstrap, Host: "registry.example", Port: 443},
			{Purpose: executiondriver.NativeEgressDestinationControl, Host: "relay.example", Port: 7443},
		},
		Redirect: executiondriver.NativeEgressRedirectIntent{
			Mode: executiondriver.NativeEgressRedirectModeCaptureTCP, LoopbackAddress: "127.0.0.1",
			TransparentTCPPort: 15001, ExplicitCONNECTPort: 15002,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	aliases, err := NativeEgressHostAliases(attachment)
	if err != nil {
		t.Fatal(err)
	}
	addresses := map[string]string{}
	for _, alias := range aliases {
		if prior := addresses[alias.Host]; prior != "" && prior != alias.Address {
			t.Fatal("one trusted host received divergent guest aliases")
		}
		addresses[alias.Host] = alias.Address
	}
	if addresses[attachment.Relay.Host] == "" || addresses[attachment.Relay.ServerName] != addresses[attachment.Relay.Host] {
		t.Fatalf("TLS serving name did not select the relay forward: %#v", addresses)
	}
}

func testCA(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
