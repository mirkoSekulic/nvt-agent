package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/contract"
)

func TestBuildArchiveIsDeterministicAndExtractsExactly(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "supervisor")
	if err := os.WriteFile(source, []byte("native-supervisor\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := testManifest()
	first := filepath.Join(directory, "first.tar.gz")
	second := filepath.Join(directory, "second.tar.gz")
	for _, output := range []string{first, second} {
		if _, err := BuildArchive(output, manifest, []InputFile{{Path: "bin/nvt-guest-supervisor", Source: source, Mode: 0o755}}); err != nil {
			t.Fatal(err)
		}
	}
	firstBytes, _ := os.ReadFile(first)
	secondBytes, _ := os.ReadFile(second)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("deterministic builds differ")
	}
	destination := filepath.Join(directory, "extracted")
	decoded, err := ExtractArchive(bytes.NewReader(firstBytes), destination)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.BundleVersion != manifest.BundleVersion {
		t.Fatalf("unexpected manifest: %#v", decoded)
	}
	content, _ := os.ReadFile(filepath.Join(destination, "bin", "nvt-guest-supervisor"))
	if string(content) != "native-supervisor\n" {
		t.Fatalf("unexpected content %q", content)
	}
}

func TestExtractArchiveRejectsUnsafeTypesPathsOwnershipAndDuplicates(t *testing.T) {
	validManifestBytes, err := contract.EncodeManifest(contract.Manifest{
		ContractVersion: contract.Version, OS: "linux", Architecture: "amd64",
		BundleVersion: "0.8.33-test", BuildID: strings.Repeat("a", 40),
		NativeEntrypoint: "bin/nvt-guest-supervisor", ServiceIdentity: "nvt-agent-guest.service",
		Compatibility: contract.Compatibility{AgentdProtocol: contract.AgentdProtocolVersion},
		Files:         []contract.File{{Path: "bin/nvt-guest-supervisor", SHA256: contract.Digest([]byte("x")), Size: 1, Mode: 0o755}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		headers []*tar.Header
		bodies  [][]byte
	}{
		{name: "traversal", headers: []*tar.Header{{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o755, Size: 1, Uid: 0, Gid: 0, ModTime: time.Unix(0, 0)}}, bodies: [][]byte{[]byte("x")}},
		{name: "symlink", headers: []*tar.Header{{Name: "bin/nvt-guest-supervisor", Typeflag: tar.TypeSymlink, Linkname: "/tmp/x", Mode: 0o755, Uid: 0, Gid: 0, ModTime: time.Unix(0, 0)}}},
		{name: "device", headers: []*tar.Header{{Name: "bin/nvt-guest-supervisor", Typeflag: tar.TypeChar, Mode: 0o755, Devmajor: 1, Devminor: 3, Uid: 0, Gid: 0, ModTime: time.Unix(0, 0)}}},
		{name: "ownership", headers: []*tar.Header{{Name: "bin/nvt-guest-supervisor", Typeflag: tar.TypeReg, Mode: 0o755, Size: 1, Uid: 1000, Gid: 1000, ModTime: time.Unix(0, 0)}}, bodies: [][]byte{[]byte("x")}},
		{name: "duplicate", headers: []*tar.Header{
			{Name: "bin/nvt-guest-supervisor", Typeflag: tar.TypeReg, Mode: 0o755, Size: 1, Uid: 0, Gid: 0, ModTime: time.Unix(0, 0)},
			{Name: "bin/nvt-guest-supervisor", Typeflag: tar.TypeReg, Mode: 0o755, Size: 1, Uid: 0, Gid: 0, ModTime: time.Unix(0, 0)},
		}, bodies: [][]byte{[]byte("x"), []byte("x")}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			archive := customArchive(t, validManifestBytes, test.headers, test.bodies)
			if _, err := ExtractArchive(bytes.NewReader(archive), filepath.Join(t.TempDir(), "out")); err == nil {
				t.Fatal("unsafe archive was accepted")
			}
		})
	}
}

func customArchive(t *testing.T, manifest []byte, headers []*tar.Header, bodies [][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	gzipWriter.Header.ModTime = time.Unix(0, 0)
	tarWriter := tar.NewWriter(gzipWriter)
	manifestHeader := &tar.Header{Name: contract.ManifestPath, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(manifest)), Uid: 0, Gid: 0, ModTime: time.Unix(0, 0)}
	if err := tarWriter.WriteHeader(manifestHeader); err != nil {
		t.Fatal(err)
	}
	_, _ = tarWriter.Write(manifest)
	for index, header := range headers {
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if index < len(bodies) {
			_, _ = tarWriter.Write(bodies[index])
		}
	}
	_ = tarWriter.Close()
	_ = gzipWriter.Close()
	return output.Bytes()
}

func testManifest() contract.Manifest {
	return contract.Manifest{
		ContractVersion: contract.Version, OS: "linux", Architecture: "amd64",
		BundleVersion: "0.8.33-test", BuildID: strings.Repeat("a", 40),
		NativeEntrypoint: "bin/nvt-guest-supervisor", ServiceIdentity: "nvt-agent-guest.service",
		Compatibility: contract.Compatibility{AgentdProtocol: contract.AgentdProtocolVersion},
	}
}
