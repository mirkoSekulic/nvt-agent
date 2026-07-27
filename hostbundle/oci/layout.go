package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mirkoSekulic/nvt-agent/hostbundle/contract"
)

const refNameAnnotation = "org.opencontainers.image.ref.name"

func BuildLayout(directory, tag, archivePath, operatingSystem, architecture string, annotations map[string]string) (string, error) {
	if directory == "" || tag == "" || operatingSystem != "linux" || (architecture != "amd64" && architecture != "arm64") {
		return "", errors.New("OCI layout parameters are invalid")
	}
	if err := os.MkdirAll(filepath.Join(directory, "blobs", "sha256"), 0o755); err != nil {
		return "", fmt.Errorf("create OCI layout: %w", err)
	}
	layerDescriptor, err := importBlob(directory, archivePath, contract.LayerMediaType)
	if err != nil {
		return "", err
	}
	layerDescriptor.Annotations = map[string]string{"org.opencontainers.image.title": "nvt-host-bundle.tar.gz"}
	configDescriptor, err := writeBlob(directory, []byte("{}"), contract.OCIEmptyConfigMediaType)
	if err != nil {
		return "", err
	}
	manifestBytes, err := compact(Manifest{
		SchemaVersion: 2,
		MediaType:     contract.OCIManifestMediaType,
		ArtifactType:  contract.ArtifactType,
		Config:        configDescriptor,
		Layers:        []Descriptor{layerDescriptor},
	})
	if err != nil {
		return "", errors.New("encode OCI artifact manifest")
	}
	manifestDescriptor, err := writeBlob(directory, manifestBytes, contract.OCIManifestMediaType)
	if err != nil {
		return "", err
	}
	manifestDescriptor.ArtifactType = contract.ArtifactType
	manifestDescriptor.Platform = &Platform{OS: operatingSystem, Architecture: architecture}
	rootBytes, err := compact(Index{
		SchemaVersion: 2,
		MediaType:     contract.OCIIndexMediaType,
		ArtifactType:  contract.ArtifactType,
		Manifests:     []Descriptor{manifestDescriptor},
		Annotations:   cloneAnnotations(annotations),
	})
	if err != nil {
		return "", errors.New("encode OCI artifact index")
	}
	rootDescriptor, err := writeBlob(directory, rootBytes, contract.OCIIndexMediaType)
	if err != nil {
		return "", err
	}
	rootDescriptor.ArtifactType = contract.ArtifactType
	rootDescriptor.Annotations = map[string]string{refNameAnnotation: tag}
	layoutIndex, err := json.Marshal(Index{SchemaVersion: 2, Manifests: []Descriptor{rootDescriptor}})
	if err != nil {
		return "", errors.New("encode OCI layout index")
	}
	layoutFile, _ := json.Marshal(LayoutFile{ImageLayoutVersion: "1.0.0"})
	if err := os.WriteFile(filepath.Join(directory, "index.json"), append(layoutIndex, '\n'), 0o644); err != nil {
		return "", errors.New("write OCI layout index")
	}
	if err := os.WriteFile(filepath.Join(directory, "oci-layout"), append(layoutFile, '\n'), 0o644); err != nil {
		return "", errors.New("write OCI layout marker")
	}
	return rootDescriptor.Digest, nil
}

func cloneAnnotations(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func importBlob(directory, source, mediaType string) (Descriptor, error) {
	file, err := os.Open(source)
	if err != nil {
		return Descriptor{}, errors.New("open OCI layer")
	}
	defer file.Close()
	temporary, err := os.CreateTemp(filepath.Join(directory, "blobs", "sha256"), ".blob-*.tmp")
	if err != nil {
		return Descriptor{}, errors.New("create OCI layer")
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	hasher := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(temporary, hasher), io.LimitReader(file, contract.MaxBundleBytes+1))
	closeErr := temporary.Close()
	if copyErr != nil || closeErr != nil || size > contract.MaxBundleBytes {
		return Descriptor{}, errors.New("OCI layer exceeds the bound")
	}
	digestHex := hex.EncodeToString(hasher.Sum(nil))
	if err := os.Rename(temporaryName, filepath.Join(directory, "blobs", "sha256", digestHex)); err != nil {
		return Descriptor{}, errors.New("publish OCI layer")
	}
	return Descriptor{MediaType: mediaType, Digest: "sha256:" + digestHex, Size: size}, nil
}

func writeBlob(directory string, content []byte, mediaType string) (Descriptor, error) {
	sum := sha256.Sum256(content)
	digestHex := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(directory, "blobs", "sha256", digestHex), content, 0o644); err != nil {
		return Descriptor{}, errors.New("write OCI metadata blob")
	}
	return Descriptor{MediaType: mediaType, Digest: "sha256:" + digestHex, Size: int64(len(content))}, nil
}
