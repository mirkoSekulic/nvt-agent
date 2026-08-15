package portal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

type SecretPatcher interface {
	Patch(ctx context.Context, namespace, name, key string, credential []byte) error
}

type KubernetesSecretPatcher struct{ Client rest.Interface }

type LocalFilePatcher struct {
	Directory    string
	Namespace    string
	Destinations map[string]string
}

func NewLocalFilePatcher(directory, namespace string, slots []Slot) (LocalFilePatcher, error) {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || namespace == "" {
		return LocalFilePatcher{}, errors.New("local credential directory unavailable")
	}
	destinations := make(map[string]string, len(slots))
	for _, slot := range slots {
		destinations[slot.SecretName+"\x00"+slot.DataKey] = slot.Name
	}
	return LocalFilePatcher{Directory: directory, Namespace: namespace, Destinations: destinations}, nil
}

func (p LocalFilePatcher) Patch(_ context.Context, namespace, name, key string, credential []byte) error {
	filename, ok := p.Destinations[name+"\x00"+key]
	if !ok || namespace != p.Namespace || len(credential) == 0 || len(credential) > maxBrokerCredential {
		return errors.New("local credential replacement rejected")
	}
	target := filepath.Join(p.Directory, filename)
	if filepath.Dir(target) != filepath.Clean(p.Directory) {
		return errors.New("local credential replacement rejected")
	}
	if info, err := os.Lstat(target); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("local credential replacement rejected")
		}
	} else if !os.IsNotExist(err) {
		return errors.New("local credential replacement unavailable")
	}
	temporary, err := os.CreateTemp(p.Directory, ".credential-next-")
	if err != nil {
		return errors.New("local credential replacement unavailable")
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil || writeAndSync(temporary, credential) != nil || temporary.Close() != nil {
		return errors.New("local credential replacement unavailable")
	}
	if err := os.Rename(temporaryName, target); err != nil {
		return errors.New("local credential replacement unavailable")
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(p.Directory)
		if err != nil {
			return errors.New("local credential replacement unavailable")
		}
		err = directory.Sync()
		_ = directory.Close()
		if err != nil {
			return errors.New("local credential replacement unavailable")
		}
	}
	return nil
}

func writeAndSync(file *os.File, content []byte) error {
	if _, err := file.Write(content); err != nil {
		return err
	}
	return file.Sync()
}

func (p KubernetesSecretPatcher) Patch(ctx context.Context, namespace, name, key string, credential []byte) error {
	request := []struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value []byte `json:"value"`
	}{{
		Op: "add", Path: "/data/" + escapeJSONPointer(key), Value: credential,
	}}
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode Secret patch: %w", err)
	}
	defer func() {
		for index := range body {
			body[index] = 0
		}
		body = nil
	}()
	response, err := p.Client.Patch(types.JSONPatchType).
		Namespace(namespace).
		Resource("secrets").
		Name(name).
		SetHeader("Accept", "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json;q=0.9").
		Body(body).
		Stream(ctx)
	if err != nil {
		return fmt.Errorf("patch Secret: %w", err)
	}
	buffer := make([]byte, 32*1024)
	defer func() {
		for index := range buffer {
			buffer[index] = 0
		}
		buffer = nil
	}()
	_, copyErr := io.CopyBuffer(io.Discard, io.LimitReader(response, 2*1024*1024), buffer)
	closeErr := response.Close()
	if copyErr != nil {
		return fmt.Errorf("discard Secret patch response: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close Secret patch response: %w", closeErr)
	}
	return nil
}

func escapeJSONPointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}
