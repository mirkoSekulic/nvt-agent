package portal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

type SecretPatcher interface {
	Patch(ctx context.Context, namespace, name, key string, credential []byte) error
}

type KubernetesSecretPatcher struct{ Client rest.Interface }

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
