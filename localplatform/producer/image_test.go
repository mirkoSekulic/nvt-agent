package producer

import (
	"context"
	"io"
	"reflect"
	"strings"
	"testing"
)

type imageInspectRunnerFunc func(context.Context, io.Reader, ...string) ([]byte, error)

func (function imageInspectRunnerFunc) Run(ctx context.Context, stdin io.Reader, arguments ...string) ([]byte, error) {
	return function(ctx, stdin, arguments...)
}

func TestDockerImageInspectorReturnsResolvedIdentityAndDeclaredVolumes(t *testing.T) {
	runner := imageInspectRunnerFunc(func(_ context.Context, stdin io.Reader, arguments ...string) ([]byte, error) {
		if stdin != nil || strings.Join(arguments, " ") != "image inspect ghcr.io/example/producer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
			t.Fatalf("inspect invocation: stdin=%#v arguments=%#v", stdin, arguments)
		}
		return []byte(`[{"Id":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","Config":{"Volumes":{"/state":{},"/cache":{}}}}]`), nil
	})
	resolved, err := (DockerImageInspector{Runner: runner}).InspectImage(context.Background(), "ghcr.io/example/producer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.ID != testResolvedImageID || !reflect.DeepEqual(resolved.DeclaredVolumes, []string{"/cache", "/state"}) {
		t.Fatalf("resolved image = %#v", resolved)
	}
}

func TestDockerImageInspectorRejectsAmbiguousOutput(t *testing.T) {
	for name, output := range map[string]string{
		"multiple":   `[{"Id":"` + testResolvedImageID + `"},{"Id":"` + testResolvedImageID + `"}]`,
		"no config":  `[{"Id":"` + testResolvedImageID + `"}]`,
		"mutable ID": `[{"Id":"latest","Config":{}}]`,
		"trailing":   `[{"Id":"` + testResolvedImageID + `","Config":{}}] {}`,
	} {
		t.Run(name, func(t *testing.T) {
			inspector := DockerImageInspector{Runner: imageInspectRunnerFunc(func(context.Context, io.Reader, ...string) ([]byte, error) {
				return []byte(output), nil
			})}
			if _, err := inspector.InspectImage(context.Background(), "image"); err == nil {
				t.Fatal("invalid image inspection was accepted")
			}
		})
	}
}
