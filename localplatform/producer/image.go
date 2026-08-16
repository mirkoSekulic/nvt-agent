package producer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
)

// ImageInspectRunner is the narrow command boundary used to inspect a locally
// resolved image before its Compose service can be rendered.
type ImageInspectRunner interface {
	Run(context.Context, io.Reader, ...string) ([]byte, error)
}

// ResolvedImage contains only the immutable identity and image-declared mount
// authority needed by the producer renderer.
type ResolvedImage struct {
	ID              string
	DeclaredVolumes []string
}

type ImageInspector interface {
	InspectImage(context.Context, string) (ResolvedImage, error)
}

type ImageInspectorFunc func(context.Context, string) (ResolvedImage, error)

func (function ImageInspectorFunc) InspectImage(ctx context.Context, image string) (ResolvedImage, error) {
	return function(ctx, image)
}

// DockerImageInspector parses `docker image inspect` through an injected,
// bounded command runner. The caller is responsible for resolving the digest
// into the local daemon before rendering.
type DockerImageInspector struct {
	Runner ImageInspectRunner
}

func (inspector DockerImageInspector) InspectImage(ctx context.Context, image string) (ResolvedImage, error) {
	if inspector.Runner == nil || ctx == nil || len(image) == 0 || len(image) > 4096 || image != strings.TrimSpace(image) || strings.ContainsAny(image, "\x00\r\n") {
		return ResolvedImage{}, errors.New("external producer image inspection is unavailable")
	}
	output, err := inspector.Runner.Run(ctx, nil, "image", "inspect", image)
	if err != nil {
		return ResolvedImage{}, errors.New("external producer image inspection failed")
	}
	var records []struct {
		ID     string `json:"Id"`
		Config *struct {
			Volumes map[string]json.RawMessage `json:"Volumes"`
		} `json:"Config"`
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	if decoder.Decode(&records) != nil || len(records) != 1 || !validResolvedImageID(records[0].ID) || records[0].Config == nil {
		return ResolvedImage{}, errors.New("external producer image inspection is invalid")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ResolvedImage{}, errors.New("external producer image inspection is invalid")
	}
	volumes := make([]string, 0, len(records[0].Config.Volumes))
	for destination := range records[0].Config.Volumes {
		volumes = append(volumes, destination)
	}
	sort.Strings(volumes)
	return ResolvedImage{ID: records[0].ID, DeclaredVolumes: volumes}, nil
}

func validResolvedImageID(value string) bool {
	return resolvedImageIDPattern.MatchString(value)
}

func validExternalImageConfiguration(image ResolvedImage) bool {
	return validResolvedImageID(image.ID) && len(image.DeclaredVolumes) == 0
}

var resolvedImageIDPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
