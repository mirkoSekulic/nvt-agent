package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"

	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
)

type StateFile struct {
	Name string
	Mode int64
	UID  int
	GID  int
	Data io.Reader
}

// Store is the narrow trusted-state persistence boundary. Implementations must
// never copy Data into commands, environment values, labels, output, or logs.
type Store interface {
	EnsureVolumes(context.Context, []Volume) (map[string]bool, error)
	ReplaceFiles(context.Context, string, []StateFile) error
	CopyPrivateFile(context.Context, string, string, int, int) error
}

type Manager struct {
	Store  Store
	Random io.Reader
}

// Ensure validates every existing volume before writing anything, updates
// generated non-secret configuration and static inputs, initializes missing
// generated sources, then refreshes every exact consumer copy.
func (manager Manager) Ensure(ctx context.Context, project string, compiled manifest.Compiled, inputs *Inputs) (Plan, error) {
	if manager.Store == nil {
		return Plan{}, errors.New("trusted state store is unavailable")
	}
	prepared, err := preparePlan(project, compiled, inputs)
	if err != nil {
		return Plan{}, err
	}
	configuration, err := configurationFiles(compiled, inputs, prepared.Plan)
	if err != nil {
		return Plan{}, errors.New("generated configuration is invalid")
	}
	created, err := manager.Store.EnsureVolumes(ctx, prepared.Volumes)
	if err != nil {
		return Plan{}, errors.New("trusted state volume ownership conflict or storage failure")
	}
	if err := manager.Store.ReplaceFiles(ctx, prepared.configVolume, configuration); err != nil {
		return Plan{}, errors.New("generated configuration storage failed")
	}
	for _, input := range prepared.static {
		reader, err := inputs.privateReader(input.owner, input.name)
		if err != nil {
			return Plan{}, errors.New("resolved private input became unavailable")
		}
		if err := manager.Store.ReplaceFiles(ctx, input.volume, []StateFile{{Name: "value", Mode: 0o400, UID: input.uid, GID: input.gid, Data: reader}}); err != nil {
			return Plan{}, errors.New("private input storage failed")
		}
	}
	for _, input := range prepared.generated {
		if created[input.sourceVolume] {
			value, err := generatedBytes(manager.Random, input.encoding)
			if err != nil {
				return Plan{}, err
			}
			writeErr := manager.Store.ReplaceFiles(ctx, input.sourceVolume, []StateFile{{Name: "value", Mode: 0o400, UID: 0, GID: 0, Data: bytes.NewReader(value)}})
			clear(value)
			if writeErr != nil {
				return Plan{}, errors.New("generated private state storage failed")
			}
		}
		for _, consumer := range input.consumer {
			if err := manager.Store.CopyPrivateFile(ctx, input.sourceVolume, consumer.volume, consumer.uid, consumer.gid); err != nil {
				return Plan{}, errors.New("generated private state is missing or corrupt")
			}
		}
	}
	return prepared.Plan, nil
}

func configurationFiles(compiled manifest.Compiled, inputs *Inputs, plan Plan) ([]StateFile, error) {
	compiledJSON, err := compiled.CanonicalJSON()
	if err != nil {
		return nil, err
	}
	broker, err := json.Marshal(compiled.Broker)
	if err != nil {
		return nil, err
	}
	controller, err := json.Marshal(compiled.Controller)
	if err != nil {
		return nil, err
	}
	gateway, err := json.Marshal(compiled.Gateway)
	if err != nil {
		return nil, err
	}
	redacted, err := plan.CanonicalJSON()
	if err != nil {
		return nil, err
	}
	values := map[string][]byte{
		"compiled.json": compiledJSON, "broker.json": broker, "local-controller.json": controller,
		"gateway.json": gateway, "state-plan.json": redacted,
	}
	if len(compiled.Gateway.CredentialPortalAccounts) > 0 {
		portal, err := portalConfiguration(compiled.Gateway.CredentialPortalAccounts)
		if err != nil {
			return nil, err
		}
		values["credential-portal.json"] = portal
	}
	for _, instruction := range inputs.Instructions {
		values["instructions/"+shortID(instruction.Owner+"\x00"+instruction.Name)] = instruction.Content
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]StateFile, 0, len(names))
	for _, name := range names {
		result = append(result, StateFile{Name: name, Mode: 0o444, UID: 0, GID: 0, Data: bytes.NewReader(values[name])})
	}
	return result, nil
}
