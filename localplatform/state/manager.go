package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	serviceconfig "github.com/mirkoSekulic/nvt-agent/localplatform/config"
	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	plancontract "github.com/mirkoSekulic/nvt-agent/localplatform/plan"
	producerrender "github.com/mirkoSekulic/nvt-agent/localplatform/producer"
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
	// ValidateVolumes performs a read-only exact-label check and returns the
	// names that already exist.
	ValidateVolumes(context.Context, []Volume) (map[string]bool, error)
	EnsureVolumes(context.Context, []Volume) (map[string]bool, error)
	// ReadVolumeInventory verifies and reads an existing generated-config
	// volume, or returns an empty result without creating the volume when it
	// does not exist yet.
	ReadVolumeInventory(context.Context, Volume) ([]byte, error)
	EnsureDirectory(context.Context, Volume, int, int, int64) error
	InspectPrivateSource(context.Context, Volume, int) (PrivateSourceState, error)
	FinalizePrivateSource(context.Context, Volume, int) error
	InitializePrivateSource(context.Context, Volume, int, []StateFile) error
	ReplaceFiles(context.Context, Volume, []StateFile) error
	CopyPrivateFile(context.Context, Volume, Volume, int, int, int) error
}

type PrivateSourceState uint8

const (
	PrivateSourceInvalid PrivateSourceState = iota
	PrivateSourceEmpty
	PrivateSourcePublishing
	PrivateSourceReady
	PrivateSourceCorrupt
)

const privateSourceMarkerVersion = "nvt.local-platform.private-source/v2"

func privateSourceMarker(value []byte) []byte {
	digest := sha256.Sum256(value)
	return fmt.Appendf(nil, "%s sha256:%x %d\n", privateSourceMarkerVersion, digest, len(value))
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
	configuration, err := configurationFiles(compiled, inputs, prepared.Plan, prepared.Volumes)
	if err != nil {
		return Plan{}, errors.New("generated configuration is invalid")
	}
	volumes := make(map[string]Volume, len(prepared.Volumes))
	for _, volume := range prepared.Volumes {
		volumes[volume.Name] = volume
	}
	historical, err := manager.Store.ReadVolumeInventory(ctx, volumes[prepared.configVolume])
	if err != nil {
		return Plan{}, errors.New("managed volume inventory is unavailable")
	}
	inventory, err := mergeVolumeInventory(project, historical, prepared.Volumes)
	if err != nil {
		return Plan{}, errors.New("managed volume inventory is invalid")
	}
	configuration, err = configurationFiles(compiled, inputs, prepared.Plan, inventory)
	if err != nil {
		return Plan{}, errors.New("generated configuration is invalid")
	}
	existing, err := manager.Store.ValidateVolumes(ctx, prepared.Volumes)
	if err != nil {
		return Plan{}, errors.New("trusted state volume ownership conflict or storage failure")
	}
	sourceStates := map[string]PrivateSourceState{}
	for _, input := range prepared.generated {
		if !existing[input.sourceVolume] {
			continue
		}
		expectedSize := generatedValueSize(input.encoding)
		state, err := manager.Store.InspectPrivateSource(ctx, volumes[input.sourceVolume], expectedSize)
		if err != nil || state == PrivateSourceInvalid || state == PrivateSourceCorrupt {
			return Plan{}, errors.New("generated private state is missing or corrupt")
		}
		sourceStates[input.sourceVolume] = state
	}
	configVolume := volumes[prepared.configVolume]
	if _, err := manager.Store.EnsureVolumes(ctx, []Volume{configVolume}); err != nil {
		return Plan{}, errors.New("trusted state inventory volume creation failed")
	}
	if err := manager.Store.ReplaceFiles(ctx, configVolume, configuration); err != nil {
		return Plan{}, errors.New("generated configuration storage failed")
	}
	_, err = manager.Store.EnsureVolumes(ctx, prepared.Volumes)
	if err != nil {
		return Plan{}, errors.New("trusted state volume ownership conflict or storage failure")
	}
	for _, input := range prepared.generated {
		if _, inspected := sourceStates[input.sourceVolume]; inspected {
			continue
		}
		expectedSize := generatedValueSize(input.encoding)
		state, err := manager.Store.InspectPrivateSource(ctx, volumes[input.sourceVolume], expectedSize)
		if err != nil || state == PrivateSourceInvalid || state == PrivateSourceCorrupt {
			return Plan{}, errors.New("generated private state is missing or corrupt")
		}
		sourceStates[input.sourceVolume] = state
	}
	for _, input := range prepared.generated {
		if sourceStates[input.sourceVolume] == PrivateSourcePublishing {
			if err := manager.Store.FinalizePrivateSource(ctx, volumes[input.sourceVolume], generatedValueSize(input.encoding)); err != nil {
				return Plan{}, errors.New("generated private state publication recovery failed")
			}
			sourceStates[input.sourceVolume] = PrivateSourceReady
		}
	}
	for _, directory := range prepared.directories {
		if err := manager.Store.EnsureDirectory(ctx, volumes[directory.volume], directory.uid, directory.gid, directory.mode); err != nil {
			return Plan{}, errors.New("trusted state directory initialization failed")
		}
	}
	for _, input := range prepared.static {
		reader, err := inputs.privateReader(input.owner, input.name)
		if err != nil {
			return Plan{}, errors.New("resolved private input became unavailable")
		}
		if err := manager.Store.ReplaceFiles(ctx, volumes[input.volume], []StateFile{{Name: "value", Mode: 0o400, UID: input.uid, GID: input.gid, Data: reader}}); err != nil {
			return Plan{}, errors.New("private input storage failed")
		}
	}
	for _, input := range prepared.generated {
		if sourceStates[input.sourceVolume] == PrivateSourceEmpty {
			value, err := generatedBytes(manager.Random, input.encoding)
			if err != nil {
				return Plan{}, err
			}
			marker := privateSourceMarker(value)
			writeErr := manager.Store.InitializePrivateSource(ctx, volumes[input.sourceVolume], generatedValueSize(input.encoding), []StateFile{
				{Name: ".initialized", Mode: 0o400, UID: 0, GID: 0, Data: bytes.NewReader(marker)},
				{Name: "value", Mode: 0o400, UID: 0, GID: 0, Data: bytes.NewReader(value)},
			})
			clear(marker)
			clear(value)
			if writeErr != nil {
				return Plan{}, errors.New("generated private state storage failed")
			}
		}
		for _, consumer := range input.consumer {
			if err := manager.Store.CopyPrivateFile(ctx, volumes[input.sourceVolume], volumes[consumer.volume], consumer.uid, consumer.gid, generatedValueSize(input.encoding)); err != nil {
				return Plan{}, errors.New("generated private state is missing or corrupt")
			}
		}
	}
	return prepared.Plan, nil
}

func configurationFiles(compiled manifest.Compiled, inputs *Inputs, plan Plan, inventory []Volume) ([]StateFile, error) {
	compiledJSON, err := compiled.CanonicalJSON()
	if err != nil {
		return nil, err
	}
	broker, err := serviceconfig.Broker(compiled)
	if err != nil {
		return nil, err
	}
	instructions := serviceconfig.Instructions{}
	for _, instruction := range inputs.Instructions {
		instructions[instruction.Name] = string(instruction.Content)
	}
	controller, err := serviceconfig.Controller(compiled, instructions)
	if err != nil {
		return nil, err
	}
	gateway, err := serviceconfig.Gateway(compiled)
	if err != nil {
		return nil, err
	}
	redacted, err := plan.CanonicalJSON()
	if err != nil {
		return nil, err
	}
	volumeInventory, err := (plancontract.VolumeInventory{Version: stateVersion, Project: plan.Project, Volumes: inventory}).CanonicalJSON()
	if err != nil {
		return nil, err
	}
	values := map[string][]byte{
		"compiled.json": compiledJSON, "broker.json": broker, "local-controller.json": controller,
		"gateway.json": gateway, "state-plan.json": redacted, "volume-inventory.json": volumeInventory,
	}
	if len(compiled.Gateway.CredentialPortalAccounts) > 0 {
		portal, err := portalConfiguration(compiled.Gateway.CredentialPortalAccounts)
		if err != nil {
			return nil, err
		}
		values["credential-portal.json"] = portal
	}
	producerFiles, err := producerrender.Configurations(compiled)
	if err != nil {
		return nil, err
	}
	for _, file := range producerFiles {
		values[file.Name] = file.Data
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
		if len(values[name]) > maxStateFileBytes {
			return nil, errors.New("generated state file is oversized")
		}
		result = append(result, StateFile{Name: name, Mode: 0o444, UID: 0, GID: 0, Data: bytes.NewReader(values[name])})
	}
	return result, nil
}

// MaxVolumeInventoryRecords is the shared finite ownership-record bound used
// before publication and by destructive reset validation.
const MaxVolumeInventoryRecords = 1024

func mergeVolumeInventory(project string, historical []byte, current []Volume) ([]Volume, error) {
	merged := map[string]Volume{}
	if len(historical) != 0 {
		if len(historical) > maxStateFileBytes {
			return nil, errors.New("managed volume inventory is oversized")
		}
		var inventory plancontract.VolumeInventory
		if json.Unmarshal(historical, &inventory) != nil || inventory.Version != stateVersion || inventory.Project != project || len(inventory.Volumes) == 0 || len(inventory.Volumes) > MaxVolumeInventoryRecords {
			return nil, errors.New("managed volume inventory is malformed")
		}
		for _, volume := range inventory.Volumes {
			if !validVolume(volume) || volume.Labels[ownerLabel] != project || len(volume.Consumers) != 0 {
				return nil, errors.New("managed volume inventory has invalid ownership")
			}
			if _, duplicate := merged[volume.Name]; duplicate {
				return nil, errors.New("managed volume inventory has duplicates")
			}
			merged[volume.Name] = volume
		}
	}
	for _, volume := range current {
		if !validVolume(volume) || volume.Labels[ownerLabel] != project {
			return nil, errors.New("current managed volume inventory is invalid")
		}
		if previous, exists := merged[volume.Name]; exists && !equalLabels(previous.Labels, volume.Labels) {
			return nil, errors.New("managed volume ownership changed")
		}
		volume.Consumers = nil
		merged[volume.Name] = volume
	}
	if len(merged) == 0 || len(merged) > MaxVolumeInventoryRecords {
		return nil, errors.New("managed volume inventory exceeded its bound")
	}
	names := make([]string, 0, len(merged))
	for name := range merged {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]Volume, 0, len(names))
	for _, name := range names {
		result = append(result, merged[name])
	}
	return result, nil
}
