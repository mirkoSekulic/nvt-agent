package state

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
)

const (
	ownerLabel     = "nvt.dev/local-platform-owner"
	custodianLabel = "nvt.dev/local-platform-custodian"
	roleLabel      = "nvt.dev/local-platform-role"
	volumeLabel    = "nvt.dev/local-platform-volume"
	versionLabel   = "nvt.dev/local-platform-version"
	stateVersion   = "1"
)

var projectPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)
var producerServicePattern = regexp.MustCompile(`^producer:[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$`)

// Plan is the complete redacted volume and mount contract. It contains no host
// paths or secret-derived values and is therefore safe to serialize and log.
type Plan struct {
	Version string   `json:"version"`
	Project string   `json:"project"`
	Volumes []Volume `json:"volumes"`
	Mounts  []Mount  `json:"mounts"`
}

type Volume struct {
	Name      string            `json:"name"`
	Role      string            `json:"role"`
	Owner     string            `json:"owner"`
	Consumers []string          `json:"consumers,omitempty"`
	Labels    map[string]string `json:"labels"`
}

type Mount struct {
	Service  string `json:"service"`
	Volume   string `json:"volume"`
	Subpath  string `json:"subpath,omitempty"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"readOnly"`
}

type generatedInput struct {
	name      string
	purpose   string
	consumers []string
	encoding  string
}

type preparedPlan struct {
	Plan
	configVolume string
	static       []staticInput
	generated    []generatedInputPlan
	directories  []directoryPlan
}

type directoryPlan struct {
	volume   string
	uid, gid int
	mode     int64
}

type staticInput struct {
	owner, name, volume string
	uid, gid            int
}

type generatedInputPlan struct {
	generatedInput
	sourceVolume string
	consumer     []consumerCopy
}

type consumerCopy struct {
	service, volume string
	uid, gid        int
}

// BuildPlan defines exact service mounts without touching Docker. Static and
// generated private values each receive a distinct per-consumer volume; no
// agent service is ever a consumer.
func BuildPlan(project string, compiled manifest.Compiled, inputs *Inputs) (Plan, error) {
	prepared, err := preparePlan(project, compiled, inputs)
	if err != nil {
		return Plan{}, err
	}
	return prepared.Plan, nil
}

func preparePlan(project string, compiled manifest.Compiled, inputs *Inputs) (preparedPlan, error) {
	if !projectPattern.MatchString(project) || inputs == nil {
		return preparedPlan{}, errors.New("trusted state plan configuration is invalid")
	}
	result := preparedPlan{Plan: Plan{Version: stateVersion, Project: project}}
	addVolume := func(suffix, role, owner string, consumers ...string) Volume {
		consumers = uniqueSorted(consumers)
		volume := Volume{
			Name: project + "-" + suffix, Role: role, Owner: owner, Consumers: consumers,
			Labels: map[string]string{ownerLabel: project, custodianLabel: owner, roleLabel: role, volumeLabel: project + "-" + suffix, versionLabel: stateVersion},
		}
		result.Volumes = append(result.Volumes, volume)
		return volume
	}
	portalEnabled := len(compiled.Gateway.CredentialPortalAccounts) > 0
	configConsumers := []string{"broker", "gateway", "local-controller"}
	if portalEnabled {
		configConsumers = append(configConsumers, "credential-portal")
	}
	config := addVolume("generated-config", "generated-config", "local-platform-state", configConsumers...)
	result.configVolume = config.Name
	addDirectoryMount := func(service string, volume Volume, target string, readOnly bool) {
		result.Mounts = append(result.Mounts, Mount{Service: service, Volume: volume.Name, Target: target, ReadOnly: readOnly})
	}
	brokerData := addVolume("broker-data", "broker-database-audit", "broker", "broker")
	brokerPrivate := addVolume("broker-private", "broker-identities-canonical-credentials", "broker", "broker")
	controllerData := addVolume("controller-data", "local-controller-database-audit", "local-controller", "local-controller")
	result.directories = append(result.directories,
		directoryPlan{volume: brokerData.Name, uid: 0, gid: 0, mode: 0o700},
		directoryPlan{volume: brokerPrivate.Name, uid: 0, gid: 0, mode: 0o700},
		directoryPlan{volume: controllerData.Name, uid: 0, gid: 0, mode: 0o700},
	)
	addDirectoryMount("broker", brokerData, "/var/lib/nvt/broker", false)
	addDirectoryMount("broker", brokerPrivate, "/private", false)
	addDirectoryMount("local-controller", controllerData, "/var/lib/nvt/local-controller", false)
	if portalEnabled {
		credentialSeeds := addVolume("credential-seeds", "credential-portal-seed", "credential-portal", "broker", "credential-portal")
		result.directories = append(result.directories, directoryPlan{volume: credentialSeeds.Name, uid: 1000, gid: 1000, mode: 0o700})
		addDirectoryMount("credential-portal", credentialSeeds, "/seed", false)
		addDirectoryMount("broker", credentialSeeds, "/portal-seed", true)
	}
	for _, item := range []struct{ service, subpath, target string }{
		{"broker", "broker.json", "/etc/nvt-local/broker.json"},
		{"local-controller", "local-controller.json", "/etc/nvt-local/local-controller.json"},
		{"gateway", "gateway.json", "/etc/nvt-local/gateway.json"},
	} {
		result.Mounts = append(result.Mounts, Mount{Service: item.service, Volume: config.Name, Subpath: "current/" + item.subpath, Target: item.target, ReadOnly: true})
	}
	if portalEnabled {
		result.Mounts = append(result.Mounts, Mount{Service: "credential-portal", Volume: config.Name, Subpath: "current/credential-portal.json", Target: "/etc/nvt-local/credential-portal.json", ReadOnly: true})
	}

	seenStatic := map[inputKey]struct{}{}
	expectedInstructions := map[inputKey]struct{}{}
	for _, input := range compiled.PrivateInputs {
		if input.Purpose == "instructions" {
			expectedInstructions[inputKey{owner: input.Owner, name: input.Name}] = struct{}{}
			continue
		}
		key := inputKey{owner: input.Owner, name: input.Name}
		if _, exists := seenStatic[key]; exists {
			continue
		}
		if _, exists := inputs.private[key]; !exists || !trustedPrivateOwner(input.Owner) {
			return preparedPlan{}, errors.New("resolved private inputs do not match compiled intent")
		}
		seenStatic[key] = struct{}{}
		uid, gid := serviceIdentity(input.Owner)
		suffix := "input-" + shortID(input.Owner+"\x00"+input.Name)
		volume := addVolume(suffix, "static-private-input", input.Owner, input.Owner)
		result.static = append(result.static, staticInput{input.Owner, input.Name, volume.Name, uid, gid})
		result.Mounts = append(result.Mounts, Mount{Service: input.Owner, Volume: volume.Name, Subpath: "current/value", Target: privateTarget(input.Name), ReadOnly: true})
	}
	if len(seenStatic) != len(inputs.private) {
		return preparedPlan{}, errors.New("resolved private inputs exceed compiled intent")
	}
	seenInstructions := map[inputKey]struct{}{}
	for _, instruction := range inputs.Instructions {
		key := inputKey{owner: instruction.Owner, name: instruction.Name}
		if _, expected := expectedInstructions[key]; !expected {
			return preparedPlan{}, errors.New("resolved instructions exceed compiled intent")
		}
		if _, duplicate := seenInstructions[key]; duplicate {
			return preparedPlan{}, errors.New("duplicate resolved instruction")
		}
		seenInstructions[key] = struct{}{}
	}
	if len(seenInstructions) != len(expectedInstructions) {
		return preparedPlan{}, errors.New("compiled instructions are unresolved")
	}

	generated := []generatedInput{
		{name: "local-controller-identity", purpose: "controller-identity-key", consumers: []string{"local-controller"}, encoding: "raw"},
		{name: "local-controller-admin-token", purpose: "controller-admin-token", consumers: []string{"local-controller"}, encoding: "base64url"},
		{name: "local-controller-route-token", purpose: "controller-route-token", consumers: []string{"gateway", "local-controller"}, encoding: "base64url"},
	}
	if portalEnabled {
		generated = append(generated,
			generatedInput{name: "credential-runner-key", purpose: "credential-runner-authentication", consumers: []string{"credential-portal", "credential-runner"}, encoding: "base64url"},
			generatedInput{name: "credential-portal-session-key", purpose: "credential-portal-session", consumers: []string{"credential-portal"}, encoding: "base64url"},
		)
	}
	for _, input := range compiled.GeneratedPrivateInputs {
		if input.Owner != "local-platform-state" || len(input.Consumers) == 0 {
			return preparedPlan{}, errors.New("generated private input ownership is invalid")
		}
		generated = append(generated, generatedInput{name: input.Name, purpose: input.Purpose, consumers: append([]string(nil), input.Consumers...), encoding: "base64url"})
	}
	sort.Slice(generated, func(i, j int) bool { return generated[i].name < generated[j].name })
	seenGenerated := map[string]struct{}{}
	for _, input := range generated {
		if input.name == "" || input.purpose == "" {
			return preparedPlan{}, errors.New("generated private input is invalid")
		}
		if _, exists := seenGenerated[input.name]; exists {
			return preparedPlan{}, errors.New("duplicate generated private input")
		}
		seenGenerated[input.name] = struct{}{}
		input.consumers = uniqueSorted(input.consumers)
		for _, consumer := range input.consumers {
			if !trustedGeneratedConsumer(consumer) {
				return preparedPlan{}, errors.New("generated private input consumer is invalid")
			}
		}
		source := addVolume("generated-"+shortID(input.name), "generated-private-source", "local-platform-state")
		entry := generatedInputPlan{generatedInput: input, sourceVolume: source.Name}
		for _, consumer := range input.consumers {
			uid, gid := serviceIdentity(consumer)
			copyVolume := addVolume("generated-"+shortID(input.name+"\x00"+consumer), "generated-private-input", "local-platform-state", consumer)
			entry.consumer = append(entry.consumer, consumerCopy{consumer, copyVolume.Name, uid, gid})
			result.Mounts = append(result.Mounts, Mount{Service: consumer, Volume: copyVolume.Name, Subpath: "current/value", Target: privateTarget(input.name), ReadOnly: true})
		}
		result.generated = append(result.generated, entry)
	}
	sort.Slice(result.Volumes, func(i, j int) bool { return result.Volumes[i].Name < result.Volumes[j].Name })
	sort.Slice(result.Mounts, func(i, j int) bool {
		a, b := result.Mounts[i], result.Mounts[j]
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return a.Volume < b.Volume
	})
	return result, nil
}

func trustedGeneratedConsumer(value string) bool {
	return value == "broker" || value == "credential-portal" || value == "credential-runner" || value == "gateway" || value == "local-controller" || producerServicePattern.MatchString(value)
}

func serviceIdentity(service string) (int, int) {
	switch service {
	case "gateway":
		return 65532, 65532
	case "credential-portal", "credential-runner":
		return 1000, 1000
	default:
		if strings.HasPrefix(service, "producer:") {
			return 65532, 65532
		}
		return 0, 0
	}
}

func privateTarget(name string) string { return "/run/nvt-private/" + shortID(name) }
func shortID(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:12])
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		seen[value] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// CanonicalJSON returns a stable redacted plan. It is safe for generated
// configuration because Plan cannot represent secret bytes or host paths.
func (plan Plan) CanonicalJSON() ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(plan); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}

func generatedBytes(random io.Reader, encoding string) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	raw := make([]byte, 32)
	if _, err := io.ReadFull(random, raw); err != nil {
		clear(raw)
		return nil, errors.New("generated private state is unavailable")
	}
	if encoding == "raw" {
		return raw, nil
	}
	if encoding != "base64url" {
		clear(raw)
		return nil, errors.New("generated private state encoding is invalid")
	}
	encoded := []byte(base64.RawURLEncoding.EncodeToString(raw))
	clear(raw)
	return encoded, nil
}

func portalConfiguration(accounts []manifest.PortalAccountIntent) ([]byte, error) {
	const maxPortalSlots = 128
	type slot struct {
		Name           string            `json:"name"`
		Label          string            `json:"label"`
		Owner          map[string]string `json:"owner"`
		Adapter        string            `json:"adapter"`
		BrokerProvider string            `json:"brokerProvider"`
		SecretName     string            `json:"secretName"`
		DataKey        string            `json:"dataKey"`
	}
	accounts = append([]manifest.PortalAccountIntent(nil), accounts...)
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].Name < accounts[j].Name })
	if len(accounts) == 0 || len(accounts) > maxPortalSlots {
		return nil, errors.New("credential portal requires 1..128 accounts")
	}
	slots := []slot{}
	seenNames := map[string]struct{}{}
	seenDestinations := map[string]struct{}{}
	for _, account := range accounts {
		adapter := ""
		switch account.Preset {
		case "codex-oauth":
			adapter = "codex-oauth-file"
		case "claude-oauth":
			adapter = "claude-oauth-file"
		default:
			return nil, fmt.Errorf("unsupported credential portal account %q", account.Name)
		}
		slotName := portalSlotName(account.Name)
		dataKey := slotName + ".json"
		if _, exists := seenNames[slotName]; exists {
			return nil, errors.New("credential portal slot mapping collision")
		}
		if _, exists := seenDestinations[dataKey]; exists {
			return nil, errors.New("credential portal destination mapping collision")
		}
		seenNames[slotName] = struct{}{}
		seenDestinations[dataKey] = struct{}{}
		slots = append(slots, slot{slotName, account.Name, map[string]string{"issuer": "local://workstation", "subject": "developer"}, adapter, account.Name, "local-seed", dataKey})
	}
	document := map[string]any{
		"auth":      map[string]any{"mode": "local", "session": map[string]any{"cookieName": "nvt_local_credentials", "maxAgeSeconds": 3600, "secure": false}, "local": map[string]any{"principal": map[string]string{"issuer": "local://workstation", "subject": "developer", "displayName": "Local developer"}}},
		"publicURL": "http://localhost:4090/agents/credentials", "returnURL": "/agents", "listenAddr": "0.0.0.0:8080", "namespace": "local", "slots": slots,
		"enrollment":     map[string]any{"maxSessions": 16, "maxConcurrent": 2, "timeoutSeconds": 600, "maxOutputBytes": 65536, "experimentalCodexDeviceAuth": true},
		"maxUploadBytes": 65536, "recoveryUpload": map[string]bool{"enabled": true}, "persistence": map[string]any{"mode": "local", "local": map[string]string{"directory": "/seed"}},
	}
	return json.Marshal(document)
}

func portalSlotName(account string) string {
	digest := sha256.Sum256([]byte("nvt.local-credential-slot/v1\x00" + account))
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])
	return "slot-" + strings.ToLower(encoded)
}
