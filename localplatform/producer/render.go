// Package producer renders the bounded local producer configuration and
// Docker Compose fragment from compiled administrator intent.
package producer

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/distribution/reference"
	"github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	plancontract "github.com/mirkoSekulic/nvt-agent/localplatform/plan"
	"gopkg.in/yaml.v3"
)

const (
	ConfigPath              = "/etc/nvt-producer/config.json"
	StatePath               = "/var/lib/nvt-producer"
	defaultAdmissionBaseURL = "http://local-controller:7480"
	defaultControlNetwork   = "local-control-plane"
	defaultEgressNetwork    = "producer-egress"
	defaultGitHubImage      = "nvt-github-comments-producer:latest"
)

type Options struct {
	ControlNetwork      string
	EgressNetwork       string
	GitHubCommentsImage string
}

type ConfigFile struct {
	Name string
	Data []byte
}

type externalConfiguration struct {
	APIVersion   string            `json:"apiVersion"`
	Name         string            `json:"name"`
	Workflow     string            `json:"workflow"`
	PublicConfig map[string]any    `json:"publicConfig,omitempty"`
	SecretFiles  map[string]string `json:"secretFiles,omitempty"`
}

type composeDocument struct {
	Services map[string]composeService `yaml:"services"`
	Volumes  map[string]externalObject `yaml:"volumes"`
	Networks map[string]externalObject `yaml:"networks"`
}

type externalObject struct {
	External bool   `yaml:"external"`
	Name     string `yaml:"name"`
}

type composeService struct {
	Image           string            `yaml:"image"`
	User            string            `yaml:"user"`
	Environment     map[string]string `yaml:"environment,omitempty"`
	Networks        []string          `yaml:"networks"`
	Volumes         []composeMount    `yaml:"volumes"`
	ReadOnly        bool              `yaml:"read_only"`
	CapDrop         []string          `yaml:"cap_drop"`
	SecurityOpt     []string          `yaml:"security_opt"`
	Tmpfs           []string          `yaml:"tmpfs"`
	Restart         string            `yaml:"restart"`
	Init            bool              `yaml:"init"`
	PidsLimit       int               `yaml:"pids_limit"`
	CPUs            string            `yaml:"cpus"`
	MemLimit        string            `yaml:"mem_limit"`
	StopGracePeriod string            `yaml:"stop_grace_period"`
	Labels          map[string]string `yaml:"labels"`
	Logging         composeLogging    `yaml:"logging"`
}

type composeLogging struct {
	Driver  string            `yaml:"driver"`
	Options map[string]string `yaml:"options"`
}

type composeMount struct {
	Type     string             `yaml:"type"`
	Source   string             `yaml:"source"`
	Target   string             `yaml:"target"`
	ReadOnly bool               `yaml:"read_only,omitempty"`
	Volume   *composeVolumeSpec `yaml:"volume,omitempty"`
}

type composeVolumeSpec struct {
	Subpath string `yaml:"subpath"`
}

// Configurations renders one non-secret, read-only configuration file per
// producer. Private inputs are represented only by their fixed mount paths.
func Configurations(compiled manifest.Compiled) ([]ConfigFile, error) {
	if compiled.Version != manifest.APIVersion || len(compiled.Producers) > manifest.MaxItems {
		return nil, errors.New("compiled producer configuration is invalid")
	}
	producers := append([]manifest.ProducerIntent(nil), compiled.Producers...)
	sort.Slice(producers, func(i, j int) bool { return producers[i].Name < producers[j].Name })
	result := make([]ConfigFile, 0, len(producers))
	seen := map[string]struct{}{}
	for _, intent := range producers {
		if err := validateIntent(intent); err != nil {
			return nil, err
		}
		if _, duplicate := seen[intent.Name]; duplicate {
			return nil, errors.New("duplicate compiled producer")
		}
		seen[intent.Name] = struct{}{}
		var value any
		if intent.Kind == "github-comments" {
			value = githubConfiguration(intent)
		} else {
			secretFiles := map[string]string{}
			for _, name := range sortedNames(intent.Secrets) {
				secretFiles[name] = plancontract.PrivateTarget(intent.Secrets[name])
			}
			value = externalConfiguration{
				APIVersion: "nvt.dev/local-producer/v1", Name: intent.Name, Workflow: intent.Workflow,
				PublicConfig: intent.PublicConfig, SecretFiles: secretFiles,
			}
		}
		encoded, err := json.Marshal(value)
		if err != nil || len(encoded) == 0 || len(encoded) > manifest.MaxDocumentBytes {
			return nil, errors.New("producer configuration is unavailable")
		}
		result = append(result, ConfigFile{Name: "producers/" + intent.Name + ".json", Data: encoded})
	}
	return result, nil
}

func githubConfiguration(intent manifest.ProducerIntent) map[string]any {
	commandWorkflows := map[string]string{"pr-create": intent.Workflow, "review": intent.Workflow, "run": intent.Workflow}
	return map[string]any{
		"commandPrefixes": []string{intent.GitHub.Prefix},
		"allowedAuthors":  append([]string(nil), intent.GitHub.AllowedAuthors...),
		"repositories": []map[string]string{{
			"owner": intent.GitHub.RepositoryOwner, "name": intent.GitHub.RepositoryName,
		}},
		"githubApp": map[string]any{
			"appID": intent.GitHub.AppID, "installationID": intent.GitHub.InstallationID,
			"privateKeyPath": plancontract.PrivateTarget(intent.GitHub.PrivateKeySecret),
		},
		"state":        map[string]string{"sqlitePath": StatePath + "/state.db"},
		"pollInterval": "30s",
		"idempotency":  map[string]string{"scope": "issue"},
		"schedulingReactions": map[string]any{
			"enabled": true, "accepted": "+1", "rejected": "-1",
		},
		"submission": map[string]any{
			"mode": "scheduleAdmission", "backend": "local", "admissionMode": "profiled",
			"admissionBaseURL": defaultAdmissionBaseURL, "admissionTokenFile": plancontract.PrivateTarget(intent.AdmissionCredential),
			"scheduleNamespace": "unused", "scheduleName": intent.Name, "workflow": intent.Workflow, "commandWorkflows": commandWorkflows,
		},
		"agentRun": map[string]any{},
	}
}

// RenderCompose emits an independently reviewable producer-only Compose
// document. Every volume is selected from the exact redacted state plan.
func RenderCompose(compiled manifest.Compiled, statePlan plancontract.Plan, options Options) ([]byte, error) {
	options = withDefaults(options, statePlan.Project)
	if err := validateOptions(options); err != nil || compiled.Version != manifest.APIVersion || statePlan.Version != "1" || !localProjectPattern.MatchString(statePlan.Project) {
		return nil, errors.New("producer renderer configuration is invalid")
	}
	if _, err := Configurations(compiled); err != nil {
		return nil, err
	}
	knownVolumes := map[string]plancontract.Volume{}
	for _, volume := range statePlan.Volumes {
		if volume.Name == "" || !validPlannedVolume(volume, statePlan.Project) {
			return nil, errors.New("producer state plan is invalid")
		}
		if _, duplicate := knownVolumes[volume.Name]; duplicate {
			return nil, errors.New("producer state plan has duplicate volumes")
		}
		knownVolumes[volume.Name] = volume
	}
	document := composeDocument{
		Services: map[string]composeService{}, Volumes: map[string]externalObject{},
		Networks: map[string]externalObject{
			"local-control-plane": {External: true, Name: options.ControlNetwork},
			"producer-egress":     {External: true, Name: options.EgressNetwork},
		},
	}
	expectedServices := map[string]struct{}{}
	for _, intent := range compiled.Producers {
		serviceID := "producer:" + intent.Name
		expectedServices[serviceID] = struct{}{}
		mounts := producerMounts(statePlan.Mounts, serviceID)
		if err := validateMounts(intent, mounts, knownVolumes, statePlan.Project); err != nil {
			return nil, err
		}
		image := intent.Image
		environment := map[string]string{
			"NVT_PRODUCER_CONFIG_FILE":          ConfigPath,
			"NVT_SCHEDULE_ADMISSION_URL":        admissionURL(defaultAdmissionBaseURL, intent.Name),
			"NVT_SCHEDULE_ADMISSION_TOKEN_FILE": plancontract.PrivateTarget(intent.AdmissionCredential),
		}
		if intent.Kind == "github-comments" {
			image = options.GitHubCommentsImage
			environment = map[string]string{"NVT_GITHUB_COMMENTS_CONFIG": ConfigPath}
		}
		composeMounts := make([]composeMount, 0, len(mounts))
		for _, mount := range mounts {
			entry := composeMount{Type: "volume", Source: mount.Volume, Target: mount.Target, ReadOnly: mount.ReadOnly}
			if mount.Subpath != "" {
				entry.Volume = &composeVolumeSpec{Subpath: mount.Subpath}
			}
			composeMounts = append(composeMounts, entry)
			document.Volumes[mount.Volume] = externalObject{External: true, Name: mount.Volume}
		}
		key := "producer-" + intent.Name
		if _, duplicate := document.Services[key]; duplicate {
			return nil, errors.New("duplicate producer service")
		}
		document.Services[key] = composeService{
			Image: image, User: strconv.Itoa(intent.RuntimeIdentity.UID) + ":" + strconv.Itoa(intent.RuntimeIdentity.GID),
			Environment: environment, Networks: []string{"local-control-plane", "producer-egress"}, Volumes: composeMounts,
			ReadOnly: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
			Tmpfs: []string{"/tmp:rw,noexec,nosuid,nodev,size=16m"}, Restart: "unless-stopped", Init: true,
			PidsLimit: 128, CPUs: "1.0", MemLimit: "256m", StopGracePeriod: "30s",
			Labels:  map[string]string{"nvt.dev/local-platform-owner": statePlan.Project, "nvt.dev/local-producer": intent.Name},
			Logging: composeLogging{Driver: "json-file", Options: map[string]string{"max-file": "3", "max-size": "10m"}},
		}
	}
	for _, mount := range statePlan.Mounts {
		if strings.HasPrefix(mount.Service, "producer:") {
			if _, exists := expectedServices[mount.Service]; !exists {
				return nil, errors.New("producer state plan contains an undeclared service")
			}
		}
	}
	encoded, err := yaml.Marshal(document)
	if err != nil || len(encoded) > 512<<10 {
		return nil, errors.New("producer compose rendering failed")
	}
	return encoded, nil
}

func validateIntent(intent manifest.ProducerIntent) error {
	if intent.Name == "" || intent.Owner != "producer:"+intent.Name || intent.Workflow == "" || intent.AdmissionCredential != "producer-admission:"+intent.Name ||
		intent.RuntimeIdentity.UID <= 0 || intent.RuntimeIdentity.UID > 1<<31-1 || intent.RuntimeIdentity.GID <= 0 || intent.RuntimeIdentity.GID > 1<<31-1 ||
		!localNamePattern.MatchString(intent.Name) || !workflowNamePattern.MatchString(intent.Workflow) {
		return errors.New("compiled producer intent is invalid")
	}
	switch intent.Kind {
	case "github-comments":
		if intent.Image != "" || intent.GitHub == nil || intent.GitHub.AppID <= 0 || intent.GitHub.InstallationID <= 0 ||
			intent.GitHub.PrivateKeySecret == "" || intent.GitHub.RepositoryOwner == "" || intent.GitHub.RepositoryName == "" || intent.GitHub.Prefix == "" ||
			len(intent.Secrets) != 0 || len(intent.PublicConfig) != 0 {
			return errors.New("compiled GitHub producer intent is invalid")
		}
	case "oci":
		if intent.GitHub != nil || !immutableImage(intent.Image) {
			return errors.New("compiled external producer intent is invalid")
		}
	default:
		return errors.New("compiled producer kind is invalid")
	}
	return nil
}

func validateMounts(intent manifest.ProducerIntent, mounts []plancontract.Mount, volumes map[string]plancontract.Volume, project string) error {
	type expectedMount struct {
		readOnly bool
		volume   string
	}
	service := "producer:" + intent.Name
	expected := map[string]expectedMount{
		ConfigPath: {readOnly: true, volume: plancontract.VolumeName(project, plancontract.GeneratedConfigSuffix)},
		plancontract.PrivateTarget(intent.AdmissionCredential): {
			readOnly: true, volume: plancontract.VolumeName(project, plancontract.GeneratedInputSuffix(intent.AdmissionCredential, service)),
		},
	}
	if intent.Kind == "github-comments" {
		expected[plancontract.PrivateTarget(intent.GitHub.PrivateKeySecret)] = expectedMount{
			readOnly: true, volume: plancontract.VolumeName(project, plancontract.StaticInputSuffix(service, intent.GitHub.PrivateKeySecret)),
		}
		expected[StatePath] = expectedMount{volume: plancontract.VolumeName(project, plancontract.ProducerStateSuffix(intent.Name))}
	} else {
		for _, secret := range intent.Secrets {
			expected[plancontract.PrivateTarget(secret)] = expectedMount{
				readOnly: true, volume: plancontract.VolumeName(project, plancontract.StaticInputSuffix(service, secret)),
			}
		}
	}
	seen := map[string]struct{}{}
	for _, mount := range mounts {
		planned, ok := expected[mount.Target]
		volume, volumeOK := volumes[mount.Volume]
		if !ok || !volumeOK || mount.ReadOnly != planned.readOnly || mount.Volume != planned.volume || mount.Target == "" ||
			!validProducerVolume(volume, mount, intent, project) {
			return errors.New("producer mount plan exceeds compiled intent")
		}
		if _, duplicate := seen[mount.Target]; duplicate {
			return errors.New("duplicate producer mount target")
		}
		seen[mount.Target] = struct{}{}
		if mount.Target == ConfigPath && mount.Subpath != "current/producers/"+intent.Name+".json" ||
			mount.Target != ConfigPath && mount.Target != StatePath && mount.Subpath != "current/value" ||
			mount.Target == StatePath && mount.Subpath != "" {
			return errors.New("producer mount subpath is invalid")
		}
	}
	if len(seen) != len(expected) {
		return errors.New("producer mount plan is incomplete")
	}
	return nil
}

func producerMounts(mounts []plancontract.Mount, service string) []plancontract.Mount {
	result := []plancontract.Mount{}
	for _, mount := range mounts {
		if mount.Service == service {
			result = append(result, mount)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Target != result[j].Target {
			return result[i].Target < result[j].Target
		}
		return result[i].Volume < result[j].Volume
	})
	return result
}

func immutableImage(value string) bool {
	named, err := reference.ParseNormalizedNamed(value)
	if err != nil || strings.Contains(value, "//") || strings.ContainsAny(value, " \t\r\n?#") {
		return false
	}
	canonical, ok := named.(reference.Canonical)
	return ok && canonical.Digest().Algorithm().String() == "sha256" && len(canonical.Digest().Encoded()) == 64
}

func withDefaults(options Options, project string) Options {
	if options.ControlNetwork == "" {
		options.ControlNetwork = project + "_" + defaultControlNetwork
	}
	if options.EgressNetwork == "" {
		options.EgressNetwork = project + "_" + defaultEgressNetwork
	}
	if options.GitHubCommentsImage == "" {
		options.GitHubCommentsImage = defaultGitHubImage
	}
	return options
}

func validateOptions(options Options) error {
	if strings.ContainsAny(options.ControlNetwork+options.EgressNetwork+options.GitHubCommentsImage, "\x00\r\n") ||
		!networkNamePattern.MatchString(options.ControlNetwork) || !networkNamePattern.MatchString(options.EgressNetwork) ||
		options.ControlNetwork == options.EgressNetwork || options.GitHubCommentsImage == "" {
		return errors.New("producer renderer options are invalid")
	}
	if _, err := reference.ParseNormalizedNamed(options.GitHubCommentsImage); err != nil {
		return errors.New("producer renderer options are invalid")
	}
	return nil
}

func admissionURL(baseURL, name string) string {
	return strings.TrimRight(baseURL, "/") + "/v1/schedules/" + url.PathEscape(name) + "/admissions"
}

func sortedNames[V any](values map[string]V) []string {
	result := make([]string, 0, len(values))
	for name := range values {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

var (
	localNamePattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$`)
	workflowNamePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
)
var localProjectPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)
var networkNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func validPlannedVolume(volume plancontract.Volume, project string) bool {
	return volume.Labels["nvt.dev/local-platform-owner"] == project &&
		volume.Labels["nvt.dev/local-platform-custodian"] == volume.Owner &&
		volume.Labels["nvt.dev/local-platform-role"] == volume.Role &&
		volume.Labels["nvt.dev/local-platform-volume"] == volume.Name &&
		volume.Labels["nvt.dev/local-platform-version"] == "1"
}

func validProducerVolume(volume plancontract.Volume, mount plancontract.Mount, intent manifest.ProducerIntent, project string) bool {
	service := "producer:" + intent.Name
	if !validPlannedVolume(volume, project) || !contains(volume.Consumers, service) {
		return false
	}
	switch mount.Target {
	case ConfigPath:
		return volume.Role == "generated-config" && volume.Owner == "local-platform-state"
	case StatePath:
		return volume.Role == "producer-state" && volume.Owner == service && len(volume.Consumers) == 1
	case plancontract.PrivateTarget(intent.AdmissionCredential):
		return volume.Role == "generated-private-input" && volume.Owner == "local-platform-state" && len(volume.Consumers) == 1
	default:
		return volume.Role == "static-private-input" && volume.Owner == service && len(volume.Consumers) == 1
	}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
