package manifest

import (
	"bytes"
	"encoding/json"
	"sort"
)

// Compiled is deterministic, secret-free intent for the later renderer slices.
// Each section names its sole output owner; it is not a runtime protocol.
type Compiled struct {
	Version       string               `json:"version"`
	Broker        BrokerIntent         `json:"broker"`
	Controller    ControllerIntent     `json:"localController"`
	Gateway       GatewayIntent        `json:"gateway"`
	Producers     []ProducerIntent     `json:"producers,omitempty"`
	PrivateInputs []PrivateInputIntent `json:"privateInputs,omitempty"`
}

type BrokerIntent struct {
	Owner        string                   `json:"owner"`
	Accounts     []NamedAccount           `json:"accounts,omitempty"`
	Profiles     []BrokerProfileIntent    `json:"profiles"`
	Repositories []BrokerRepositoryIntent `json:"repositories"`
}
type ControllerIntent struct {
	Owner        string                       `json:"owner"`
	Profiles     []ControllerProfileIntent    `json:"profiles"`
	Repositories []ControllerRepositoryIntent `json:"repositories"`
	Workstations []Workstation                `json:"workstations,omitempty"`
	Workflows    []NamedWorkflow              `json:"workflows"`
}
type GatewayIntent struct {
	Owner        string   `json:"owner"`
	Workstations []string `json:"workstations,omitempty"`
}
type ProducerIntent struct {
	Owner    string                `json:"owner"`
	Name     string                `json:"name"`
	Kind     string                `json:"kind"`
	Image    string                `json:"image,omitempty"`
	Workflow string                `json:"workflow"`
	Config   map[string]any        `json:"config,omitempty"`
	Secrets  map[string]string     `json:"secrets,omitempty"`
	GitHub   *GitHubProducerIntent `json:"github,omitempty"`
}
type GitHubProducerIntent struct {
	AppID            int64    `json:"appID"`
	InstallationID   int64    `json:"installationID"`
	PrivateKeySecret string   `json:"privateKeySecret"`
	RepositoryOwner  string   `json:"repositoryOwner"`
	RepositoryName   string   `json:"repositoryName"`
	Prefix           string   `json:"prefix"`
	AllowedAuthors   []string `json:"allowedAuthors"`
}
type PrivateInputIntent struct{ Owner, Name, File, Purpose string }

func (p PrivateInputIntent) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Owner   string `json:"owner"`
		Name    string `json:"name"`
		File    string `json:"file"`
		Purpose string `json:"purpose"`
	}{p.Owner, p.Name, p.File, p.Purpose})
}

type NamedAccount struct {
	Name    string  `json:"name"`
	Account Account `json:"account"`
}
type BrokerProfileIntent struct {
	Name     string   `json:"name"`
	Accounts []string `json:"accounts,omitempty"`
}
type ControllerProfileIntent struct {
	Name    string  `json:"name"`
	Profile Profile `json:"profile"`
}
type BrokerRepositoryIntent struct {
	Name             string `json:"name"`
	BrokerRepository string `json:"brokerRepository,omitempty"`
	Account          string `json:"account,omitempty"`
}
type ControllerRepositoryIntent struct {
	Name             string `json:"name"`
	URL              string `json:"url"`
	CheckoutTarget   string `json:"checkoutTarget"`
	BrokerRepository string `json:"brokerRepository,omitempty"`
	Path             string `json:"path,omitempty"`
	Upstream         string `json:"upstream,omitempty"`
	Account          string `json:"account,omitempty"`
}
type NamedWorkflow struct {
	Name     string   `json:"name"`
	Workflow Workflow `json:"workflow"`
}

// Compile normalizes every unordered collection and returns only references to
// private inputs. It never reads files or embeds secret material.
func Compile(m Manifest) (Compiled, error) {
	if err := m.Validate(); err != nil {
		return Compiled{}, err
	}
	result := Compiled{Version: APIVersion, Broker: BrokerIntent{Owner: "broker", Profiles: []BrokerProfileIntent{}, Repositories: []BrokerRepositoryIntent{}}, Controller: ControllerIntent{Owner: "local-controller", Profiles: []ControllerProfileIntent{}, Repositories: []ControllerRepositoryIntent{}, Workflows: []NamedWorkflow{}}, Gateway: GatewayIntent{Owner: "gateway"}}
	for _, name := range SortedNames(m.Accounts) {
		account := m.Accounts[name]
		account.Installations = sortedMap(account.Installations)
		result.Broker.Accounts = append(result.Broker.Accounts, NamedAccount{name, account})
	}
	for _, name := range SortedNames(m.Profiles) {
		profile := m.Profiles[name]
		profile.Accounts = append([]string(nil), profile.Accounts...)
		profile.Tools.Packages = append([]string(nil), profile.Tools.Packages...)
		profile.Tools.Mise = append([]string(nil), profile.Tools.Mise...)
		profile.Capabilities = append([]string(nil), profile.Capabilities...)
		profile.Plugins = append([]string(nil), profile.Plugins...)
		sort.Strings(profile.Accounts)
		sort.Strings(profile.Tools.Packages)
		sort.Strings(profile.Tools.Mise)
		sort.Strings(profile.Capabilities)
		sort.Strings(profile.Plugins)
		result.Broker.Profiles = append(result.Broker.Profiles, BrokerProfileIntent{name, append([]string(nil), profile.Accounts...)})
		result.Controller.Profiles = append(result.Controller.Profiles, ControllerProfileIntent{name, profile})
	}
	for _, name := range SortedNames(m.Repositories) {
		repository := compileRepository(name, m.Repositories[name])
		result.Controller.Repositories = append(result.Controller.Repositories, repository)
		result.Broker.Repositories = append(result.Broker.Repositories, BrokerRepositoryIntent{name, repository.BrokerRepository, repository.Account})
	}
	result.Controller.Workstations = append([]Workstation(nil), m.Workstations...)
	for i := range result.Controller.Workstations {
		result.Controller.Workstations[i].Repositories = append([]string(nil), result.Controller.Workstations[i].Repositories...)
		sort.Strings(result.Controller.Workstations[i].Repositories)
	}
	sort.Slice(result.Controller.Workstations, func(i, j int) bool {
		return result.Controller.Workstations[i].Name < result.Controller.Workstations[j].Name
	})
	for _, name := range SortedNames(m.Workflows) {
		result.Controller.Workflows = append(result.Controller.Workflows, NamedWorkflow{name, m.Workflows[name]})
	}
	for _, workstation := range result.Controller.Workstations {
		result.Gateway.Workstations = append(result.Gateway.Workstations, workstation.Name)
	}
	producers := append([]Producer(nil), m.Producers...)
	sort.Slice(producers, func(i, j int) bool { return producers[i].Name < producers[j].Name })
	for _, producer := range producers {
		intent := ProducerIntent{Owner: "producer:" + producer.Name, Name: producer.Name, Kind: producer.Preset, Image: producer.Image, Workflow: producer.Workflow, Config: producer.Config, Secrets: sortedMap(producer.Secrets)}
		if producer.Preset == "github-comments" {
			account := m.Accounts[producer.Account]
			owner, repository, _ := githubCoordinates(m.Repositories[producer.Repository])
			appID, _ := positiveID(account.AppID)
			installationID, _ := githubInstallationID(account, owner)
			authors := append([]string(nil), producer.AllowedAuthors...)
			sort.Strings(authors)
			intent.GitHub = &GitHubProducerIntent{appID, installationID, account.PrivateKeySecret, owner, repository, producer.Prefix, authors}
		}
		if intent.Kind == "" {
			intent.Kind = "oci"
		}
		result.Producers = append(result.Producers, intent)
	}
	for _, name := range SortedNames(m.Accounts) {
		account := m.Accounts[name]
		for _, secretName := range []string{account.PrivateKeySecret, account.TokenSecret} {
			if secretName != "" {
				result.PrivateInputs = append(result.PrivateInputs, PrivateInputIntent{"broker", secretName, m.Secrets[secretName].File, "secret"})
			}
		}
	}
	for _, name := range SortedNames(m.Profiles) {
		if ref := m.Profiles[name].Instructions; ref != nil {
			result.PrivateInputs = append(result.PrivateInputs, PrivateInputIntent{"local-controller", name, ref.File, "instructions"})
		}
	}
	for _, producer := range producers {
		if producer.Preset == "github-comments" {
			account := m.Accounts[producer.Account]
			result.PrivateInputs = append(result.PrivateInputs, PrivateInputIntent{"producer:" + producer.Name, account.PrivateKeySecret, m.Secrets[account.PrivateKeySecret].File, "github-app-private-key"})
		}
		for _, mountName := range SortedNames(producer.Secrets) {
			secretName := producer.Secrets[mountName]
			result.PrivateInputs = append(result.PrivateInputs, PrivateInputIntent{"producer:" + producer.Name, secretName, m.Secrets[secretName].File, "secret:" + mountName})
		}
	}
	sort.Slice(result.PrivateInputs, func(i, j int) bool {
		a, b := result.PrivateInputs[i], result.PrivateInputs[j]
		if a.Owner != b.Owner {
			return a.Owner < b.Owner
		}
		if a.Purpose != b.Purpose {
			return a.Purpose < b.Purpose
		}
		return a.Name < b.Name
	})
	return result, nil
}

func compileRepository(name string, repository Repository) ControllerRepositoryIntent {
	result := ControllerRepositoryIntent{Name: name, URL: repository.URL, CheckoutTarget: repository.CheckoutTarget, BrokerRepository: repository.BrokerRepository, Path: repository.Path, Upstream: repository.Upstream, Account: repository.Account}
	if repository.GitHub != "" {
		result.URL = "https://github.com/" + repository.GitHub + ".git"
		result.CheckoutTarget = "github.com/" + repository.GitHub
		if repository.Account != "" {
			result.BrokerRepository = repository.GitHub
		}
	}
	return result
}

func sortedMap[T any](input map[string]T) map[string]T {
	if input == nil {
		return nil
	}
	result := make(map[string]T, len(input))
	for _, key := range SortedNames(input) {
		result[key] = input[key]
	}
	return result
}

// CanonicalJSON is the stable serialization used for equality, hashing, and
// handoff to the private generated-config volume owned by later slices.
func (c Compiled) CanonicalJSON() ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(c); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}
