package manifest

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// AzureAccess carries public identity/scope intent. The broker owns enrollment.
type AzureAccess struct {
	Provider      string                   `json:"provider"`
	Resources     []string                 `json:"resources"`
	Authorization *KubernetesAuthorization `json:"authorization,omitempty"`
}

var azureUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var azureARM = regexp.MustCompile(`^arm:/subscriptions/[0-9a-f-]{36}(/resourcegroups/[a-z0-9][a-z0-9_.()-]{0,127}(/providers/[a-z.]+/[a-z0-9][a-z0-9_.()-]{0,127}/[a-z0-9][a-z0-9_.()-]{0,127})?)?$`)

func azureResources(resources []string, tenant string) bool {
	if len(resources) == 0 || len(resources) > 256 || uniqueStrings(resources) != nil {
		return false
	}
	query, workspace := false, false
	for _, resource := range resources {
		switch {
		case resource == "query-identity/"+tenant:
			query = true
		case strings.HasPrefix(resource, "workspace/") && azureUUID.MatchString(strings.TrimPrefix(resource, "workspace/")):
			workspace = true
		case azureARM.MatchString(resource) && azureUUID.MatchString(strings.Split(resource, "/")[2]):
		default:
			return false
		}
	}
	return !(query && workspace)
}

func validateAzureProvider(provider BrokerProvider) error {
	invalid := errors.New("invalid Azure provider: require public tenant/subscriptions, explicit allow.resources and isolated broker enrollment")
	if len(provider.Secrets) != 0 || len(provider.Mediation.Hosts) != 0 || provider.Mediation.Materialization != "" || provider.Mediation.Git || provider.Mediation.Username != "" || provider.Mediation.TargetMode != "" {
		return invalid
	}
	for key := range provider.Config {
		if key != "tenant" && key != "subscriptions" && key != "cloud" {
			return invalid
		}
	}
	tenant, _ := provider.Config["tenant"].(string)
	if !azureUUID.MatchString(tenant) {
		return invalid
	}
	if cloud, ok := provider.Config["cloud"]; ok && cloud != "AzureCloud" {
		return invalid
	}
	subscriptions, ok := azureStringList(provider.Config["subscriptions"])
	if !ok || len(subscriptions) == 0 || len(subscriptions) > 256 || uniqueStrings(subscriptions) != nil {
		return invalid
	}
	for _, subscription := range subscriptions {
		if !azureUUID.MatchString(subscription) {
			return invalid
		}
	}
	for key := range provider.Allow {
		if key != "resources" && key != "authorization" {
			return invalid
		}
	}
	resources, ok := azureStringList(provider.Allow["resources"])
	if !ok || !azureResources(resources, tenant) {
		return invalid
	}
	for _, resource := range resources {
		if strings.HasPrefix(resource, "arm:") && !contains(subscriptions, strings.Split(resource, "/")[2]) {
			return invalid
		}
	}
	if raw, ok := provider.Allow["authorization"]; ok {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return invalid
		}
		var authorization KubernetesAuthorization
		if strictJSON(encoded, &authorization) != nil || validateKubernetesAuthorization(&authorization) != nil || authorization.Preset != "" {
			return invalid
		}
	}
	return nil
}

func azureStringList(value any) ([]string, bool) {
	if values, ok := value.([]string); ok {
		return values, true
	}
	values, ok := value.([]any)
	if !ok {
		return nil, false
	}
	result := make([]string, len(values))
	for index, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, false
		}
		result[index] = text
	}
	return result, true
}

func hasAzureAccess(profile Profile, provider string) bool {
	for _, access := range profile.Azure {
		if access.Provider == provider {
			return true
		}
	}
	return false
}

func validateAzureAccess(m Manifest, profile Profile) error {
	if len(profile.Azure) > 0 {
		for _, plugin := range profile.Plugins {
			if plugin.Name == "azure-cli" {
				return errors.New("Azure access generates the azure-cli plugin; do not configure it twice")
			}
		}
	}
	seen := map[string]bool{}
	for _, access := range profile.Azure {
		provider, ok := m.BrokerProviders[access.Provider]
		tenant, _ := provider.Config["tenant"].(string)
		if !ok || provider.Plugin != "azure" || seen[access.Provider] || !azureResources(access.Resources, tenant) || validateKubernetesAuthorization(access.Authorization) != nil {
			return errors.New("invalid Azure access")
		}
		seen[access.Provider] = true
	}
	return nil
}
