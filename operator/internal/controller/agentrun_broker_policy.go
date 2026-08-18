package controller

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

func agentRunLabels(agentRunName string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "nvt-agent",
		"app.kubernetes.io/component": "agentrun",
		agentRunLabelKey:              agentRunName,
	}
}

// GenerateToken returns a URL-safe token with 256 bits of cryptographic entropy.
func GenerateToken(reader io.Reader) (string, error) {
	randomBytes := make([]byte, generatedTokenByteLength)
	if _, err := io.ReadFull(reader, randomBytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

// BrokerTokenHash returns the broker policy hash for a raw token.
func BrokerTokenHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BrokerAgentGrants converts AgentRun grants into broker policy grants.
func BrokerAgentGrants(broker *nvtv1alpha1.AgentRunBroker) []brokerAgentGrantEntry {
	if broker == nil || broker.Grants == nil {
		return []brokerAgentGrantEntry{}
	}

	grants := make([]brokerAgentGrantEntry, 0, len(broker.Grants))
	for _, grant := range broker.Grants {
		repositories := []string{}
		if grant.Repositories != nil {
			repositories = append(repositories, grant.Repositories...)
		}
		var permissions map[string]string
		if len(grant.Permissions) > 0 {
			permissions = make(map[string]string, len(grant.Permissions))
			for key, value := range grant.Permissions {
				permissions[key] = value
			}
		}
		var quota *brokerAgentQuota
		if grant.Quota != nil {
			quota = &brokerAgentQuota{Requests: grant.Quota.Requests}
		}
		grants = append(grants, brokerAgentGrantEntry{
			Provider:        grant.Provider,
			Repositories:    repositories,
			Materialization: string(AgentRunGrantMaterialization(grant)),
			EgressHosts:     append([]string{}, grant.EgressHosts...),
			Permissions:     permissions,
			Authorization:   grant.Authorization.DeepCopy(),
			Quota:           quota,
		})
	}
	sort.SliceStable(grants, func(i, j int) bool {
		if grants[i].Provider != grants[j].Provider {
			return grants[i].Provider < grants[j].Provider
		}
		if grants[i].Materialization != grants[j].Materialization {
			return grants[i].Materialization < grants[j].Materialization
		}
		return stringsLess(grants[i].Repositories, grants[j].Repositories)
	})

	return grants
}

// ParseBrokerAgentsYAML parses broker agents policy YAML.
func ParseBrokerAgentsYAML(raw string) (brokerAgentsPolicy, error) {
	if raw == "" {
		raw = "agents: []"
	}

	var policy brokerAgentsPolicy
	if err := yaml.Unmarshal([]byte(raw), &policy); err != nil {
		return brokerAgentsPolicy{}, err
	}
	if policy.Agents == nil {
		policy.Agents = []brokerAgentEntry{}
	}
	normalizeBrokerAgentsPolicy(&policy)

	return policy, nil
}

// RenderBrokerAgentsYAML renders deterministic broker agents policy YAML.
func RenderBrokerAgentsYAML(policy brokerAgentsPolicy) (string, error) {
	normalizeBrokerAgentsPolicy(&policy)
	if err := ValidateBrokerAgentsPolicy(policy); err != nil {
		return "", err
	}
	rendered, err := yaml.Marshal(policy)
	if err != nil {
		return "", err
	}
	return string(rendered), nil
}

// UpsertBrokerAgent inserts or replaces one broker agent entry.
func UpsertBrokerAgent(policy brokerAgentsPolicy, entry brokerAgentEntry) brokerAgentsPolicy {
	normalizeBrokerAgentEntry(&entry)
	agents := make([]brokerAgentEntry, 0, len(policy.Agents)+1)
	for i := range policy.Agents {
		if policy.Agents[i].ID == entry.ID {
			continue
		}
		agents = append(agents, policy.Agents[i])
	}
	agents = append(agents, entry)
	policy.Agents = agents
	normalizeBrokerAgentsPolicy(&policy)
	return policy
}

// RemoveBrokerAgent removes one broker agent entry by id.
func RemoveBrokerAgent(policy brokerAgentsPolicy, id string) brokerAgentsPolicy {
	agents := make([]brokerAgentEntry, 0, len(policy.Agents))
	for _, agent := range policy.Agents {
		if agent.ID == id {
			continue
		}
		agents = append(agents, agent)
	}
	policy.Agents = agents
	normalizeBrokerAgentsPolicy(&policy)
	return policy
}

// ValidateBrokerAgentsPolicy checks the policy shape accepted by the broker.
func ValidateBrokerAgentsPolicy(policy brokerAgentsPolicy) error {
	seenIDs := map[string]struct{}{}
	seenHashes := map[string]string{}
	pairedAgents := map[string]string{}
	for agentIndex, agent := range policy.Agents {
		if agent.ID == "" {
			return fmt.Errorf("agents[%d].id is required", agentIndex)
		}
		if _, exists := seenIDs[agent.ID]; exists {
			return fmt.Errorf("duplicate agent id: %s", agent.ID)
		}
		seenIDs[agent.ID] = struct{}{}
		if !validBrokerTokenHash(agent.TokenSHA256) {
			return fmt.Errorf("agents[%d].token-sha256 must be sha256:<hex>", agentIndex)
		}
		if existingID, exists := seenHashes[agent.TokenSHA256]; exists {
			return fmt.Errorf("duplicate token hash for agents %s and %s", existingID, agent.ID)
		}
		seenHashes[agent.TokenSHA256] = agent.ID
		switch agent.Role {
		case "", "agent":
			if agent.PairedAgent != "" {
				return fmt.Errorf("agents[%d].paired-agent is valid only for egress identities", agentIndex)
			}
		case "egress":
			if agent.PairedAgent == "" {
				return fmt.Errorf("agents[%d].paired-agent is required for egress identities", agentIndex)
			}
			if existingEgress, exists := pairedAgents[agent.PairedAgent]; exists {
				return fmt.Errorf("agents[%d].paired-agent duplicates egress identity %s", agentIndex, existingEgress)
			}
			pairedAgents[agent.PairedAgent] = agent.ID
			if len(agent.Grants) != 0 {
				return fmt.Errorf("agents[%d].grants must be empty for egress identities", agentIndex)
			}
		default:
			return fmt.Errorf("agents[%d].role must be agent or egress", agentIndex)
		}
		for grantIndex, grant := range agent.Grants {
			if grant.Provider == "" {
				return fmt.Errorf("agents[%d].grants[%d].provider is required", agentIndex, grantIndex)
			}
			switch grant.Materialization {
			case "", string(nvtv1alpha1.AgentRunGrantFileBundle), string(nvtv1alpha1.AgentRunGrantHeaderInject), string(nvtv1alpha1.AgentRunGrantPlaceholderFile):
			default:
				return fmt.Errorf("agents[%d].grants[%d].materialization must be file-bundle, header-inject, or placeholder-file", agentIndex, grantIndex)
			}
			for repoIndex, repository := range grant.Repositories {
				if repository == "" {
					return fmt.Errorf("agents[%d].grants[%d].repositories[%d] must be a non-empty string", agentIndex, grantIndex, repoIndex)
				}
			}
			for hostIndex, host := range grant.EgressHosts {
				if !validEgressHost(host) {
					return fmt.Errorf("agents[%d].grants[%d].egress-hosts[%d] must be a host or host:port, got %q", agentIndex, grantIndex, hostIndex, host)
				}
			}
			for key, value := range grant.Permissions {
				if key == "" || (value != "read" && value != "write") {
					return fmt.Errorf("agents[%d].grants[%d].permissions must map permission names to read or write", agentIndex, grantIndex)
				}
			}
		}
	}
	for pairedAgent, egressID := range pairedAgents {
		if _, exists := seenIDs[pairedAgent]; !exists {
			return fmt.Errorf("egress identity %s paired-agent %s does not exist", egressID, pairedAgent)
		}
	}

	return nil
}

func validBrokerTokenHash(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	encoded := strings.TrimPrefix(value, "sha256:")
	if len(encoded) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(encoded)
	return err == nil
}

func normalizeBrokerAgentsPolicy(policy *brokerAgentsPolicy) {
	if policy.Agents == nil {
		policy.Agents = []brokerAgentEntry{}
	}
	for i := range policy.Agents {
		normalizeBrokerAgentEntry(&policy.Agents[i])
	}
	sort.SliceStable(policy.Agents, func(i, j int) bool {
		return policy.Agents[i].ID < policy.Agents[j].ID
	})
}

func normalizeBrokerAgentEntry(entry *brokerAgentEntry) {
	if entry.Grants == nil {
		entry.Grants = []brokerAgentGrantEntry{}
	}
	for i := range entry.Grants {
		if entry.Grants[i].Repositories == nil {
			entry.Grants[i].Repositories = []string{}
		}
		if entry.Grants[i].EgressHosts == nil {
			entry.Grants[i].EgressHosts = []string{}
		}
		if entry.Grants[i].Materialization == "" {
			entry.Grants[i].Materialization = string(nvtv1alpha1.AgentRunGrantFileBundle)
		}
	}
	sort.SliceStable(entry.Grants, func(i, j int) bool {
		if entry.Grants[i].Provider != entry.Grants[j].Provider {
			return entry.Grants[i].Provider < entry.Grants[j].Provider
		}
		if entry.Grants[i].Materialization != entry.Grants[j].Materialization {
			return entry.Grants[i].Materialization < entry.Grants[j].Materialization
		}
		return stringsLess(entry.Grants[i].Repositories, entry.Grants[j].Repositories)
	})
}

func stringsLess(left, right []string) bool {
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i] != right[i] {
			return left[i] < right[i]
		}
	}
	return len(left) < len(right)
}
