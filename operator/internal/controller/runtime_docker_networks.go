package controller

import (
	"encoding/json"
	"fmt"
	"net/netip"

	utilvalidation "k8s.io/apimachinery/pkg/util/validation"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

const (
	managedDockerNetworkPool  = "172.31.0.0/16"
	maxRequiredDockerNetworks = 16
)

// ValidateAgentRunDockerNetworks validates the bounded, IPv4-only Docker
// network contract. The explicit subnets are kept within the same managed pool
// that transparent DinD reserves for dynamically-created bridge networks.
func ValidateAgentRunDockerNetworks(agentRun *nvtv1alpha1.AgentRun) error {
	if agentRun == nil {
		return fmt.Errorf("AgentRun is required")
	}
	return validateRuntimeDockerNetworks(agentRun.Spec.Runtime)
}

func validateRuntimeDockerNetworks(runtime nvtv1alpha1.AgentRunRuntime) error {
	if runtime.Docker == nil {
		return nil
	}
	networks := runtime.Docker.RequiredNetworks
	if len(networks) > maxRequiredDockerNetworks {
		return fmt.Errorf("runtime.docker.requiredNetworks supports at most %d entries", maxRequiredDockerNetworks)
	}
	pool := netip.MustParsePrefix(managedDockerNetworkPool)
	names := make(map[string]struct{}, len(networks))
	subnets := make(map[netip.Prefix]struct{}, len(networks))
	for i, network := range networks {
		if problems := utilvalidation.IsDNS1123Label(network.Name); len(problems) != 0 {
			return fmt.Errorf("runtime.docker.requiredNetworks[%d].name must be a DNS label", i)
		}
		if _, exists := names[network.Name]; exists {
			return fmt.Errorf("runtime.docker.requiredNetworks name %q is duplicated", network.Name)
		}
		names[network.Name] = struct{}{}

		subnet, err := netip.ParsePrefix(network.Subnet)
		if err != nil || !subnet.Addr().Is4() || subnet.Bits() != 24 || subnet != subnet.Masked() || !pool.Contains(subnet.Addr()) {
			return fmt.Errorf("runtime.docker.requiredNetworks[%d].subnet must be a canonical IPv4 /24 within %s", i, managedDockerNetworkPool)
		}
		if _, exists := subnets[subnet]; exists {
			return fmt.Errorf("runtime.docker.requiredNetworks subnet %q is duplicated", network.Subnet)
		}
		subnets[subnet] = struct{}{}
	}
	return nil
}

// AgentRunDockerKernelLogDevice reports the administrator-owned, profile-owned
// intent to expose the kernel-log character device to the Docker sidecar. It is
// opt-in and defaults to false, so omitting it preserves existing behavior.
func AgentRunDockerKernelLogDevice(agentRun *nvtv1alpha1.AgentRun) bool {
	if agentRun == nil || agentRun.Spec.Runtime.Docker == nil {
		return false
	}
	return agentRun.Spec.Runtime.Docker.KernelLogDevice
}

func requiredDockerNetworksJSON(agentRun *nvtv1alpha1.AgentRun) (string, error) {
	if err := ValidateAgentRunDockerNetworks(agentRun); err != nil {
		return "", err
	}
	if agentRun.Spec.Runtime.Docker == nil || len(agentRun.Spec.Runtime.Docker.RequiredNetworks) == 0 {
		return "", nil
	}
	encoded, err := json.Marshal(agentRun.Spec.Runtime.Docker.RequiredNetworks)
	if err != nil {
		return "", fmt.Errorf("encode runtime.docker.requiredNetworks: %w", err)
	}
	return string(encoded), nil
}
