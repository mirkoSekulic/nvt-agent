package driver

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mirkoSekulic/nvt-agent/executiondrivers/azure/internal/config"
)

type resourcePlan struct {
	Prefix    string
	Resources ResourceIDs
}

func planFor(configuration config.Configuration, executionID string) resourcePlan {
	digest := sha256.Sum256([]byte("nvt.azure-resource/v1:" + executionID))
	prefix := "nvt-" + hex.EncodeToString(digest[:10])
	base := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers", configuration.SubscriptionID, configuration.ResourceGroup)
	return resourcePlan{Prefix: prefix, Resources: ResourceIDs{
		VM:         base + "/Microsoft.Compute/virtualMachines/" + prefix + "-vm",
		NIC:        base + "/Microsoft.Network/networkInterfaces/" + prefix + "-nic",
		OSDisk:     base + "/Microsoft.Compute/disks/" + prefix + "-os",
		NSG:        base + "/Microsoft.Network/networkSecurityGroups/" + prefix + "-nsg",
		Deployment: base + "/Microsoft.Resources/deployments/" + prefix,
	}}
}

func resourceName(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}
