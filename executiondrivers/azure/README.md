# Azure execution driver

This directory contains NVT's first production-shaped external-VM execution
driver. It is a standalone Go implementation of `nvt.execution-driver/v1` and
the protected guest-enrollment handoff. Azure-specific code and durable state
remain here; the operator, agentd, runtime, broker, producers, and portable
contracts contain no Azure branches.

The coordinated image is `nvt-azure-execution-driver`. Installations must pin
its OCI digest and register it through the execution-driver host. The driver
uses only `azidentity.WorkloadIdentityCredential`, requiring exactly
`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and
`AZURE_FEDERATED_TOKEN_FILE`. It deliberately does not use
`DefaultAzureCredential`, Azure CLI, a client secret, or a guest managed
identity. The registration PVC holds bounded convergence metadata and the
temporary bootstrap key; it must use `Recreate` and must not be shared. The
configured state path is the volume root. The non-root driver creates and owns
only its `azure/` child, leaving the root-owned, fsGroup-writable PVC mount
unchanged.

The strict administrator-owned class configuration is versioned as
`nvt.azure-driver/v1`:

```json
{
  "contract_version": "nvt.azure-driver/v1",
  "subscription_id": "11111111-1111-4111-8111-111111111111",
  "resource_group": "nvt-agents",
  "location": "westeurope",
  "subnet_resource_id": "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/nvt-network/providers/Microsoft.Network/virtualNetworks/nvt-vnet/subnets/agents",
  "vm_image_resource_id": "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/nvt-images/providers/Microsoft.Compute/galleries/nvtgallery/images/nvtguest/versions/1.2.3",
  "guest_architecture": "amd64",
  "vm_size": "Standard_D2s_v5",
  "os_disk": {"size_gib": 64, "storage_account_type": "Premium_LRS"},
  "host_bundle": {"repository": "https://ghcr.io/example/nvt-host-bundle", "digest": "sha256:<64-lowercase-hex>"},
  "enrollment_endpoint": "https://broker.example:7347",
  "enrollment_ca_pem": "<public enrollment CA PEM>",
  "native_session_endpoint": "tls://gateway.example:7443",
  "native_session_ca_pem": "<public gateway CA PEM>",
  "ssh_host_public_key": "ssh-ed25519 <immutable image host key>",
  "network": {"driver_source_cidr": "10.40.0.0/24", "dns_server": "168.63.129.16"},
  "bootstrap_timeout_seconds": 90
}
```

The image reference must be an exact Azure Compute Gallery image *version*;
definitions, `latest`, marketplace aliases, custom data, public-IP settings,
and unknown fields are rejected before Azure mutation. The immutable image
must provide the fixed root-owned
`/usr/local/libexec/nvt-azure-bootstrap-receiver` SSH command and the public
host key selected above. The driver copies the repository-owned
`nvt-host-bootstrap` input over that fixed channel, then installs the selected
host bundle by exact OCI digest. The one-time enrollment envelope is written
only to SSH stdin. It never enters ARM, Bicep, tags, state JSON, command lines,
environment, or status.

`deployment.bicep` defines one NSG, NIC, managed OS disk, and VM with no public
IP and no VM identity. The generalized gallery image is applied through the
VM's `imageReference`; its named OS disk is created `FromImage`, never attached
as a specialized disk while an `osProfile` is present. CI recompiles the
template with the pinned Bicep compiler and
compares it byte-for-byte with the embedded ARM JSON. Runtime uses the Azure Go
SDK to submit an incremental resource-group deployment; the image contains no
Azure CLI, Bicep, Terraform, shell, Git, or package manager. Every owned
resource and the deployment record are identified and read back by exact ID
plus the stable execution/generation tags before adoption or deletion. Azure
resource-ID comparisons are uniformly case-insensitive. An exact-owned stopped
or deallocated VM is recovered through the Azure Start long-running operation
and authoritative readback rather than deployment replay alone.

For a portable native-egress attachment, the driver resolves its bounded
relay/bootstrap/control DNS names once per execution through the same explicit
DNS server configured on the VM NIC, validates every returned address, and
programs their exact IPv4 addresses into the per-run NSG. A higher-priority deny-all rule prevents
the Azure default Internet/VNet rules from providing a bypass; explicit
`AzurePlatformIMDS`, `AzurePlatformLKM`, and `AzurePlatformDNS` deny rules cover
platform traffic that ordinary NSG rules do not override, while the selected
DNS server remains allowed only on TCP/UDP 53. Enrollment is unavailable until
that infrastructure-owned bootstrap fence is read back.
After acceptance the driver locks the bootstrap account, removes the SSH and
one-time registry allowance, erases the private key, and reports the exact
current attachment confinement only after steady-fence readback. The configured
broker remains pinned because runtime/session/egress identity rotation requires
it. The guest redirect is routing plumbing and is never accepted as the
security boundary. Direct mode is explicit and retains Azure's ordinary
outbound model.

Deletion is level-triggered. It verifies the complete remaining ownership
graph before the first destructive operation, rechecks each object immediately
before deletion, and confirms VM, disk, NIC, NSG, and deployment record are all
absent before removing local state. The driver never deletes the shared
resource group, subnet, image, workload identity, or other infrastructure.

## Deployment and selection boundary

This PR publishes the digest-pinned driver image but deliberately adds no Azure
values, validation, Deployment, ServiceAccount, PVC, or Workload Identity
branch to the provider-neutral `nvt` chart or operator. A following deployment
PR must provide a separate `nvt-execution-driver-azure` chart (or Azure-owned
manifests) for those provider-specific resources. It must also supply the
resource group/subnet fence, immutable image, UAMI/federated identity, custom
role, and public relay ingress. The core chart must remain unaware of those
details.

Registration alone must not make Azure producer-selectable. The required
admission follow-up separates administrator-owned execution-profile selection
from workflow and authentication profiles. A request may then carry only a
bounded execution-profile name; server-side producer policy resolves an
allowlisted choice or fixed default to a provider-neutral `driverRef` and its
trusted class configuration. Subscription/resource-group IDs, VM sizes,
images, driver endpoints, and opaque Azure parameters remain impossible in
producer input. Policy may, for example, fix `github-comments` to `kata-pod`
and `vm-workstations` to `azure-standard` while authorizing only explicit
alternatives. Omitted selection continues to mean the built-in Kubernetes
Pod/Kata path. Until that reviewed integration lands, this PR adds no path by
which an untrusted producer request can select Azure.

CI uses pinned Bicep compilation plus fake ARM/LRO servers. It validates the
compiled resource graph but does not perform or claim a live Azure template
deployment proof. `real-smoke.sh` is an explicit opt-in driver lifecycle runner
for a prepared installation; it is not generic chart wiring.
