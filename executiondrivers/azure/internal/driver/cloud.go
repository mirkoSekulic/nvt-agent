package driver

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/mirkoSekulic/nvt-agent/executiondrivers/azure/internal/template"
	"github.com/mirkoSekulic/nvt-agent/operator/executiondriver"
)

const (
	azureTenantIDEnv  = "AZURE_TENANT_ID"
	azureClientIDEnv  = "AZURE_CLIENT_ID"
	azureTokenFileEnv = "AZURE_FEDERATED_TOKEN_FILE"
)

var RequiredWorkloadIdentityEnvironment = []string{azureTenantIDEnv, azureClientIDEnv, azureTokenFileEnv}

type CloudObservation struct {
	Exists         bool
	Exact          bool
	Running        bool
	PrivateIP      string
	SteadyFence    bool
	BootstrapFence bool
}

type Cloud interface {
	Deploy(context.Context, State, bool) error
	Observe(context.Context, State) (CloudObservation, error)
	Start(context.Context, State) error
	Delete(context.Context, State) error
}

type sdkCloud struct {
	resources       *armresources.Client
	deployments     *armresources.DeploymentsClient
	virtualMachines *armcompute.VirtualMachinesClient
	disks           *armcompute.DisksClient
}

func NewWorkloadIdentityCloud() (Cloud, error) {
	tenantID, clientID, tokenFile := os.Getenv(azureTenantIDEnv), os.Getenv(azureClientIDEnv), os.Getenv(azureTokenFileEnv)
	if tenantID == "" || clientID == "" || tokenFile == "" || !filepath.IsAbs(tokenFile) || filepath.Clean(tokenFile) != tokenFile {
		return nil, errors.New("Azure Workload Identity configuration is unavailable")
	}
	info, err := os.Stat(tokenFile)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 1<<20 {
		return nil, errors.New("Azure Workload Identity token projection is unavailable")
	}
	transport := &http.Client{Transport: &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
		ForceAttemptHTTP2: true, MaxIdleConns: 32, MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second,
	}}
	credential, err := azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
		TenantID: tenantID, ClientID: clientID, TokenFilePath: tokenFile,
		ClientOptions: azcore.ClientOptions{Transport: transport},
	})
	if err != nil {
		return nil, errors.New("Azure Workload Identity credential is unavailable")
	}
	return &multiplexCloud{credential: credential, options: &arm.ClientOptions{ClientOptions: azcore.ClientOptions{Transport: transport}}}, nil
}

type multiplexCloud struct {
	credential azcore.TokenCredential
	options    *arm.ClientOptions
	clients    sync.Map
}

func (cloud *multiplexCloud) client(subscriptionID string) (Cloud, error) {
	if value, found := cloud.clients.Load(subscriptionID); found {
		return value.(Cloud), nil
	}
	created, err := NewSDKCloud(subscriptionID, cloud.credential, cloud.options)
	if err != nil {
		return nil, err
	}
	actual, _ := cloud.clients.LoadOrStore(subscriptionID, created)
	return actual.(Cloud), nil
}
func (cloud *multiplexCloud) Deploy(ctx context.Context, state State, bootstrap bool) error {
	client, err := cloud.client(state.Configuration.SubscriptionID)
	if err != nil {
		return err
	}
	return client.Deploy(ctx, state, bootstrap)
}
func (cloud *multiplexCloud) Observe(ctx context.Context, state State) (CloudObservation, error) {
	client, err := cloud.client(state.Configuration.SubscriptionID)
	if err != nil {
		return CloudObservation{}, err
	}
	return client.Observe(ctx, state)
}
func (cloud *multiplexCloud) Start(ctx context.Context, state State) error {
	client, err := cloud.client(state.Configuration.SubscriptionID)
	if err != nil {
		return err
	}
	return client.Start(ctx, state)
}
func (cloud *multiplexCloud) Delete(ctx context.Context, state State) error {
	client, err := cloud.client(state.Configuration.SubscriptionID)
	if err != nil {
		return err
	}
	return client.Delete(ctx, state)
}

func (cloud *sdkCloud) Start(ctx context.Context, state State) error {
	poller, err := cloud.virtualMachines.BeginStart(ctx, state.Configuration.ResourceGroup, resourceName(state.Resources.VM), nil)
	if err != nil {
		return sanitizeAzureError(err)
	}
	if _, err := poller.PollUntilDone(ctx, &azruntime.PollUntilDoneOptions{Frequency: time.Second}); err != nil {
		return sanitizeAzureError(err)
	}
	return nil
}

func NewSDKCloud(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) (Cloud, error) {
	resources, err := armresources.NewClient(subscriptionID, credential, options)
	if err != nil {
		return nil, errors.New("Azure resource client is unavailable")
	}
	deployments, err := armresources.NewDeploymentsClient(subscriptionID, credential, options)
	if err != nil {
		return nil, errors.New("Azure deployment client is unavailable")
	}
	virtualMachines, err := armcompute.NewVirtualMachinesClient(subscriptionID, credential, options)
	if err != nil {
		return nil, errors.New("Azure compute client is unavailable")
	}
	disks, err := armcompute.NewDisksClient(subscriptionID, credential, options)
	if err != nil {
		return nil, errors.New("Azure disk client is unavailable")
	}
	return &sdkCloud{resources: resources, deployments: deployments, virtualMachines: virtualMachines, disks: disks}, nil
}

func (cloud *sdkCloud) Deploy(ctx context.Context, state State, bootstrap bool) error {
	compiled, err := template.Compiled()
	if err != nil {
		return errors.New("Azure deployment template is unavailable")
	}
	if err := cloud.preflightDeploy(ctx, state); err != nil {
		return err
	}
	parameters := deploymentParameters(state, bootstrap)
	mode := armresources.DeploymentModeIncremental
	poller, err := cloud.deployments.BeginCreateOrUpdate(ctx, state.Configuration.ResourceGroup, resourceName(state.Resources.Deployment), armresources.Deployment{
		Properties: &armresources.DeploymentProperties{Mode: &mode, Template: compiled, Parameters: parameters},
		Tags:       ownershipTagPointers(state),
	}, nil)
	if err != nil {
		return sanitizeAzureError(err)
	}
	if _, err := poller.PollUntilDone(ctx, &azruntime.PollUntilDoneOptions{Frequency: time.Second}); err != nil {
		return sanitizeAzureError(err)
	}
	return cloud.ensureDiskLockdown(ctx, state)
}

func (cloud *sdkCloud) preflightDeploy(ctx context.Context, state State) error {
	deployment, err := cloud.deployments.Get(ctx, state.Configuration.ResourceGroup, resourceName(state.Resources.Deployment), nil)
	deploymentExists := err == nil
	if err != nil && !isNotFound(err) {
		return sanitizeAzureError(err)
	}
	if deploymentExists && !ownedDeploymentIdentity(state, deployment.DeploymentExtended) {
		return &cloudError{retryable: false}
	}
	read := make(map[string]map[string]any, 4)
	for _, resource := range []struct{ id, version string }{
		{state.Resources.NSG, "2024-05-01"}, {state.Resources.NIC, "2024-05-01"},
		{state.Resources.VM, "2024-07-01"}, {state.Resources.OSDisk, "2024-03-02"},
	} {
		value, exists, readErr := cloud.readResource(ctx, resource.id, resource.version)
		if readErr != nil {
			return readErr
		}
		if exists {
			read[resource.id] = value
		}
	}
	for _, id := range []string{state.Resources.NSG, state.Resources.NIC, state.Resources.VM} {
		if value := read[id]; value != nil && (!deploymentExists || !ownedResource(state, id, value)) {
			return &cloudError{retryable: false}
		}
	}
	if disk := read[state.Resources.OSDisk]; disk != nil {
		if !deploymentExists {
			return &cloudError{retryable: false}
		}
		if exactDiskLockdown(state, disk) {
			return nil
		}
		// Before the PATCH establishes durable disk ownership, recognize the
		// deterministic disk only through an exact owned deployment and an
		// exact owned VM attachment. A matching name or disk tags alone never
		// authorize adoption.
		vm := read[state.Resources.VM]
		if !ownedDeploymentIdentity(state, deployment.DeploymentExtended) ||
			vm == nil || validateVMReadback(state, vm) != nil || !pendingDiskLockdown(state, disk) {
			return &cloudError{retryable: false}
		}
	}
	return nil
}

func (cloud *sdkCloud) readResource(ctx context.Context, id, version string) (map[string]any, bool, error) {
	response, err := cloud.resources.GetByID(ctx, id, version, nil)
	if isNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, sanitizeAzureError(err)
	}
	encoded, err := json.Marshal(response.GenericResource)
	if err != nil {
		return nil, false, errors.New("Azure resource readback is invalid")
	}
	var value map[string]any
	if json.Unmarshal(encoded, &value) != nil {
		return nil, false, errors.New("Azure resource readback is invalid")
	}
	return value, true, nil
}

func (cloud *sdkCloud) ensureDiskLockdown(ctx context.Context, state State) error {
	deployment, err := cloud.deployments.Get(ctx, state.Configuration.ResourceGroup, resourceName(state.Resources.Deployment), nil)
	if err != nil {
		return sanitizeAzureError(err)
	}
	vm, vmExists, err := cloud.readResource(ctx, state.Resources.VM, "2024-07-01")
	if err != nil {
		return err
	}
	disk, diskExists, err := cloud.readResource(ctx, state.Resources.OSDisk, "2024-03-02")
	if err != nil {
		return err
	}
	if !ownedDeploymentIdentity(state, deployment.DeploymentExtended) || !vmExists || validateVMReadback(state, vm) != nil || !diskExists {
		return &cloudError{retryable: false}
	}
	if exactDiskLockdown(state, disk) {
		return nil
	}
	if !pendingDiskLockdown(state, disk) {
		return &cloudError{retryable: false}
	}
	denyAll := armcompute.NetworkAccessPolicyDenyAll
	publicDisabled := armcompute.PublicNetworkAccessDisabled
	poller, updateErr := cloud.disks.BeginUpdate(ctx, state.Configuration.ResourceGroup, resourceName(state.Resources.OSDisk), armcompute.DiskUpdate{
		Tags: ownershipTagPointers(state),
		Properties: &armcompute.DiskUpdateProperties{
			NetworkAccessPolicy: &denyAll,
			PublicNetworkAccess: &publicDisabled,
		},
	}, nil)
	if updateErr == nil {
		_, updateErr = poller.PollUntilDone(ctx, &azruntime.PollUntilDoneOptions{Frequency: time.Second})
	}
	// A committed PATCH whose response was lost is recovered by exact
	// authoritative readback. Plaintext replay state is unnecessary.
	locked, exists, readErr := cloud.readResource(ctx, state.Resources.OSDisk, "2024-03-02")
	if readErr == nil && exists && exactDiskLockdown(state, locked) {
		return nil
	}
	if updateErr != nil {
		return sanitizeAzureError(updateErr)
	}
	if readErr != nil {
		return readErr
	}
	return &cloudError{retryable: false}
}

func (cloud *sdkCloud) Observe(ctx context.Context, state State) (CloudObservation, error) {
	deployment, err := cloud.deployments.Get(ctx, state.Configuration.ResourceGroup, resourceName(state.Resources.Deployment), nil)
	if isNotFound(err) {
		return CloudObservation{}, nil
	}
	if err != nil {
		return CloudObservation{}, sanitizeAzureError(err)
	}
	if !ownedDeployment(state, deployment.DeploymentExtended) {
		return CloudObservation{Exists: true}, &cloudError{retryable: false}
	}
	resources := []struct{ id, version string }{
		{state.Resources.NSG, "2024-05-01"}, {state.Resources.NIC, "2024-05-01"},
		{state.Resources.OSDisk, "2024-03-02"}, {state.Resources.VM, "2024-07-01"},
	}
	read := make(map[string]map[string]any, len(resources))
	for _, resource := range resources {
		response, err := cloud.resources.GetByID(ctx, resource.id, resource.version, nil)
		if isNotFound(err) {
			return CloudObservation{}, nil
		}
		if err != nil {
			return CloudObservation{}, sanitizeAzureError(err)
		}
		encoded, _ := json.Marshal(response.GenericResource)
		var value map[string]any
		if json.Unmarshal(encoded, &value) != nil {
			return CloudObservation{}, errors.New("Azure resource readback is invalid")
		}
		read[resource.id] = value
	}
	observation, err := validateReadback(state, read)
	if err != nil {
		return CloudObservation{Exists: true}, &cloudError{retryable: false}
	}
	view, err := cloud.virtualMachines.InstanceView(ctx, state.Configuration.ResourceGroup, resourceName(state.Resources.VM), nil)
	if err != nil {
		return CloudObservation{Exists: true, Exact: true, PrivateIP: observation.PrivateIP, SteadyFence: observation.SteadyFence}, sanitizeAzureError(err)
	}
	for _, status := range view.Statuses {
		if status != nil && status.Code != nil && *status.Code == "PowerState/running" {
			observation.Running = true
		}
	}
	return observation, nil
}

func (cloud *sdkCloud) Delete(ctx context.Context, state State) error {
	if disk, exists, err := cloud.readResource(ctx, state.Resources.OSDisk, "2024-03-02"); err != nil {
		return err
	} else if exists && !exactDiskLockdown(state, disk) {
		// Establish durable ownership while the exact deployment and attached
		// VM still provide recovery authority. Once the VM is removed, an
		// untagged deterministic disk is deliberately not adoptable.
		if err := cloud.ensureDiskLockdown(ctx, state); err != nil {
			return errors.New("Azure cleanup ownership could not be verified")
		}
	}
	resources := []struct{ id, version string }{
		{state.Resources.VM, "2024-07-01"}, {state.Resources.OSDisk, "2024-03-02"},
		{state.Resources.NIC, "2024-05-01"}, {state.Resources.NSG, "2024-05-01"},
	}
	// Verify the complete remaining graph before the first destructive call.
	// Each item is checked again immediately before its own delete below. This
	// prevents a collision in a later object (including the deployment record)
	// from causing even an earlier, correctly named object to be removed.
	for _, resource := range resources {
		response, err := cloud.resources.GetByID(ctx, resource.id, resource.version, nil)
		if isNotFound(err) {
			continue
		}
		if err != nil {
			return sanitizeAzureError(err)
		}
		encoded, _ := json.Marshal(response.GenericResource)
		var value map[string]any
		if json.Unmarshal(encoded, &value) != nil || !ownedResource(state, resource.id, value) {
			return errors.New("Azure cleanup ownership could not be verified")
		}
	}
	deployment, err := cloud.deployments.Get(ctx, state.Configuration.ResourceGroup, resourceName(state.Resources.Deployment), nil)
	if err != nil && !isNotFound(err) {
		return sanitizeAzureError(err)
	}
	if err == nil && !ownedDeploymentIdentity(state, deployment.DeploymentExtended) {
		return errors.New("Azure cleanup ownership could not be verified")
	}
	for _, resource := range resources {
		response, err := cloud.resources.GetByID(ctx, resource.id, resource.version, nil)
		if isNotFound(err) {
			continue
		}
		if err != nil {
			return sanitizeAzureError(err)
		}
		encoded, _ := json.Marshal(response.GenericResource)
		var value map[string]any
		if json.Unmarshal(encoded, &value) != nil || !ownedResource(state, resource.id, value) {
			return errors.New("Azure cleanup ownership could not be verified")
		}
		poller, err := cloud.resources.BeginDeleteByID(ctx, resource.id, resource.version, nil)
		if err != nil && !isNotFound(err) {
			return sanitizeAzureError(err)
		}
		if err == nil {
			if _, err = poller.PollUntilDone(ctx, nil); err != nil && !isNotFound(err) {
				return sanitizeAzureError(err)
			}
		}
		if _, err = cloud.resources.GetByID(ctx, resource.id, resource.version, nil); !isNotFound(err) {
			return errors.New("Azure resource deletion is pending")
		}
	}
	deployment, err = cloud.deployments.Get(ctx, state.Configuration.ResourceGroup, resourceName(state.Resources.Deployment), nil)
	if err != nil && !isNotFound(err) {
		return sanitizeAzureError(err)
	}
	if err == nil && !ownedDeploymentIdentity(state, deployment.DeploymentExtended) {
		return errors.New("Azure cleanup ownership could not be verified")
	}
	poller, err := cloud.deployments.BeginDelete(ctx, state.Configuration.ResourceGroup, resourceName(state.Resources.Deployment), nil)
	if err != nil && !isNotFound(err) {
		return sanitizeAzureError(err)
	}
	if err == nil {
		if _, err = poller.PollUntilDone(ctx, nil); err != nil && !isNotFound(err) {
			return sanitizeAzureError(err)
		}
	}
	if _, err = cloud.deployments.Get(ctx, state.Configuration.ResourceGroup, resourceName(state.Resources.Deployment), nil); !isNotFound(err) {
		return errors.New("Azure deployment record deletion is pending")
	}
	return nil
}

func deploymentParameters(state State, bootstrap bool) map[string]any {
	rules := make([]map[string]any, 0, len(state.PinnedDestinations))
	for _, destination := range state.PinnedDestinations {
		if !includePinnedDestination(state, destination, bootstrap) {
			continue
		}
		rules = append(rules, map[string]any{"address": destination.Address, "port": destination.Port})
	}
	tags := ownershipTags(state)
	values := map[string]any{
		"location": state.Configuration.Location, "vmName": resourceName(state.Resources.VM),
		"nicName": resourceName(state.Resources.NIC), "nsgName": resourceName(state.Resources.NSG),
		"diskName": resourceName(state.Resources.OSDisk), "subnetResourceId": state.Configuration.SubnetResourceID,
		"imageVersionResourceId": state.Configuration.VMImageResourceID, "vmSize": state.Configuration.VMSize,
		"diskSizeGiB": state.Configuration.OSDisk.SizeGiB, "diskStorageAccountType": state.Configuration.OSDisk.StorageAccountType,
		"sshPublicKey": state.BootstrapPublicKey, "bootstrapSSHEnabled": bootstrap, "mediated": state.NativeEgressAttachment != nil,
		"driverSourceCIDR": state.Configuration.Network.DriverSourceCIDR, "dnsServer": state.Configuration.Network.DNSServer,
		"outboundRules": rules, "tags": tags, "adminUsername": "nvt-bootstrap",
	}
	parameters := make(map[string]any, len(values))
	for name, value := range values {
		parameters[name] = map[string]any{"value": value}
	}
	return parameters
}

func ownershipTags(state State) map[string]string {
	return map[string]string{
		"nvt-execution-id": state.ExecutionID, "nvt-generation": strconv.FormatInt(state.Generation, 10),
		"nvt-desired-fingerprint": state.DesiredFingerprint, "nvt-guest-instance": state.GuestInstanceID,
	}
}

func ownershipTagPointers(state State) map[string]*string {
	result := make(map[string]*string, len(ownershipTags(state)))
	for key, value := range ownershipTags(state) {
		copy := value
		result[key] = &copy
	}
	return result
}

func ownedDeployment(state State, deployment armresources.DeploymentExtended) bool {
	if !ownedDeploymentIdentity(state, deployment) || deployment.Properties == nil ||
		deployment.Properties.ProvisioningState == nil || *deployment.Properties.ProvisioningState != "Succeeded" || len(deployment.Tags) < 4 {
		return false
	}
	return true
}

func ownedDeploymentIdentity(state State, deployment armresources.DeploymentExtended) bool {
	if deployment.ID == nil || !sameResourceID(*deployment.ID, state.Resources.Deployment) ||
		deployment.Properties == nil || deployment.Properties.Mode == nil || *deployment.Properties.Mode != armresources.DeploymentModeIncremental || len(deployment.Tags) < 4 {
		return false
	}
	for key, expected := range ownershipTags(state) {
		if actual := deployment.Tags[key]; actual == nil || *actual != expected {
			return false
		}
	}
	return true
}

func validateReadback(state State, resources map[string]map[string]any) (CloudObservation, error) {
	for id, value := range resources {
		if id == state.Resources.OSDisk {
			if !exactDiskLockdown(state, value) {
				return CloudObservation{}, errors.New("Azure resource ownership or configuration drifted")
			}
			continue
		}
		if !ownedResource(state, id, value) {
			return CloudObservation{}, errors.New("Azure resource ownership or configuration drifted")
		}
	}
	nic := resources[state.Resources.NIC]
	properties, _ := nic["properties"].(map[string]any)
	nsgReference, _ := properties["networkSecurityGroup"].(map[string]any)
	dnsSettings, _ := properties["dnsSettings"].(map[string]any)
	dnsServers, _ := dnsSettings["dnsServers"].([]any)
	if !sameResourceID(referenceID(nsgReference), state.Resources.NSG) || properties["enableIPForwarding"] != false ||
		properties["enableAcceleratedNetworking"] != false || len(dnsServers) != 1 || dnsServers[0] != state.Configuration.Network.DNSServer {
		return CloudObservation{}, errors.New("Azure NIC network boundary drifted")
	}
	configurations, _ := properties["ipConfigurations"].([]any)
	if len(configurations) != 1 {
		return CloudObservation{}, errors.New("Azure NIC configuration drifted")
	}
	ipConfig, _ := configurations[0].(map[string]any)
	ipProperties, _ := ipConfig["properties"].(map[string]any)
	privateIP, _ := ipProperties["privateIPAddress"].(string)
	subnet, _ := ipProperties["subnet"].(map[string]any)
	if net.ParseIP(privateIP) == nil || net.ParseIP(privateIP).To4() == nil || ipProperties["publicIPAddress"] != nil || !sameResourceID(referenceID(subnet), state.Configuration.SubnetResourceID) ||
		ipProperties["privateIPAllocationMethod"] != "Dynamic" || ipProperties["primary"] != true {
		return CloudObservation{}, errors.New("Azure NIC address configuration drifted")
	}
	if err := validateVMReadback(state, resources[state.Resources.VM]); err != nil {
		return CloudObservation{}, err
	}
	disk := resources[state.Resources.OSDisk]
	diskProperties, _ := disk["properties"].(map[string]any)
	creation, _ := diskProperties["creationData"].(map[string]any)
	imageReference, _ := creation["imageReference"].(map[string]any)
	sku, _ := disk["sku"].(map[string]any)
	if !sameResourceID(referenceID(imageReference), state.Configuration.VMImageResourceID) || creation["createOption"] != "FromImage" ||
		diskProperties["networkAccessPolicy"] != "DenyAll" ||
		diskProperties["publicNetworkAccess"] != "Disabled" || diskProperties["osType"] != "Linux" ||
		numericInt32(diskProperties["diskSizeGB"]) != state.Configuration.OSDisk.SizeGiB ||
		sku["name"] != state.Configuration.OSDisk.StorageAccountType {
		return CloudObservation{}, errors.New("Azure OS disk configuration drifted")
	}
	steady := nsgMatches(state, resources[state.Resources.NSG], false)
	bootstrap := nsgMatches(state, resources[state.Resources.NSG], true)
	return CloudObservation{Exists: true, Exact: true, PrivateIP: privateIP, SteadyFence: steady, BootstrapFence: bootstrap}, nil
}

func validateVMReadback(state State, vm map[string]any) error {
	if !ownedResource(state, state.Resources.VM, vm) {
		return errors.New("Azure VM ownership drifted")
	}
	vmProperties, _ := vm["properties"].(map[string]any)
	hardware, _ := vmProperties["hardwareProfile"].(map[string]any)
	storage, _ := vmProperties["storageProfile"].(map[string]any)
	vmImageReference, _ := storage["imageReference"].(map[string]any)
	osDisk, _ := storage["osDisk"].(map[string]any)
	managedDisk, _ := osDisk["managedDisk"].(map[string]any)
	networkProfile, _ := vmProperties["networkProfile"].(map[string]any)
	interfaces, _ := networkProfile["networkInterfaces"].([]any)
	var interfaceProperties map[string]any
	if len(interfaces) == 1 {
		interfaceProperties, _ = asMap(interfaces[0])["properties"].(map[string]any)
	}
	osProfile, _ := vmProperties["osProfile"].(map[string]any)
	linuxConfiguration, _ := osProfile["linuxConfiguration"].(map[string]any)
	sshConfiguration, _ := linuxConfiguration["ssh"].(map[string]any)
	publicKeys, _ := sshConfiguration["publicKeys"].([]any)
	diagnostics, _ := vmProperties["diagnosticsProfile"].(map[string]any)
	bootDiagnostics, _ := diagnostics["bootDiagnostics"].(map[string]any)
	if !noVMIdentity(vm["identity"]) || vmProperties["provisioningState"] != "Succeeded" ||
		hardware["vmSize"] != state.Configuration.VMSize || !sameResourceID(referenceID(vmImageReference), state.Configuration.VMImageResourceID) ||
		!sameResourceID(referenceID(managedDisk), state.Resources.OSDisk) || managedDisk["storageAccountType"] != state.Configuration.OSDisk.StorageAccountType ||
		osDisk["name"] != resourceName(state.Resources.OSDisk) || osDisk["createOption"] != "FromImage" || osDisk["deleteOption"] != "Detach" ||
		osDisk["osType"] != "Linux" || numericInt32(osDisk["diskSizeGB"]) != state.Configuration.OSDisk.SizeGiB ||
		len(interfaces) != 1 || !sameResourceID(referenceID(asMap(interfaces[0])), state.Resources.NIC) ||
		interfaceProperties["deleteOption"] != "Detach" || interfaceProperties["primary"] != true ||
		osProfile["adminUsername"] != "nvt-bootstrap" || osProfile["allowExtensionOperations"] != false || osProfile["requireGuestProvisionSignal"] != false ||
		linuxConfiguration["disablePasswordAuthentication"] != true || linuxConfiguration["provisionVMAgent"] != false ||
		len(publicKeys) != 1 || bootDiagnostics["enabled"] != false {
		return errors.New("Azure VM identity or provisioning state drifted")
	}
	key := asMap(publicKeys[0])
	if key["path"] != "/home/nvt-bootstrap/.ssh/authorized_keys" || key["keyData"] != state.BootstrapPublicKey {
		return errors.New("Azure VM bootstrap identity drifted")
	}
	return nil
}

func exactDiskLockdown(state State, disk map[string]any) bool {
	return ownedResource(state, state.Resources.OSDisk, disk) && diskConfigurationMatches(state, disk) && diskLockdownMatches(disk)
}

func pendingDiskLockdown(state State, disk map[string]any) bool {
	if !diskConfigurationMatches(state, disk) {
		return false
	}
	tags, _ := disk["tags"].(map[string]any)
	if len(tags) == 0 {
		return true
	}
	// A lost PATCH can leave exact tags visible before the final readback sees
	// every property. Conflicting or partial tags are never adopted.
	for key, expected := range ownershipTags(state) {
		if actual, _ := tags[key].(string); actual != expected {
			return false
		}
	}
	return len(tags) == len(ownershipTags(state))
}

func diskConfigurationMatches(state State, disk map[string]any) bool {
	id, _ := disk["id"].(string)
	location, _ := disk["location"].(string)
	diskProperties, _ := disk["properties"].(map[string]any)
	creation, _ := diskProperties["creationData"].(map[string]any)
	imageReference, _ := creation["imageReference"].(map[string]any)
	sku, _ := disk["sku"].(map[string]any)
	return sameResourceID(id, state.Resources.OSDisk) && location == state.Configuration.Location &&
		sameResourceID(referenceID(imageReference), state.Configuration.VMImageResourceID) && creation["createOption"] == "FromImage" &&
		diskProperties["osType"] == "Linux" && numericInt32(diskProperties["diskSizeGB"]) == state.Configuration.OSDisk.SizeGiB &&
		sku["name"] == state.Configuration.OSDisk.StorageAccountType
}

func diskLockdownMatches(disk map[string]any) bool {
	properties, _ := disk["properties"].(map[string]any)
	return properties["networkAccessPolicy"] == "DenyAll" && properties["publicNetworkAccess"] == "Disabled"
}

func noVMIdentity(value any) bool {
	if value == nil {
		return true
	}
	identity, ok := value.(map[string]any)
	if !ok || identity["type"] != "None" || identity["principalId"] != nil || identity["tenantId"] != nil || identity["userAssignedIdentities"] != nil {
		return false
	}
	return true
}

func ownedResource(state State, expectedID string, value map[string]any) bool {
	id, _ := value["id"].(string)
	location, _ := value["location"].(string)
	tagsAny, _ := value["tags"].(map[string]any)
	if !sameResourceID(id, expectedID) || location != state.Configuration.Location || len(tagsAny) < 4 {
		return false
	}
	for key, expected := range ownershipTags(state) {
		if actual, _ := tagsAny[key].(string); actual != expected {
			return false
		}
	}
	return true
}

func nsgMatches(state State, value map[string]any, bootstrap bool) bool {
	properties, _ := value["properties"].(map[string]any)
	rules, _ := properties["securityRules"].([]any)
	expected := expectedNSGRules(state, bootstrap)
	if len(rules) != len(expected) {
		return false
	}
	for _, raw := range rules {
		rule, _ := raw.(map[string]any)
		name, _ := rule["name"].(string)
		actual, _ := rule["properties"].(map[string]any)
		wanted, present := expected[name]
		if !present || !rulePropertiesEqual(actual, wanted) {
			return false
		}
		delete(expected, name)
	}
	return len(expected) == 0
}

func expectedNSGRules(state State, bootstrap bool) map[string]map[string]any {
	result := map[string]map[string]any{
		"deny-all-inbound": nsgRule("*", "*", "*", "*", "Deny", 4095, "Inbound"),
	}
	if bootstrap {
		result["allow-bootstrap-ssh"] = nsgRule("Tcp", "22", state.Configuration.Network.DriverSourceCIDR, "*", "Allow", 100, "Inbound")
	}
	if state.NativeEgressAttachment == nil {
		return result
	}
	index := 0
	for _, destination := range state.PinnedDestinations {
		if !includePinnedDestination(state, destination, bootstrap) {
			continue
		}
		result["allow-nvt-"+strconv.Itoa(index)] = nsgRule("Tcp", strconv.Itoa(int(destination.Port)), "*", destination.Address, "Allow", 200+index, "Outbound")
		index++
	}
	result["allow-dns-tcp"] = nsgRule("Tcp", "53", "*", state.Configuration.Network.DNSServer, "Allow", 500, "Outbound")
	result["allow-dns-udp"] = nsgRule("Udp", "53", "*", state.Configuration.Network.DNSServer, "Allow", 501, "Outbound")
	result["deny-azure-platform-imds"] = nsgRule("*", "*", "*", "AzurePlatformIMDS", "Deny", 600, "Outbound")
	result["deny-azure-platform-lkm"] = nsgRule("*", "*", "*", "AzurePlatformLKM", "Deny", 601, "Outbound")
	result["deny-azure-platform-dns"] = nsgRule("*", "*", "*", "AzurePlatformDNS", "Deny", 602, "Outbound")
	result["deny-all-outbound"] = nsgRule("*", "*", "*", "*", "Deny", 4096, "Outbound")
	return result
}

func includePinnedDestination(state State, destination PinnedDestination, bootstrap bool) bool {
	if bootstrap || destination.Purpose != string(executiondriver.NativeEgressDestinationBootstrap) {
		return true
	}
	return destination.Host == endpointHost(state.Configuration.EnrollmentEndpoint) &&
		destination.Port == endpointPortText(state.Configuration.EnrollmentEndpoint)
}

func nsgRule(protocol, port, source, destination, access string, priority int, direction string) map[string]any {
	return map[string]any{"protocol": protocol, "sourcePortRange": "*", "destinationPortRange": port,
		"sourceAddressPrefix": source, "destinationAddressPrefix": destination, "access": access,
		"priority": priority, "direction": direction}
}

func rulePropertiesEqual(actual, expected map[string]any) bool {
	for key, wanted := range expected {
		if key == "priority" {
			if numericInt(actual[key]) != wanted.(int) {
				return false
			}
			continue
		}
		if actual[key] != wanted {
			return false
		}
	}
	return true
}

func referenceID(value map[string]any) string { id, _ := value["id"].(string); return id }
func sameResourceID(left, right string) bool {
	return left != "" && right != "" && strings.EqualFold(left, right)
}
func asMap(value any) map[string]any { result, _ := value.(map[string]any); return result }
func numericInt(value any) int {
	if number, ok := value.(float64); ok {
		return int(number)
	}
	if number, ok := value.(int); ok {
		return number
	}
	return 0
}
func numericInt32(value any) int32 { return int32(numericInt(value)) }

func isNotFound(err error) bool {
	var response *azcore.ResponseError
	return errors.As(err, &response) && response.StatusCode == http.StatusNotFound
}

func sanitizeAzureError(err error) error {
	if err == nil {
		return nil
	}
	var response *azcore.ResponseError
	if errors.As(err, &response) {
		switch response.StatusCode {
		case http.StatusRequestTimeout, http.StatusConflict, http.StatusTooManyRequests,
			http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return &cloudError{retryable: true}
		default:
			return &cloudError{retryable: false}
		}
	}
	return &cloudError{retryable: true}
}

type cloudError struct{ retryable bool }

func (*cloudError) Error() string         { return "Azure control-plane operation failed" }
func (value *cloudError) Retryable() bool { return value.retryable }
