package driver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type testCredential struct{ token string }

func (credential testCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: credential.token, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type fakeARM struct {
	mu              sync.Mutex
	state           State
	resources       map[string]map[string]any
	deployment      bool
	lostOnce        bool
	requests        int
	deletes         []string
	lastDeployment  map[string]any
	seen            []string
	foreignDeploy   bool
	asyncDeploy     bool
	polls           int
	stopped         bool
	starts          int
	startPolls      int
	deploymentState string
}

func TestSDKCloudIncrementalDeployLostResponseReadbackAndExactDelete(t *testing.T) {
	desired := testDesired(t, true)
	configuration := testConfiguration(t)
	state := newState(configuration, desired, 1, testPinnedDestinations())
	_, public, fingerprint, err := generateBootstrapKey()
	if err != nil {
		t.Fatal(err)
	}
	state.BootstrapPublicKey, state.BootstrapKeyFingerprint = public, fingerprint
	fixture := &fakeARM{state: state, lostOnce: true, asyncDeploy: true}
	server := httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	defer server.Close()
	client, err := NewSDKCloud(configuration.SubscriptionID, testCredential{token: "sdk-fake-authority"}, testARMOptions(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Deploy(context.Background(), state, true); err != nil {
		fixture.mu.Lock()
		seen := append([]string(nil), fixture.seen...)
		fixture.mu.Unlock()
		t.Fatalf("idempotent SDK retry did not recover a lost ARM response: %v (%#v)", err, seen)
	}
	observation, err := client.Observe(context.Background(), state)
	if err != nil || !observation.Exact || !observation.Running || !observation.BootstrapFence {
		fixture.mu.Lock()
		seen := append([]string(nil), fixture.seen...)
		fixture.mu.Unlock()
		t.Fatalf("authoritative readback failed: %#v %v (%#v)", observation, err, seen)
	}
	fixture.mu.Lock()
	body := fixture.lastDeployment
	seenAfterDeploy := append([]string(nil), fixture.seen...)
	polls := fixture.polls
	fixture.mu.Unlock()
	putCount := 0
	for _, request := range seenAfterDeploy {
		if strings.HasPrefix(request, "PUT ") {
			putCount++
		}
	}
	if putCount != 2 {
		t.Fatalf("lost response did not replay the exact deployment: %#v", seenAfterDeploy)
	}
	if polls == 0 {
		t.Fatal("Azure long-running deployment was not polled")
	}
	properties, _ := body["properties"].(map[string]any)
	if properties["mode"] != "Incremental" {
		t.Fatalf("non-incremental deployment submitted: %#v", properties["mode"])
	}
	encoded, _ := json.Marshal(body)
	for _, needle := range []string{"sdk-fake-authority", "nvt_eg1_", "runtime_identity", "private_key", "customData"} {
		if strings.Contains(string(encoded), needle) {
			t.Fatalf("deployment leaked %q", needle)
		}
	}
	if err := client.Delete(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	deletes := append([]string(nil), fixture.deletes...)
	fixture.mu.Unlock()
	for _, expected := range []string{state.Resources.VM, state.Resources.OSDisk, state.Resources.NIC, state.Resources.NSG, state.Resources.Deployment} {
		found := false
		for _, actual := range deletes {
			if strings.EqualFold(actual, expected) {
				found = true
			}
		}
		if !found {
			t.Fatalf("resource not deleted: %s (%#v)", expected, deletes)
		}
	}
}

func TestSDKCloudRefusesForeignResourceDeletion(t *testing.T) {
	desired := testDesired(t, true)
	state := newState(testConfiguration(t), desired, 1, testPinnedDestinations())
	_, public, fingerprint, _ := generateBootstrapKey()
	state.BootstrapPublicKey, state.BootstrapKeyFingerprint = public, fingerprint
	fixture := &fakeARM{state: state, deployment: true}
	fixture.resources = fixture.readback(true)
	fixture.resources[state.Resources.VM]["tags"].(map[string]any)["nvt-execution-id"] = "another-run"
	server := httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	defer server.Close()
	client, _ := NewSDKCloud(state.Configuration.SubscriptionID, testCredential{"authority"}, testARMOptions(server.URL))
	if err := client.Delete(context.Background(), state); err == nil {
		t.Fatal("foreign resource was accepted for deletion")
	}
	fixture.mu.Lock()
	deletes := len(fixture.deletes)
	fixture.mu.Unlock()
	if deletes != 0 {
		t.Fatal("destructive call occurred before ownership validation")
	}
}

func TestSDKCloudStartsStoppedExactOwnedVMAndPolls(t *testing.T) {
	desired := testDesired(t, true)
	state := newState(testConfiguration(t), desired, 1, testPinnedDestinations())
	_, public, fingerprint, _ := generateBootstrapKey()
	state.BootstrapPublicKey, state.BootstrapKeyFingerprint = public, fingerprint
	fixture := &fakeARM{state: state, deployment: true, stopped: true}
	fixture.resources = fixture.readback(true)
	server := httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	defer server.Close()
	client, _ := NewSDKCloud(state.Configuration.SubscriptionID, testCredential{"authority"}, testARMOptions(server.URL))

	observation, err := client.Observe(context.Background(), state)
	if err != nil || !observation.Exact || observation.Running {
		t.Fatalf("stopped exact-owned VM was not observed correctly: %#v %v", observation, err)
	}
	if err := client.Start(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	observation, err = client.Observe(context.Background(), state)
	if err != nil || !observation.Running {
		t.Fatalf("started VM did not converge to running: %#v %v", observation, err)
	}
	fixture.mu.Lock()
	starts, polls := fixture.starts, fixture.startPolls
	fixture.mu.Unlock()
	if starts != 1 || polls == 0 {
		t.Fatalf("Azure Start LRO was not called and polled: starts=%d polls=%d", starts, polls)
	}
}

func TestSDKCloudRefusesOrphanResourceBeforeDeploymentMutation(t *testing.T) {
	desired := testDesired(t, true)
	state := newState(testConfiguration(t), desired, 1, testPinnedDestinations())
	_, public, fingerprint, _ := generateBootstrapKey()
	state.BootstrapPublicKey, state.BootstrapKeyFingerprint = public, fingerprint
	fixture := &fakeARM{state: state}
	fixture.resources = fixture.readback(true)
	server := httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	defer server.Close()
	client, _ := NewSDKCloud(state.Configuration.SubscriptionID, testCredential{"authority"}, testARMOptions(server.URL))
	if err := client.Deploy(context.Background(), state, true); err == nil {
		t.Fatal("orphan resources were adopted from matching tags alone")
	}
	fixture.mu.Lock()
	requests := append([]string(nil), fixture.seen...)
	fixture.mu.Unlock()
	for _, request := range requests {
		if strings.HasPrefix(request, "PUT ") {
			t.Fatalf("deployment mutation occurred before collision rejection: %#v", requests)
		}
	}
}

func TestSDKCloudRefusesForeignDeploymentBeforeAnyResourceDeletion(t *testing.T) {
	desired := testDesired(t, true)
	state := newState(testConfiguration(t), desired, 1, testPinnedDestinations())
	_, public, fingerprint, _ := generateBootstrapKey()
	state.BootstrapPublicKey, state.BootstrapKeyFingerprint = public, fingerprint
	fixture := &fakeARM{state: state, deployment: true, foreignDeploy: true}
	fixture.resources = fixture.readback(true)
	server := httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	defer server.Close()
	client, _ := NewSDKCloud(state.Configuration.SubscriptionID, testCredential{"authority"}, testARMOptions(server.URL))
	if err := client.Delete(context.Background(), state); err == nil {
		t.Fatal("foreign deployment record was accepted for deletion")
	}
	fixture.mu.Lock()
	deletes := len(fixture.deletes)
	fixture.mu.Unlock()
	if deletes != 0 {
		t.Fatal("resource deletion occurred before the complete ownership preflight")
	}
}

func TestSDKCloudPartialCreationAndReadbackDriftFailClosed(t *testing.T) {
	desired := testDesired(t, true)
	state := newState(testConfiguration(t), desired, 1, testPinnedDestinations())
	_, public, fingerprint, _ := generateBootstrapKey()
	state.BootstrapPublicKey, state.BootstrapKeyFingerprint = public, fingerprint
	fixture := &fakeARM{state: state, deployment: true}
	fixture.resources = fixture.readback(true)
	delete(fixture.resources, state.Resources.VM)
	server := httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	defer server.Close()
	client, _ := NewSDKCloud(state.Configuration.SubscriptionID, testCredential{"authority"}, testARMOptions(server.URL))
	observation, err := client.Observe(context.Background(), state)
	if err != nil || observation.Exists {
		t.Fatalf("partial graph was trusted: %#v %v", observation, err)
	}
	fixture.mu.Lock()
	fixture.resources = fixture.readback(true)
	fixture.resources[state.Resources.NIC]["properties"].(map[string]any)["enableIPForwarding"] = true
	fixture.mu.Unlock()
	observation, err = client.Observe(context.Background(), state)
	if err == nil || !observation.Exists || observation.Exact {
		t.Fatalf("readback drift was trusted: %#v %v", observation, err)
	}
}

func TestReadbackUsesOneCaseInsensitiveResourceIDComparator(t *testing.T) {
	state := newState(testConfiguration(t), testDesired(t, true), 1, testPinnedDestinations())
	_, public, fingerprint, _ := generateBootstrapKey()
	state.BootstrapPublicKey, state.BootstrapKeyFingerprint = public, fingerprint
	fixture := &fakeARM{state: state}
	resources := fixture.readback(true)
	for _, value := range resources {
		value["id"] = strings.ToUpper(value["id"].(string))
	}
	nicProperties := resources[state.Resources.NIC]["properties"].(map[string]any)
	nicProperties["networkSecurityGroup"].(map[string]any)["id"] = strings.ToUpper(state.Resources.NSG)
	nicProperties["ipConfigurations"].([]any)[0].(map[string]any)["properties"].(map[string]any)["subnet"].(map[string]any)["id"] = strings.ToUpper(state.Configuration.SubnetResourceID)
	vmStorage := resources[state.Resources.VM]["properties"].(map[string]any)["storageProfile"].(map[string]any)
	vmStorage["imageReference"].(map[string]any)["id"] = strings.ToUpper(state.Configuration.VMImageResourceID)
	vmStorage["osDisk"].(map[string]any)["managedDisk"].(map[string]any)["id"] = strings.ToUpper(state.Resources.OSDisk)
	resources[state.Resources.VM]["properties"].(map[string]any)["networkProfile"].(map[string]any)["networkInterfaces"].([]any)[0].(map[string]any)["id"] = strings.ToUpper(state.Resources.NIC)
	resources[state.Resources.OSDisk]["properties"].(map[string]any)["creationData"].(map[string]any)["imageReference"].(map[string]any)["id"] = strings.ToUpper(state.Configuration.VMImageResourceID)
	if observation, err := validateReadback(state, resources); err != nil || !observation.Exact {
		t.Fatalf("case-only Azure resource IDs caused false drift: %#v %v", observation, err)
	}
}

func TestSDKCloudCleansPartialResourcesFromFailedOwnedDeployment(t *testing.T) {
	state := newState(testConfiguration(t), testDesired(t, true), 1, testPinnedDestinations())
	_, public, fingerprint, _ := generateBootstrapKey()
	state.BootstrapPublicKey, state.BootstrapKeyFingerprint = public, fingerprint
	fixture := &fakeARM{state: state, deployment: true, deploymentState: "Failed"}
	fixture.resources = fixture.readback(true)
	delete(fixture.resources, state.Resources.VM)
	server := httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	defer server.Close()
	client, _ := NewSDKCloud(state.Configuration.SubscriptionID, testCredential{"authority"}, testARMOptions(server.URL))
	if err := client.Delete(context.Background(), state); err != nil {
		t.Fatalf("owned partial deployment could not be cleaned: %v", err)
	}
}

func TestSteadyFenceRemovesOneTimeRegistryButKeepsIdentityAuthority(t *testing.T) {
	state := newState(testConfiguration(t), testDesired(t, true), 1, testPinnedDestinations())
	bootstrap := expectedNSGRules(state, true)
	if bootstrap["allow-bootstrap-ssh"]["sourceAddressPrefix"] != state.Configuration.Network.DriverSourceCIDR || bootstrap["deny-all-inbound"] == nil {
		t.Fatalf("bootstrap SSH is not bounded by explicit deny/source rules: %#v", bootstrap)
	}
	steady := expectedNSGRules(state, false)
	if steady["allow-bootstrap-ssh"] != nil || steady["deny-all-inbound"] == nil {
		t.Fatalf("steady fence retained SSH authority: %#v", steady)
	}
	for _, name := range []string{"deny-azure-platform-imds", "deny-azure-platform-lkm", "deny-azure-platform-dns", "deny-all-outbound"} {
		if steady[name] == nil {
			t.Fatalf("steady fence omitted platform/default denial %q", name)
		}
	}
	addresses := map[string]bool{}
	for _, rule := range steady {
		if address, ok := rule["destinationAddressPrefix"].(string); ok {
			addresses[address] = true
		}
	}
	if addresses["20.1.1.1"] || !addresses["20.1.1.4"] || !addresses["20.1.1.3"] || !addresses["20.1.1.2"] {
		t.Fatalf("steady identity/control boundary is incorrect: %#v", addresses)
	}
}

func testPinnedDestinations() []PinnedDestination {
	return canonicalPinned([]PinnedDestination{
		{Purpose: "relay", Host: "relay.example", Port: 7445, Address: "20.1.1.3"},
		{Purpose: "bootstrap", Host: "broker.example", Port: 7347, Address: "20.1.1.4"},
		{Purpose: "bootstrap", Host: "registry.example", Port: 443, Address: "20.1.1.1"},
		{Purpose: "control", Host: "gateway.example", Port: 7443, Address: "20.1.1.2"},
	})
}

func (fixture *fakeARM) serveHTTP(response http.ResponseWriter, request *http.Request) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.requests++
	fixture.seen = append(fixture.seen, request.Method+" "+request.URL.RequestURI())
	if request.Header.Get("Authorization") == "" {
		response.WriteHeader(http.StatusUnauthorized)
		return
	}
	path := request.URL.Path
	if request.Method == http.MethodGet && path == "/operations/deployment" {
		fixture.polls++
		writeJSON(response, http.StatusOK, map[string]any{"status": "Succeeded"})
		return
	}
	if request.Method == http.MethodGet && path == "/operations/start" {
		fixture.startPolls++
		fixture.stopped = false
		writeJSON(response, http.StatusOK, map[string]any{"status": "Succeeded"})
		return
	}
	if request.Method == http.MethodPost && strings.HasSuffix(path, "/start") {
		fixture.starts++
		response.Header().Set("Azure-AsyncOperation", "https://management.azure.com/operations/start")
		writeJSON(response, http.StatusAccepted, map[string]any{"status": "InProgress"})
		return
	}
	if request.Method == http.MethodPut && strings.Contains(path, "/providers/Microsoft.Resources/deployments/") {
		var body map[string]any
		if json.NewDecoder(request.Body).Decode(&body) != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		fixture.lastDeployment = body
		fixture.deployment = true
		fixture.resources = fixture.readback(true)
		if fixture.lostOnce {
			fixture.lostOnce = false
			if hijacker, ok := response.(http.Hijacker); ok {
				connection, _, _ := hijacker.Hijack()
				_ = connection.Close()
				return
			}
		}
		if fixture.asyncDeploy {
			response.Header().Set("Azure-AsyncOperation", "https://management.azure.com/operations/deployment")
			value := fixture.deploymentReadback()
			value["properties"].(map[string]any)["provisioningState"] = "Accepted"
			writeJSON(response, http.StatusCreated, value)
			return
		}
		writeJSON(response, http.StatusOK, fixture.deploymentReadback())
		return
	}
	if request.Method == http.MethodGet && strings.HasSuffix(path, "/instanceView") {
		powerState := "PowerState/running"
		if fixture.stopped {
			powerState = "PowerState/deallocated"
		}
		writeJSON(response, http.StatusOK, map[string]any{"statuses": []any{map[string]any{"code": powerState}}})
		return
	}
	if request.Method == http.MethodGet && strings.Contains(path, "/providers/Microsoft.Resources/deployments/") {
		if !fixture.deployment {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(response, http.StatusOK, fixture.deploymentReadback())
		return
	}
	if request.Method == http.MethodGet {
		if value := fixture.resources[path]; value != nil {
			writeJSON(response, http.StatusOK, value)
			return
		}
		response.WriteHeader(http.StatusNotFound)
		return
	}
	if request.Method == http.MethodDelete {
		if strings.Contains(path, "/providers/Microsoft.Resources/deployments/") {
			fixture.deployment = false
		} else {
			delete(fixture.resources, path)
		}
		fixture.deletes = append(fixture.deletes, path)
		response.WriteHeader(http.StatusNoContent)
		return
	}
	response.WriteHeader(http.StatusNotFound)
}

func (fixture *fakeARM) readback(bootstrap bool) map[string]map[string]any {
	tags := map[string]any{}
	for key, value := range ownershipTags(fixture.state) {
		tags[key] = value
	}
	resource := func(id string, properties map[string]any) map[string]any {
		return map[string]any{"id": id, "location": fixture.state.Configuration.Location, "tags": cloneAnyMap(tags), "properties": properties}
	}
	rules := []any{}
	for name, properties := range expectedNSGRules(fixture.state, bootstrap) {
		rules = append(rules, map[string]any{"name": name, "properties": properties})
	}
	nsg := resource(fixture.state.Resources.NSG, map[string]any{"securityRules": rules})
	nic := resource(fixture.state.Resources.NIC, map[string]any{"enableAcceleratedNetworking": false, "enableIPForwarding": false, "dnsSettings": map[string]any{"dnsServers": []any{fixture.state.Configuration.Network.DNSServer}}, "networkSecurityGroup": map[string]any{"id": fixture.state.Resources.NSG}, "ipConfigurations": []any{map[string]any{"properties": map[string]any{"privateIPAddress": "10.42.0.7", "privateIPAllocationMethod": "Dynamic", "primary": true, "subnet": map[string]any{"id": fixture.state.Configuration.SubnetResourceID}}}}})
	disk := resource(fixture.state.Resources.OSDisk, map[string]any{"osType": "Linux", "diskSizeGB": float64(fixture.state.Configuration.OSDisk.SizeGiB), "networkAccessPolicy": "DenyAll", "publicNetworkAccess": "Disabled", "creationData": map[string]any{"createOption": "FromImage", "imageReference": map[string]any{"id": fixture.state.Configuration.VMImageResourceID}}})
	disk["sku"] = map[string]any{"name": fixture.state.Configuration.OSDisk.StorageAccountType}
	publicKeys := []any{}
	if bootstrap {
		publicKeys = append(publicKeys, map[string]any{"path": "/home/nvt-bootstrap/.ssh/authorized_keys", "keyData": fixture.state.BootstrapPublicKey})
	}
	vm := resource(fixture.state.Resources.VM, map[string]any{
		"provisioningState": "Succeeded",
		"hardwareProfile":   map[string]any{"vmSize": fixture.state.Configuration.VMSize},
		"osProfile": map[string]any{
			"adminUsername": "nvt-bootstrap", "allowExtensionOperations": false, "requireGuestProvisionSignal": false,
			"linuxConfiguration": map[string]any{
				"disablePasswordAuthentication": true, "provisionVMAgent": false, "ssh": map[string]any{"publicKeys": publicKeys},
			},
		},
		"storageProfile": map[string]any{"imageReference": map[string]any{"id": fixture.state.Configuration.VMImageResourceID}, "osDisk": map[string]any{
			"name": resourceName(fixture.state.Resources.OSDisk), "createOption": "FromImage", "deleteOption": "Detach", "osType": "Linux",
			"diskSizeGB":  float64(fixture.state.Configuration.OSDisk.SizeGiB),
			"managedDisk": map[string]any{"id": fixture.state.Resources.OSDisk, "storageAccountType": fixture.state.Configuration.OSDisk.StorageAccountType},
		}},
		"networkProfile": map[string]any{"networkInterfaces": []any{map[string]any{
			"id": fixture.state.Resources.NIC, "properties": map[string]any{"deleteOption": "Detach", "primary": true},
		}}},
		"diagnosticsProfile": map[string]any{"bootDiagnostics": map[string]any{"enabled": false}},
	})
	return map[string]map[string]any{fixture.state.Resources.NSG: nsg, fixture.state.Resources.NIC: nic, fixture.state.Resources.OSDisk: disk, fixture.state.Resources.VM: vm}
}

func (fixture *fakeARM) deploymentReadback() map[string]any {
	tags := map[string]any{}
	for key, value := range ownershipTags(fixture.state) {
		tags[key] = value
	}
	if fixture.foreignDeploy {
		tags["nvt-execution-id"] = "another-run"
	}
	provisioningState := fixture.deploymentState
	if provisioningState == "" {
		provisioningState = "Succeeded"
	}
	return map[string]any{
		"id": fixture.state.Resources.Deployment, "name": resourceName(fixture.state.Resources.Deployment),
		"type": "Microsoft.Resources/deployments", "tags": tags,
		"properties": map[string]any{"provisioningState": provisioningState, "mode": "Incremental"},
	}
}

func cloneAnyMap(value map[string]any) map[string]any {
	result := map[string]any{}
	for key, item := range value {
		result[key] = item
	}
	return result
}

func testARMOptions(endpoint string) *arm.ClientOptions {
	target, _ := url.Parse(endpoint)
	return &arm.ClientOptions{ClientOptions: azcore.ClientOptions{Transport: &http.Client{Transport: rewriteTransport{target: target}}}}
}

type rewriteTransport struct{ target *url.URL }

func (transport rewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.URL.Scheme, copy.URL.Host = transport.target.Scheme, transport.target.Host
	response, err := http.DefaultTransport.RoundTrip(copy)
	if response != nil {
		response.Request = request
	}
	return response, err
}
func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
