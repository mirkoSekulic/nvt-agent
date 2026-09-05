package controller

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	utilvalidation "k8s.io/apimachinery/pkg/util/validation"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

func NetworkPolicyCapable() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("NVT_NETWORK_POLICY_CAPABLE")))
	return value == "1" || value == "true" || value == "yes"
}

// DeploymentDenyCIDRs combines the built-in IANA non-public/transition ranges
// with deployment-specific cluster, Pod, Service, node, and VNet ranges.
func DeploymentDenyCIDRs() ([]string, error) {
	values := append([]string(nil), builtInEgressDenyCIDRs...)
	if configured := strings.TrimSpace(os.Getenv("NVT_EGRESS_DENY_CIDRS")); configured != "" {
		for _, value := range strings.Split(configured, ",") {
			value = strings.TrimSpace(value)
			if value != "" {
				values = append(values, value)
			}
		}
	}
	return normalizeCIDRs(values)
}

func normalizeCIDRs(values []string) ([]string, error) {
	unique := map[string]netip.Prefix{}
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid egress deny CIDR %q: %w", value, err)
		}
		prefix = prefix.Masked()
		unique[prefix.String()] = prefix
	}
	prefixes := make([]netip.Prefix, 0, len(unique))
	for _, prefix := range unique {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Addr().BitLen() != prefixes[j].Addr().BitLen() {
			return prefixes[i].Addr().BitLen() < prefixes[j].Addr().BitLen()
		}
		if prefixes[i].Bits() != prefixes[j].Bits() {
			return prefixes[i].Bits() < prefixes[j].Bits()
		}
		if prefixes[i].Addr() != prefixes[j].Addr() {
			return prefixes[i].Addr().Less(prefixes[j].Addr())
		}
		return false
	})
	normalized := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		covered := false
		for _, existing := range normalized {
			if existing.Contains(prefix.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			normalized = append(normalized, prefix)
		}
	}
	result := make([]string, 0, len(normalized))
	for _, prefix := range normalized {
		result = append(result, prefix.String())
	}
	return result, nil
}

// ExternalTCPPorts is the single operator-side port contract rendered into
// both egressd and its NetworkPolicy.
func ExternalTCPPorts() ([]int, error) {
	values := append([]int(nil), defaultExternalTCPPorts...)
	if configured := strings.TrimSpace(os.Getenv("NVT_EGRESS_ALLOWED_TCP_PORTS")); configured != "" {
		values = nil
		for _, raw := range strings.Split(configured, ",") {
			port, err := strconv.Atoi(strings.TrimSpace(raw))
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid external TCP port %q", raw)
			}
			values = append(values, port)
		}
	}
	seen := map[int]bool{}
	result := values[:0]
	for _, port := range values {
		if !seen[port] {
			seen[port] = true
			result = append(result, port)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("external TCP ports must not be empty")
	}
	sort.Ints(result)
	return result, nil
}

// BrokerURL is the broker base URL the operator wires into agent and egressd
// containers. The chart sets NVT_BROKER_URL=https://nvt-broker:7347 when
// broker TLS is enabled; the default stays plaintext so local/dev setups and
// existing deployments are unchanged.
func BrokerURL() string {
	if url := strings.TrimSpace(os.Getenv("NVT_BROKER_URL")); url != "" {
		return url
	}
	return defaultBrokerURL
}

// brokerIsTLS reports whether the broker leg is https, which requires the CA
// certificate to be distributed to egressd and the agent.
func brokerIsTLS() bool {
	return strings.HasPrefix(BrokerURL(), "https://")
}

// BrokerCASecretName is the Secret holding the broker's CA certificate
// (public material, key ca.crt). Empty means none configured.
func BrokerCASecretName() string {
	return strings.TrimSpace(os.Getenv("NVT_BROKER_CA_SECRET"))
}

// brokerCADistributed reports whether the operator both talks TLS to the
// broker and knows which Secret carries the CA — the precondition for
// mounting it and rendering broker_ca_file.
func brokerCADistributed() bool {
	return brokerIsTLS() && BrokerCASecretName() != ""
}

// BrandingConfigMapName is the optional administrator-owned ConfigMap whose
// fixed public asset keys replace the runtime's built-in browser branding.
func BrandingConfigMapName() string {
	return strings.TrimSpace(os.Getenv("NVT_BRANDING_CONFIGMAP"))
}

// ValidateBrandingConfig rejects names Kubernetes cannot mount. The fixed-key
// volume projection performs the remaining fail-closed check: a missing
// ConfigMap or asset key prevents the agent Pod from starting.
func ValidateBrandingConfig() error {
	name := BrandingConfigMapName()
	if name == "" {
		return nil
	}
	if problems := utilvalidation.IsDNS1123Subdomain(name); len(problems) != 0 {
		return fmt.Errorf("NVT_BRANDING_CONFIGMAP must be a valid Kubernetes ConfigMap name: %s", strings.Join(problems, "; "))
	}
	return nil
}

// ValidateBrokerTLSConfig rejects the half-configured TLS state: an https
// broker URL with no CA Secret would render Pods whose brokerctl/egressd
// calls all fail TLS verification at runtime. Checked at operator startup
// and again on every render/validation path as defense in depth.
func ValidateBrokerTLSConfig() error {
	if brokerIsTLS() && BrokerCASecretName() == "" {
		return fmt.Errorf(
			"NVT_BROKER_URL %s is https but NVT_BROKER_CA_SECRET is not set; trusted broker clients need the broker CA Secret (key %s) to verify the broker",
			BrokerURL(), brokerCAKey,
		)
	}
	return nil
}

// DefaultEgressMode is the cluster's creation-time default egress mode, read
// from NVT_DEFAULT_EGRESS_MODE (empty means direct). It is applied ONCE, at
// AgentRun creation on the nvt admission path (ApplyDefaultEgressMode) — never
// at reconcile time, so flipping the knob can never reclassify an existing
// run (the #62/#63 retroactive-reclassification hazard). AgentRunEgressMode
// deliberately does not read this env.
func DefaultEgressMode() nvtv1alpha1.AgentRunEgressMode {
	mode := strings.TrimSpace(os.Getenv("NVT_DEFAULT_EGRESS_MODE"))
	if mode == "" {
		return nvtv1alpha1.AgentRunEgressDirect
	}
	return nvtv1alpha1.AgentRunEgressMode(mode)
}

// ValidateDefaultEgressMode fails fast (operator startup) on a bad knob value.
func ValidateDefaultEgressMode() error {
	mode := DefaultEgressMode()
	if mode != nvtv1alpha1.AgentRunEgressDirect && mode != nvtv1alpha1.AgentRunEgressMediated {
		return fmt.Errorf("NVT_DEFAULT_EGRESS_MODE must be direct or mediated, got %q", mode)
	}
	return nil
}

// ApplyDefaultEgressMode stamps the cluster default into spec.egress when the
// incoming run leaves it empty, so the stored object is always explicit and a
// later knob change can never alter it. It never overrides an explicit mode.
func ApplyDefaultEgressMode(agentRun *nvtv1alpha1.AgentRun) {
	if agentRun.Spec.Egress == "" {
		agentRun.Spec.Egress = DefaultEgressMode()
	}
}

// AllowInsecureUpstreamsEnabled reports whether the cluster opted into the
// per-grant allowInsecureUpstream escape hatch via NVT_ALLOW_INSECURE_UPSTREAMS.
// It exists only so hermetic in-cluster test fixtures are reachable; a real
// deployment never sets it, so a plaintext upstream leg carrying an injected
// credential cannot be requested by an AgentRun spec.
func AllowInsecureUpstreamsEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("NVT_ALLOW_INSECURE_UPSTREAMS"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// AgentRunBrokerID returns the broker identity for an AgentRun.
func AgentRunBrokerID(namespace, name string) string {
	return namespace + "/" + name
}

func AgentRunEgressBrokerID(namespace, name string) string {
	return namespace + "/" + name + "-egress"
}

func AgentRunEgressMode(agentRun *nvtv1alpha1.AgentRun) nvtv1alpha1.AgentRunEgressMode {
	if agentRun.Spec.Egress == "" {
		return nvtv1alpha1.AgentRunEgressDirect
	}
	return agentRun.Spec.Egress
}

func AgentRunBrokerGrants(broker *nvtv1alpha1.AgentRunBroker) []nvtv1alpha1.AgentRunBrokerGrant {
	if broker == nil || broker.Grants == nil {
		return []nvtv1alpha1.AgentRunBrokerGrant{}
	}
	return broker.Grants
}

func AgentRunGrantMaterialization(grant nvtv1alpha1.AgentRunBrokerGrant) nvtv1alpha1.AgentRunGrantMaterialization {
	if grant.Materialization == "" {
		return nvtv1alpha1.AgentRunGrantFileBundle
	}
	return grant.Materialization
}

func ValidateAgentRunEgressMode(agentRun *nvtv1alpha1.AgentRun) error {
	if err := ValidateRemovedEgressForwardProxy(agentRun); err != nil {
		return err
	}
	if err := ValidateBrokerTLSConfig(); err != nil {
		return err
	}
	if _, err := DeploymentDenyCIDRs(); err != nil {
		return err
	}
	if _, err := ExternalTCPPorts(); err != nil {
		return err
	}
	mode := AgentRunEgressMode(agentRun)
	if mode != nvtv1alpha1.AgentRunEgressDirect && mode != nvtv1alpha1.AgentRunEgressMediated {
		return fmt.Errorf("spec.egress must be direct or mediated, got %q", mode)
	}
	if agentRun.Spec.EgressEnforcement && mode != nvtv1alpha1.AgentRunEgressMediated {
		return fmt.Errorf("spec.egressEnforcement requires spec.egress mediated, got %q", mode)
	}
	transport := AgentRunEgressTransport(agentRun)
	if err := validateEgressDomainPolicy(agentRun.Spec.EgressDomainPolicy); err != nil {
		return fmt.Errorf("spec.egressDomainPolicy: %w", err)
	}
	if err := validateEgressMaxConcurrentTunnels(agentRun.Spec.EgressMaxConcurrentTunnels); err != nil {
		return err
	}
	if agentRun.Spec.EgressMaxConcurrentTunnels != 0 &&
		transport != nvtv1alpha1.AgentRunEgressTransportForwardProxy &&
		transport != nvtv1alpha1.AgentRunEgressTransportTransparent {
		return fmt.Errorf("spec.egressMaxConcurrentTunnels requires spec.egressTransport forward-proxy or transparent")
	}
	switch transport {
	case nvtv1alpha1.AgentRunEgressTransportRedirect,
		nvtv1alpha1.AgentRunEgressTransportForwardProxy,
		nvtv1alpha1.AgentRunEgressTransportTransparent:
	default:
		return fmt.Errorf("spec.egressTransport must be redirect, forward-proxy, or transparent, got %q", transport)
	}
	if transport != nvtv1alpha1.AgentRunEgressTransportRedirect && (!agentRun.Spec.EgressEnforcement || mode != nvtv1alpha1.AgentRunEgressMediated) {
		return fmt.Errorf("spec.egressTransport %s requires spec.egress mediated and spec.egressEnforcement", transport)
	}
	if agentRun.Spec.EgressDomainPolicy != nil &&
		(mode != nvtv1alpha1.AgentRunEgressMediated || !agentRun.Spec.EgressEnforcement ||
			(transport != nvtv1alpha1.AgentRunEgressTransportForwardProxy && transport != nvtv1alpha1.AgentRunEgressTransportTransparent)) {
		return fmt.Errorf("spec.egressDomainPolicy requires mediated, enforced forward-proxy or transparent egress")
	}
	if transport == nvtv1alpha1.AgentRunEgressTransportTransparent && !NetworkPolicyCapable() {
		return fmt.Errorf("spec.egressTransport transparent requires a NetworkPolicy-capable deployment")
	}
	headerInjectGrants := 0
	preparations := map[string]bool{}
	if mode == nvtv1alpha1.AgentRunEgressMediated {
		if agentRun.Spec.RuntimeAuth != nil {
			return fmt.Errorf("egress mediated is incompatible with spec.runtimeAuth")
		}
		if strings.HasPrefix(BrokerURL(), "http://") && !agentRun.Spec.EgressAllowInsecureBroker {
			return fmt.Errorf("egress mediated with plaintext broker requires spec.egressAllowInsecureBroker=true for local/dev use")
		}
	}
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		seenResources := map[string]struct{}{}
		if len(grant.Resources) > 256 {
			return fmt.Errorf("broker grant %s resources exceeds 256 entries", grant.Provider)
		}
		for _, resource := range grant.Resources {
			if resource == "" || len(resource) > 4096 {
				return fmt.Errorf("broker grant %s resources require bounded non-empty values", grant.Provider)
			}
			if _, duplicate := seenResources[resource]; duplicate {
				return fmt.Errorf("broker grant %s resources contains a duplicate", grant.Provider)
			}
			seenResources[resource] = struct{}{}
		}
		for _, preparation := range grant.Preparations {
			if preparation.Operation != nvtv1alpha1.AgentRunBrokerPreparationIdentity {
				return fmt.Errorf("broker grant %s preparation operation must be identity, got %q", grant.Provider, preparation.Operation)
			}
			key := grant.Provider + "\x00" + string(preparation.Operation)
			if preparations[key] {
				return fmt.Errorf("broker grant preparation %s/%s is duplicated", grant.Provider, preparation.Operation)
			}
			preparations[key] = true
		}
		materialization := AgentRunGrantMaterialization(grant)
		switch materialization {
		case nvtv1alpha1.AgentRunGrantFileBundle, nvtv1alpha1.AgentRunGrantHeaderInject, nvtv1alpha1.AgentRunGrantPlaceholderFile:
		default:
			return fmt.Errorf("broker grant %s materialization must be file-bundle, header-inject, or placeholder-file, got %q", grant.Provider, materialization)
		}
		// header-inject and placeholder-file are zero-possession mediated modes:
		// both are rejected in direct mode (no edge to inject at) and file-bundle
		// is rejected in mediated mode (writes usable material into the container).
		if mode == nvtv1alpha1.AgentRunEgressDirect && materialization != nvtv1alpha1.AgentRunGrantFileBundle {
			return fmt.Errorf("egress direct is incompatible with broker grant %s materialization %s", grant.Provider, materialization)
		}
		if mode == nvtv1alpha1.AgentRunEgressMediated && materialization == nvtv1alpha1.AgentRunGrantFileBundle {
			return fmt.Errorf("egress mediated is incompatible with broker grant %s materialization file-bundle", grant.Provider)
		}
		if grant.Git && materialization != nvtv1alpha1.AgentRunGrantHeaderInject {
			return fmt.Errorf("broker grant %s git requires materialization header-inject", grant.Provider)
		}
		for key, value := range grant.Permissions {
			if key == "" || (value != "read" && value != "write") {
				return fmt.Errorf("broker grant %s permissions must map permission names to read or write", grant.Provider)
			}
		}
		if grant.Authorization != nil {
			if grant.Authorization.Preset != "" || grant.Authorization.ResourcePrefix != "" {
				return fmt.Errorf("broker grant %s authorization.preset must be resolved before AgentRun admission", grant.Provider)
			}
			if grant.Authorization.DefaultAction != "allow" && grant.Authorization.DefaultAction != "deny" {
				return fmt.Errorf("broker grant %s authorization.defaultAction must be allow or deny", grant.Provider)
			}
			if len(grant.Authorization.Rules) > 256 {
				return fmt.Errorf("broker grant %s authorization.rules exceeds 256 entries", grant.Provider)
			}
			for _, rule := range grant.Authorization.Rules {
				if rule.Operation == "" || len(rule.Operation) > 4096 || rule.Resource == "" || len(rule.Resource) > 8192 {
					return fmt.Errorf("broker grant %s authorization rules require bounded operation and resource", grant.Provider)
				}
			}
		}
		if grant.Quota != nil && grant.Quota.Requests <= 0 {
			return fmt.Errorf("broker grant %s quota.requests must be a positive integer", grant.Provider)
		}
		if grant.AllowInsecureUpstream {
			// A plaintext upstream leg carries the injected credential in the
			// clear, so this is gated to a cluster/test opt-in and never
			// allowed for git (git creds ride the TLS-terminated redirect).
			if grant.Git {
				return fmt.Errorf("broker grant %s must not set allowInsecureUpstream on a git grant", grant.Provider)
			}
			if !AllowInsecureUpstreamsEnabled() {
				return fmt.Errorf("broker grant %s sets allowInsecureUpstream, which requires the operator's NVT_ALLOW_INSECURE_UPSTREAMS opt-in (test/dev only)", grant.Provider)
			}
		}
		if mode == nvtv1alpha1.AgentRunEgressMediated && materialization == nvtv1alpha1.AgentRunGrantHeaderInject {
			headerInjectGrants++
			if len(grant.EgressHosts) == 0 {
				return fmt.Errorf("egress mediated broker grant %s requires egressHosts", grant.Provider)
			}
			for _, host := range grant.EgressHosts {
				if !validEgressHost(host) {
					return fmt.Errorf("egress mediated broker grant %s has invalid egressHosts entry %q", grant.Provider, host)
				}
			}
		}
		// In forward-proxy mode a placeholder-file grant's egressHosts become
		// MITM routes, so validate them too.
		if AgentRunEgressForwardProxy(agentRun) && materialization == nvtv1alpha1.AgentRunGrantPlaceholderFile {
			for _, host := range grant.EgressHosts {
				if !validEgressHost(host) {
					return fmt.Errorf("forward-proxy broker grant %s has invalid egressHosts entry %q", grant.Provider, host)
				}
			}
		}
	}
	if AgentRunEgressForwardProxy(agentRun) {
		// Forward-proxy makes every injection-capable grant's egressHosts
		// routable, so the run needs at least one such host — but no longer a
		// header-inject grant specifically.
		injects := forwardProxyInjects(agentRun)
		if len(injects) == 0 {
			return fmt.Errorf("spec.egressTransport %s requires at least one header-inject or placeholder-file broker grant with egressHosts", transport)
		}
		// Mirror egressd's inject-route rules at admission so a config egressd
		// would reject at boot fails loudly here instead of CrashLooping a
		// silently-broken run: MITM hosts must be DNS names (SNI/leaf need a
		// name), and each normalized host/capability pair is unique. A host may
		// map to more than one capability; egressd then requires an explicit
		// non-secret capability hint on the CONNECT request and fails closed
		// without one.
		claimedBy := map[string]bool{}
		for _, inject := range injects {
			if net.ParseIP(inject.Host) != nil {
				return fmt.Errorf("forward-proxy egressHost %q must be a DNS name, not an IP (TLS-MITM needs a name for SNI/leaf)", inject.Host)
			}
			key := inject.Host + "\x00" + inject.Capability
			if claimedBy[key] {
				return fmt.Errorf("forward-proxy host %q is duplicated for broker grant %s", inject.Host, inject.Capability)
			}
			claimedBy[key] = true
			if agentRun.Spec.EgressDomainPolicy != nil && !egressDomainAllowed(*agentRun.Spec.EgressDomainPolicy, inject.Host) {
				return fmt.Errorf("forward-proxy host %q required by broker grant %s is denied by spec.egressDomainPolicy", inject.Host, inject.Capability)
			}
		}
		return nil
	}
	if mode == nvtv1alpha1.AgentRunEgressMediated && headerInjectGrants == 0 {
		// Non-forward-proxy mediated runs still need a header-inject route:
		// placeholder-file grants are materialized but not routed without the
		// forward proxy.
		return fmt.Errorf("egress mediated requires at least one header-inject broker grant with egressHosts")
	}
	return nil
}

func validateEgressDomainPolicy(policy *nvtv1alpha1.AgentRunEgressDomainPolicy) error {
	if policy == nil {
		return nil
	}
	if policy.DefaultAction != nvtv1alpha1.AgentRunEgressDomainAllow && policy.DefaultAction != nvtv1alpha1.AgentRunEgressDomainDeny {
		return fmt.Errorf("defaultAction must be allow or deny")
	}
	if len(policy.Allow) > 256 || len(policy.Deny) > 256 {
		return fmt.Errorf("allow and deny must contain at most 256 entries each")
	}
	for _, list := range []struct {
		name    string
		entries []string
	}{{"allow", policy.Allow}, {"deny", policy.Deny}} {
		name, entries := list.name, list.entries
		seen := map[string]bool{}
		for index, entry := range entries {
			normalized, err := normalizeEgressDomain(entry)
			if err != nil {
				return fmt.Errorf("%s[%d]: %w", name, index, err)
			}
			if seen[normalized] {
				return fmt.Errorf("%s[%d] duplicates %q after normalization", name, index, normalized)
			}
			seen[normalized] = true
		}
	}
	return nil
}

func normalizeEgressDomain(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "/\\@?#: \t\r\n%") {
		return "", fmt.Errorf("must be a DNS domain")
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if net.ParseIP(value) != nil {
		return "", fmt.Errorf("must be a DNS domain")
	}
	if value == "" || len(value) > 253 {
		return "", fmt.Errorf("has invalid length")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("has an invalid DNS label")
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return "", fmt.Errorf("must be an ASCII DNS domain")
		}
	}
	return value, nil
}

func egressDomainAllowed(policy nvtv1alpha1.AgentRunEgressDomainPolicy, host string) bool {
	normalized, err := normalizeEgressDomain(host)
	if err != nil {
		return policy.DefaultAction == nvtv1alpha1.AgentRunEgressDomainAllow
	}
	for _, rule := range policy.Deny {
		normalizedRule, _ := normalizeEgressDomain(rule)
		if normalized == normalizedRule || strings.HasSuffix(normalized, "."+normalizedRule) {
			return false
		}
	}
	for _, rule := range policy.Allow {
		normalizedRule, _ := normalizeEgressDomain(rule)
		if normalized == normalizedRule || strings.HasSuffix(normalized, "."+normalizedRule) {
			return true
		}
	}
	return policy.DefaultAction == nvtv1alpha1.AgentRunEgressDomainAllow
}

func normalizeEgressDomains(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized, err := normalizeEgressDomain(value)
		if err == nil {
			result = append(result, normalized)
		}
	}
	return result
}

func validateEgressMaxConcurrentTunnels(value int32) error {
	if value < 0 || value > 4096 {
		return fmt.Errorf("spec.egressMaxConcurrentTunnels must be between 1 and 4096 when set, got %d", value)
	}
	return nil
}

func agentRunHasProviderPreparations(agentRun *nvtv1alpha1.AgentRun) bool {
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		if len(grant.Preparations) > 0 {
			return true
		}
	}
	return false
}

// agentRunHasGitGrant reports whether any header-inject grant is git-typed,
// which requires the per-agent CA volume and a TLS route.
func agentRunHasGitGrant(agentRun *nvtv1alpha1.AgentRun) bool {
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		if grant.Git && AgentRunGrantMaterialization(grant) == nvtv1alpha1.AgentRunGrantHeaderInject {
			return true
		}
	}
	return false
}

// ValidateRemovedEgressForwardProxy rejects the pre-1.0 compatibility field.
// The pointer exists only so API decoding and CRD validation can distinguish
// omission from explicit false; it never selects egress behavior.
func ValidateRemovedEgressForwardProxy(agentRun *nvtv1alpha1.AgentRun) error {
	if agentRun.Spec.EgressForwardProxy != nil {
		return fmt.Errorf("spec.egressForwardProxy is removed; use spec.egressTransport")
	}
	return nil
}

func validEgressHost(value string) bool {
	if value == "" || strings.Contains(value, "://") || strings.Contains(value, "/") || strings.Contains(value, "@") {
		return false
	}
	host := value
	if before, after, ok := strings.Cut(value, ":"); ok {
		if before == "" || after == "" {
			return false
		}
		host = before
	}
	return strings.TrimSpace(host) == host && host != "" && !strings.HasPrefix(host, ".") && !strings.HasSuffix(host, ".")
}
