# Zero-possession kubeconfig mediation

The local workstation backend can publish ordinary Kubernetes contexts without
placing the private kubeconfig or its bearer credentials in the agent. The
generic `kubeconfig` executable provider reads administrator-controlled input,
publishes a sanitized `$HOME/.kube/config`, and resolves credentials only when
the paired `egressd` identity requests injection.

```yaml
secrets:
  cluster-config:
    file: ./.nvt-local/secrets/kubernetes/config

brokerProviders:
  clusters:
    plugin: kubeconfig
    config:
      helper-allowlist: [kubelogin]
      helper-timeout-seconds: 30
      helper-environment:
        - name: AZURE_CONFIG_DIR
          value: state:azure
    secrets:
      private-kubeconfig: cluster-config

profiles:
  development:
    # normal runtime fields omitted
    kubernetes:
      - provider: clusters
        contexts: [development-aks, shared-services-aks]
```

Context, cluster, auth-info, namespace, and current-context names are retained.
Users in the published file are empty objects and cluster servers are stable
per-context mediated names. The local backend adds Kubernetes' standard
per-cluster `proxy-url` with the provider capability selector, so Kubernetes
traffic remains unambiguous when the same workstation also has Codex, Claude,
Git, or another provider on its global proxy. The update is atomic. If the user selected a
current context with `kubectx`, a later bootstrap preserves that selection only
when it remains in the newly granted catalog; a removed context cannot survive
an update.

Profiles may select more than one kubeconfig provider instance. The controller
merges their sanitized documents into one kubeconfig, retaining the first
provider's valid current context and coalescing identical empty auth-info
entries. Context and cluster names must remain unambiguous across instances;
collisions fail closed instead of silently routing through the wrong identity.

The first implementation accepts private static bearer tokens and Kubernetes
`ExecCredential` helpers returning `status.token`. Helper commands execute
directly without a shell and must match `helper-allowlist`. They receive a
minimal environment, a provider-instance `HOME`, optional configured
environment entries, and their kubeconfig-declared environment. Values such as
`state:azure` resolve beneath the instance's private writable state directory.
ExecCredential tokens with an expiration are refreshed before that expiration;
results without an `expirationTimestamp` are cached for at most 60 seconds.
This execution is behind an internal `CredentialExecutor` seam so it can later
be replaced by another trusted implementation without changing broker,
`egressd`, runtime, or agent contracts.

Client-certificate/client-key kubeconfigs, exec results containing client
certificate data, auth-provider entries, basic authentication, missing CA
pins, and unapproved helpers fail closed with sanitized errors. No Azure,
AWS, Google, AKS, EKS, or GKE authentication behavior exists in core. Helpers
such as `kubelogin`, `aws`, or `gke-gcloud-auth-plugin` are administrator
packaging and configuration choices; cloud discovery and kubeconfig sync stay
outside this contract.

Each catalog route freezes its exact API endpoint, TLS server identity, and CA
from trusted kubeconfig input. `egressd` may resolve a private address only for
that exact route. Under a strict domain policy, the synthetic mediated host is
still policy-checked while the trusted pinned upstream—including an IP
literal—is not treated as workload-selected general egress. It always removes agent `Authorization`,
`Proxy-Authorization`, and `Impersonate-*` headers, injects the provider token,
and uses its existing bounded 60-second material cache. Broker/provider errors,
expiry, grant removal, and refresh failures fail closed. Existing response
streaming and HTTP upgrade relays cover reads, watches, streaming logs, exec,
copy, and port-forward protocol paths.

The local backend supplies the explicit loopback proxy and matching durable-CA
constraints for forward-proxy, transparent, and redirect transports.

The catalog is snapshotted when the local run is prepared. Updating the trusted
private kubeconfig requires broker restart and run reconciliation in this first
delivery; automatic discovery and synchronization are intentionally out of
scope. If one kubeconfig cluster name is reused by contexts with different
auth-info identities, initialization fails closed because preserving that one
cluster name cannot also encode two distinct credential routes.
