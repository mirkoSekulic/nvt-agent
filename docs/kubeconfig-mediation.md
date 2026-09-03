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
        authorization:
          preset: observe
```

`authorization` is optional; omission preserves the existing context-scoped,
otherwise unrestricted behavior. `preset: observe` is compiler sugar for a
snapshotted generic default-deny policy with one `observe` rule for each exact
`context/<name>` resource. The preset and concrete form are mutually exclusive:

```yaml
authorization:
  defaultAction: deny
  rules:
    - operation: observe
      resource: context/development-aks
```

The local compiler resolves the preset before writing trusted controller or
broker grant configuration. AgentSchedule profiles do the same when they
create an AgentRun; raw AgentRuns and direct `agents.yaml` grants carry only
the concrete `defaultAction`/`rules` form. This snapshots preset semantics for
the lifetime of a run.

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
literal—is not treated as workload-selected general egress. CA inputs are
decoded and re-encoded as certificate-only PEM; private-key blocks and any
other trailing content fail closed before catalog publication. It always
removes agent `Authorization`, `Proxy-Authorization`, and `Impersonate-*`
headers, injects the provider token, and uses its existing bounded 60-second
material cache. Broker/provider errors,
expiry, grant removal, and refresh failures fail closed. Existing response
streaming and HTTP upgrade relays remain available to unrestricted grants. An
`observe` grant allows canonical discovery/version/OpenAPI/health GETs,
GET/LIST/WATCH reads of built-in and arbitrary custom resources, events,
describe-related reads, and pod logs. It denies Secret reads, every mutation,
exec, attach, port-forward, proxy and upgrade requests, token subresources,
unknown subresources, encoded or dot-segment paths, and ambiguous queries
before credential materialization. Flux and other clients need no special
configuration: inspection works only where it reduces to these Kubernetes API
reads, while reconcile/suspend/resume/create/delete/bootstrap-style writes are
denied.

Direct broker administrators may add the same concrete policy as a provider
ceiling. Both layers must allow the normalized operation/resource:

`broker.yaml` provider excerpt:

```yaml
providers:
  - name: clusters
    plugin: kubeconfig
    allow:
      resources: [development-aks]
      authorization:
        defaultAction: deny
        rules:
          - {operation: observe, resource: context/development-aks}
```

`agents.yaml` grant excerpt:

```yaml
agents:
  - id: diagnostics
    token-sha256: sha256:<hash>
    grants:
      - provider: clusters
        resources: [development-aks]
        materialization: header-inject
        authorization:
          defaultAction: deny
          rules:
            - {operation: observe, resource: context/development-aks}
```

This is defense in depth and does not replace least-privilege Kubernetes RBAC.

The local backend supplies the explicit loopback proxy and matching durable-CA
constraints for forward-proxy, transparent, and redirect transports.

The catalog is snapshotted when the local run is prepared. Updating the trusted
private kubeconfig requires broker restart and run reconciliation in this first
delivery; automatic discovery and synchronization are intentionally out of
scope. If one kubeconfig cluster name is reused by contexts with different
auth-info identities, initialization fails closed because preserving that one
cluster name cannot also encode two distinct credential routes.
