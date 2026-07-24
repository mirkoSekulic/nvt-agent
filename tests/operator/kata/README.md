# Real Kata Docker storage smoke

Ordinary Kind does not provide a Kata runtime and cannot prove virtiofs,
loop-device, xattr, or nested `overlay2` behavior. Run this gate against a
cluster where the coordinated chart is already installed, the selected
RuntimeClass schedules Kata VMs, and the persistent StorageClass is available:

```sh
KATA_DIND_CONTEXT=aks-staging \
KATA_DIND_NAMESPACE=nvt \
KATA_DIND_RUNTIME_CLASS=kata-vm-isolation \
KATA_DIND_STORAGE_CLASS=managed-csi \
KATA_DIND_RUNTIME_IMAGE=ghcr.io/mirkosekulic/nvt-agent-runtime:0.8.15-<release-sha> \
bash tests/operator/kata/dind-overlay2-smoke.sh
```

The smoke creates a persistent AgentRun and proves:

- only the Docker native sidecar is privileged and only it mounts the backing
  directory;
- `docker info` reports `overlay2`;
- a digest-pinned pgAdmin OCI image known to carry
  `security.capability` metadata pulls and unpacks successfully;
- a BuildKit build copies and hashes generated nested files successfully; and
- deleting the AgentRun removes its lifecycle-owned PVC.

The default pinned image is
`dpage/pgadmin4@sha256:8c128407f45f1c582eda69e71da1a393237388469052e3cc1e6ae4a475e12b70`.
Override it only with another immutable digest using `KATA_DIND_XATTR_IMAGE`.
The script deletes the smoke AgentRun on exit; set `KATA_DIND_KEEP=1` to retain
failed resources for diagnosis.
