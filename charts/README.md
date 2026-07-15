# Helm Charts

The repository publishes two independent OCI Helm charts:

- `oci://ghcr.io/mirkosekulic/helm/nvt`
- `oci://ghcr.io/mirkosekulic/helm/nvt-github-comments-producer`

Each chart owns its version in its `Chart.yaml`. Chart versions follow semantic
versioning and are immutable after publication. `appVersion` is informational;
deployment image tags or digests remain explicit Helm values.

When chart content changes, update that chart's `version`. Pull-request CI
rejects a changed chart whose version was not updated. After merge to `main`,
the charts workflow packages and publishes only the changed charts and refuses
to overwrite a version already present in GHCR. Repository Git tags and GitHub
Releases are not part of chart versioning.

For the initial `0.1.0` publication, run the `charts` workflow manually with
`chart=all`. After the first push, set both GHCR packages to Public in their
GitHub package settings. Public charts can be pulled without credentials.

Install a published version with:

```sh
helm upgrade --install nvt \
  oci://ghcr.io/mirkosekulic/helm/nvt \
  --version 0.1.0 \
  --namespace nvt \
  --create-namespace
```

The producer is installed separately:

```sh
helm upgrade --install nvt-github-comments-producer \
  oci://ghcr.io/mirkosekulic/helm/nvt-github-comments-producer \
  --version 0.1.0 \
  --namespace nvt
```
