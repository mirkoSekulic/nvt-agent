# Helm chart

The project publishes one official OCI chart for the complete tested platform:

```text
oci://ghcr.io/mirkosekulic/helm/nvt
```

The chart version is the release SemVer. Publication derives one immutable
application/image identity from that version and the release commit. For
example, chart `0.2.0` released from commit `943d5ba...` has `appVersion`
`0.2.0-943d5ba`, and every default production image uses that exact tag.

```sh
helm upgrade --install nvt \
  oci://ghcr.io/mirkosekulic/helm/nvt \
  --version 0.2.0 \
  --namespace nvt \
  --create-namespace
```

The GitHub comments producer is part of this chart and is disabled by default.
Enable it with `producer.enabled=true`; there is no separately versioned or
published producer chart.

Chart versions are immutable. Pull-request validation requires a SemVer bump
whenever `charts/nvt` changes and rejects versions already present in GHCR.
The coordinated release builds or verifies all seven production image tags
from the same commit, verifies every manifest, and publishes the chart last.
Exact artifacts from an interrupted run are reused; conflicting artifacts fail
the release. A manual workflow dispatch from `main` safely retries a partial
publication. Repository Git tags are not required.
