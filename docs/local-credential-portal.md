# Local credential management

Declaring a `codex-oauth` or `claude-oauth` account in `nvt.local.yaml`
automatically enables the local credential portal. Start with `make local-up`,
open `http://nvt.agent.localhost:4090`, and choose **Manage credentials**.

The manifest owns account names and presets. Slot names, portal configuration,
runner/session keys, broker provider paths, and seed handoff are generated in
labeled Docker volumes. OAuth values are written only to the portal seed
volume, imported by the broker seed supervisor, and retained in broker-private
canonical storage. They do not enter the workspace, generated configuration,
command arguments, environment values, or agent containers.
The portal persists each value under its generated slot name, and the broker
provider reads that same extensionless canonical filename after seed import.

`make local-down` preserves enrolled accounts. `make local-reset` explicitly
destroys their exact-owned volumes with the selected local project. Kubernetes
portal configuration, identity policy, and Secret patching remain unchanged.
