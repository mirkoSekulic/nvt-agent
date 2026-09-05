# Azure CLI adapter

Optional tool-only plugin exporting `az`. Install Azure CLI 2.89.1 and the
log-analytics 1.0.0b1 extension using the optional image layer. Configure
`egress.provider` and public `config.providers` account metadata, then grant
each provider through mediated egress. `NVT_AZURE_PROVIDER` selects a different
explicitly configured identity for an invocation.

This code owns no Azure credential and enforces no Azure authorization. It
provides an inert credential factory for the real CLI. Provider policy and
scope enforcement occur in the trusted broker before egress injection.

See [Azure CLI mediation](../../../docs/azure-cli-mediation.md) for enrollment,
configuration, versions, supported operations, query boundaries and tests.
