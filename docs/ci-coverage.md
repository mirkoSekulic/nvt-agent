# CI coverage

CI covers the supported Kubernetes Pod and local Docker execution paths.

- Operator unit and kind suites validate default Pod execution, RuntimeClass
  selection (including Kata), lifecycle, persistence, cleanup, and routing.
- Broker, egressd, captured, gateway, and runtime suites validate mediated
  credentials, transparent capture, and zero-secret agent containers.
- Local platform and controller suites validate workstation and disposable
  Docker workflows, producers, local gateway routing, and lifecycle cleanup.
- Helm tests validate the supported chart resources, values, and generated
  AgentRun and AgentSchedule CRDs.
