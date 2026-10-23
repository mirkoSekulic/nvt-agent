import sys
import yaml
from verify_policy import ROOT, verify

documents = list(yaml.safe_load_all(sys.stdin))
schedule = next(d for d in documents if d and d.get("kind") == "AgentSchedule")
grant = schedule["spec"]["profiles"][0]["broker"]["grants"][0]
configmap = next(d for d in documents if d and d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "nvt-broker-config")
provider = yaml.safe_load(configmap["data"]["broker.yaml"])["providers"][0]
direct = yaml.safe_load((ROOT / "examples/http-authorization/broker.yaml").read_text())["providers"][0]
local = yaml.safe_load((ROOT / "examples/http-authorization/manifest.example.yaml").read_text())
raw = yaml.safe_load((ROOT / "examples/http-authorization/agentrun.yaml").read_text())["spec"]["broker"]["grants"][0]
assert provider["allow"] == direct["allow"] == local["brokerProviders"]["api"]["allow"]
assert grant["authorization"] == raw["authorization"] == local["profiles"]["api-client"]["httpCredentials"][0]["authorization"]
assert grant["materialization"] == "header-inject"
verify([grant], provider)
