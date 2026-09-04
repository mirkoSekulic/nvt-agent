"""Validate rendered Azure examples and consistency with direct/local intent."""
import importlib.util
from pathlib import Path
import sys
import yaml

root = Path(__file__).resolve().parents[2]
documents = list(yaml.safe_load_all(sys.stdin))
schedule = next(d for d in documents if d and d.get("kind") == "AgentSchedule")
grant = schedule["spec"]["profiles"][0]["broker"]["grants"][0]
assert grant["authorization"] == {"preset": "observe", "resourcePrefix": "azure/"}
assert grant["materialization"] == "header-inject"
configmap = next(d for d in documents if d and d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "nvt-broker-config")
broker = yaml.safe_load(configmap["data"]["broker.yaml"])
direct = yaml.safe_load((root / "examples/azure/broker.yaml").read_text())
assert broker == direct
local = yaml.safe_load((root / "examples/azure/manifest.example.yaml").read_text())
assert broker["providers"][0]["allow"] == local["brokerProviders"]["azure-dev"]["allow"]
assert grant["resources"] == local["profiles"]["azure-investigation"]["azure"][0]["resources"]
spec = importlib.util.spec_from_file_location("azure_provider", root / "broker/providers/azure/provider.py")
provider = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provider)
params = broker["providers"][0]
params["provider_instance_name"] = params.pop("name")
assert provider.AzureProvider(params).initialize_result()["injection_hosts"] == [provider.ARM, provider.LOGS]
crd = next(d for d in documents if d and d.get("kind") == "CustomResourceDefinition" and d["metadata"]["name"] == "agentschedules.nvt.dev")
assert "resourcePrefix" in str(crd)
print("Azure Helm/direct/local examples and provider initialization passed")
