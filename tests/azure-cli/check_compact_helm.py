"""Exercise the documented compact substitutions through the unchanged chart."""
import importlib.util
from pathlib import Path
import subprocess
import yaml

root = Path(__file__).resolve().parents[2]
overlay = yaml.safe_load((root / "examples/azure/helm-values.yaml").read_text())
local = yaml.safe_load((root / "examples/azure/compact.example.yaml").read_text())
providers = []
grants = []
metadata = {}
for name, intent in local["brokerProviders"].items():
    tenant = intent["config"]["tenant"]
    providers.append({"name": name, **intent, "config": {**intent["config"], "state-dir": "/state/azure/"+name}})
    grants.append({"provider": name, "resources": ["provider-scope/"+tenant, "query-identity/"+tenant],
                   "materialization": "header-inject", "egressHosts": ["management.azure.com:443", "api.loganalytics.io:443"],
                   "authorization": {"preset": "observe", "resourcePrefix": "azure/"}})
    metadata[name] = {"tenant": tenant, "catalog": True}
overlay["broker"]["config"]["providers"] = providers
profile = overlay["agentSchedule"]["profiles"][0]
profile["broker"]["grants"] = grants
profile["agentRuntimeConfig"]["proxy"]["provider"] = "azure-one"
plugin = overlay["agentSchedule"]["template"]["agent"]["config"]["plugins"][0]
plugin["egress"]["provider"] = "azure-one"
plugin["config"]["providers"] = metadata
rendered = subprocess.check_output(["helm", "template", "nvt", str(root / "charts/nvt"), "-n", "nvt", "-f", "-"], input=yaml.safe_dump(overlay).encode())
documents = list(yaml.safe_load_all(rendered))
schedule = next(d for d in documents if d and d.get("kind") == "AgentSchedule")
assert schedule["spec"]["profiles"][0]["broker"]["grants"] == grants
configmap = next(d for d in documents if d and d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "nvt-broker-config")
broker = yaml.safe_load(configmap["data"]["broker.yaml"])
assert broker["providers"] == providers
spec = importlib.util.spec_from_file_location("provider", root / "broker/providers/azure/provider.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for provider in broker["providers"]:
    assert "catalog" in module.AzureProvider(provider).initialize_result()["capabilities"]
print("Compact two-identity Helm rendering and lazy provider initialization passed")
