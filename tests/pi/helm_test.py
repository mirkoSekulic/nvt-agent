"""Check the public Pi Helm example against the rendered broker and profile."""

from pathlib import Path
import subprocess
import yaml

root = Path(__file__).resolve().parents[2]
raw = subprocess.check_output(
    [
        "helm",
        "template",
        "pi-test",
        str(root / "charts/nvt"),
        "-f",
        str(root / "examples/pi/values.example.yaml"),
    ],
    text=True,
)
objects = list(yaml.safe_load_all(raw))
schedule = next(o for o in objects if o.get("kind") == "AgentSchedule")
profile = schedule["spec"]["profiles"][0]
assert profile["runtime"]["type"] == "pi"
assert profile["runtime"]["autonomy"] == "trusted-local"
assert profile["runtime"]["credentialProvider"] == "model-api"
assert profile["agentRuntimeConfig"] == {"command": "pi"}
assert profile["broker"]["grants"][0]["materialization"] == "header-inject"
deployment = next(
    o
    for o in objects
    if o.get("kind") == "Deployment" and o["metadata"]["name"] == "nvt-broker"
)
volumes = deployment["spec"]["template"]["spec"]["volumes"]
seed = next(v for v in volumes if v["name"] == "broker-state-seed")
assert seed["secret"]["secretName"] == "pi-model-key"
assert seed["secret"]["defaultMode"] == 0o400
assert "FAKE-EXAMPLE-API-KEY" not in raw
assert "apiKey" not in raw
for obj in objects:
    if obj.get("kind") == "ConfigMap":
        assert "FAKE-EXAMPLE-API-KEY" not in str(obj)
print("Pi Helm profile and broker-only Secret binding passed")
