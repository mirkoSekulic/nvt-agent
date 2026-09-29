"""Run the real exported CLI with an actual local/operator-rendered agent env.

Relocate mount paths and the egress listener into isolated fixtures; never add
broker credentials. The egress TLS/protocol suite tests the real metadata relay.
"""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

environment = json.load(sys.stdin)
assert not any(k.startswith("NVT_BROKER_") for k in environment)
tenant, subscription = "22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111"


class Catalog(BaseHTTPRequestHandler):
    def do_GET(self):
        assert self.path == "/_nvt/catalog"
        assert self.headers.get("Authorization") is None
        assert self.headers.get("Proxy-Authorization") == "Basic " + base64.b64encode(b"azure-one:x").decode()
        metadata = {"tenant": tenant, "subscriptions": [{"id": subscription, "name": "Public fixture"}]}
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True, "files": [{"path": "azure-account-metadata.json", "content": json.dumps(metadata)}], "expires_at": None}).encode())

    def log_message(self, *args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), Catalog)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        config = home / "plugin.json"
        config.write_text(json.dumps({"providers": {"azure-one": {"tenant": tenant, "catalog": True}}}))
        # Only paths/service addresses change; preserve the renderer's lack of
        # secret environment and add the usual bootstrap public proxy selector.
        environment.update({"HOME": tmp, "NVT_WORKSPACE": tmp, "NVT_STATE_DIR": str(home / ".nvt-agent"),
                            "NVT_PLUGIN_CONFIG": str(config), "NVT_PLUGIN_EGRESS_PROVIDER": "azure-one",
                            "NVT_EGRESS_FORWARD_PROXY_URL_AZURE_ONE": f"http://azure-one:x@127.0.0.1:{server.server_port}",
                            "PATH": str(home / ".local/bin")+":"+str(home / "fixture-bin")})
        environment.pop("NVT_EGRESS_CA_FILE", None)  # plaintext loopback fixture
        fixture = Path(__file__).with_name("export_fixture.py")
        subprocess.run([sys.executable, str(fixture), sys.executable], env=environment, check=True, capture_output=True)
        result = subprocess.run([str(home / ".local/bin/az"), "account", "list"], env=environment, check=True, capture_output=True)
        assert json.loads(result.stdout)[0]["id"] == subscription
        print("Rendered zero-secret environment: exported az account list passed")
finally:
    server.shutdown()
    server.server_close()
    thread.join()
