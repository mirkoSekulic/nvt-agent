"""Real broker on an ephemeral loopback socket; all inputs are test-owned."""
from http.server import ThreadingHTTPServer
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from broker.core.server import Broker, make_handler

broker = Broker()
server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(broker))
print(f"http://127.0.0.1:{server.server_port}", flush=True)
try:
    server.serve_forever()
finally:
    server.server_close()
    broker.close()
