import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path


class AuditLog:
    def __init__(self, path=None):
        self.path = Path(path or os.environ.get("NVT_BROKER_AUDIT_LOG", "/tmp/nvt-broker-audit.jsonl"))
        self.lock = threading.Lock()

    def write(self, **fields):
        record = {"ts": datetime.now(timezone.utc).isoformat(), **fields}
        line = json.dumps(record, separators=(",", ":")) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock, self.path.open("a", encoding="utf-8") as file:
            file.write(line)
        return record
