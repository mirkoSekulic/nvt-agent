#!/usr/bin/env python3
"""Real pinned Pi + tmux/agentd + broker + egressd, using only fake keys.

Run with NVT_PI_TEST_BINARY=/path/to/pi NVT_PI_TEST_EGRESSD=/path/to/egressd.
No live backend, shared home, Docker socket, or existing tmux session is used.
"""

import hashlib
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import shlex
import socket
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
PI = os.environ["NVT_PI_TEST_BINARY"]
EGRESSD = os.environ["NVT_PI_TEST_EGRESSD"]
KEY = "fixture-model-api-key-315"
PLACEHOLDER = "NVT-PLACEHOLDER-NOT-A-KEY"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if isinstance(value, str) else json.dumps(value))
    path.chmod(0o600)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(predicate, label, timeout=25):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError("timeout: " + label)


def main():
    assert subprocess.check_output([PI, "--version"], text=True).strip() == "0.85.1"
    with tempfile.TemporaryDirectory(prefix="nvt-pi-test-") as temporary:
        tmp = Path(temporary)
        private, agent = tmp / "private", tmp / "agent"
        workspace, state = agent / "workspace", agent / "state"
        workspace.mkdir(parents=True)
        private.mkdir()
        state.mkdir()
        write(
            workspace / "AGENTS.md",
            "NVT-GUIDANCE-SENTINEL. Use nvt-work complete to complete work.",
        )
        # Project-local executable/settings must not override declarative intent.
        write(
            workspace / ".pi/settings.json",
            {"defaultProvider": "bad", "packages": ["npm:must-never-install"]},
        )
        write(
            workspace / ".pi/extensions/evil.ts",
            "throw new Error('PROJECT-EXTENSION-MUST-NOT-LOAD');",
        )
        write(private / "model-key", KEY)
        cert, key = private / "tls.crt", private / "tls.key"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        seen, errors = [], []
        busy = threading.Event()
        release = threading.Event()

        class Endpoint(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append(body)
                if self.headers.get("Authorization") != "Bearer " + KEY:
                    errors.append("wrong upstream credential")
                text = json.dumps(body["messages"])
                latest = next(
                    (
                        m.get("content", "")
                        for m in reversed(body["messages"])
                        if m["role"] == "user"
                    ),
                    "",
                )
                if isinstance(latest, list):
                    latest = json.dumps(latest)
                if "AUTH-FAIL" in latest or "RATE-FAIL" in latest:
                    self.send_response(401 if "AUTH-FAIL" in latest else 429)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(
                        json.dumps(
                            {
                                "error": {
                                    "message": "fixture upstream rejected",
                                    "type": "fixture",
                                }
                            }
                        ).encode()
                    )
                    return
                if "BUSY" in latest or "INTERRUPT" in latest:
                    busy.set()
                    release.wait(15)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()

                def emit(delta, finish=None):
                    event = {
                        "id": "fixture-response",
                        "object": "chat.completion.chunk",
                        "created": 1,
                        "model": "example-model",
                        "choices": [
                            {"index": 0, "delta": delta, "finish_reason": finish}
                        ],
                    }
                    self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
                    self.wfile.flush()

                try:
                    if (
                        body["messages"][-1]["role"] != "tool"
                        and "INITIAL-TASK" in latest
                    ):
                        emit(
                            {
                                "role": "assistant",
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "id": "call_fixture",
                                        "type": "function",
                                        "function": {
                                            "name": "bash",
                                            "arguments": json.dumps(
                                                {
                                                    "command": "printf tool-round-trip > proof.txt; nvt-work complete"
                                                }
                                            ),
                                        },
                                    }
                                ],
                            }
                        )
                        emit({}, "tool_calls")
                    else:
                        emit({"role": "assistant", "content": "PI-STREAM-"})
                        emit({"content": "COMPLETE"}, "stop")
                    self.wfile.write(b"data: [DONE]\n\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass

        endpoint = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Endpoint)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        endpoint.socket = tls.wrap_socket(endpoint.socket, server_side=True)
        threading.Thread(target=endpoint.serve_forever, daemon=True).start()
        broker_port, proxy_port = free_port(), free_port()
        write(
            private / "broker.json",
            {
                "providers": [
                    {
                        "name": "model-api",
                        "plugin": "token",
                        "config": {
                            "token-file": str(private / "model-key"),
                            "injection-hosts": ["models.example.test"],
                        },
                    }
                ]
            },
        )

        def identity(name, token, **extra):
            return {
                "id": name,
                "token-sha256": "sha256:" + hashlib.sha256(token.encode()).hexdigest(),
                **extra,
            }

        write(
            private / "agents.json",
            {
                "agents": [
                    identity(
                        "pi-test",
                        "fixture-agent-token",
                        role="agent",
                        grants=[
                            {
                                "provider": "model-api",
                                "materialization": "header-inject",
                            }
                        ],
                    ),
                    identity(
                        "pi-test-egress",
                        "fixture-egress-token",
                        role="egress",
                        **{"paired-agent": "pi-test", "grants": []},
                    ),
                ]
            },
        )
        write(
            private / "egress.json",
            {
                "broker_url": f"https://127.0.0.1:{broker_port}",
                "broker_ca_file": str(cert),
                "ca": {"publish_dir": str(agent / "ca")},
                "forward_proxy": {
                    "listen": f"127.0.0.1:{proxy_port}",
                    "allow_ports": [443],
                    "inject_routes": [
                        {
                            "host": "models.example.test",
                            "capability": "model-api",
                            "upstream": f"127.0.0.1:{endpoint.server_port}",
                            "upstream_ca_pem": cert.read_text(),
                            "upstream_server_name": "localhost",
                            "allow_private_upstream": True,
                            "require_capability_hint": True,
                        }
                    ],
                },
            },
        )
        processes, logs = [], []
        base_env = {"PATH": os.environ["PATH"], "HOME": str(agent), "LANG": "C.UTF-8"}

        def start(command, env, name):
            log = open(tmp / (name + ".log"), "w+")
            logs.append(log)
            p = subprocess.Popen(
                command, env={**base_env, **env}, stdout=log, stderr=log
            )
            processes.append(p)
            return p

        tmux_socket = str(tmp / "tmux.sock")

        def tmux(*args, check=True):
            return subprocess.run(
                ["/usr/bin/tmux", "-S", tmux_socket, *args],
                check=check,
                capture_output=True,
                text=True,
            )

        try:
            start(
                ["python3", str(ROOT / "broker/brokerd.py")],
                {
                    "NVT_BROKER_CONFIG": str(private / "broker.json"),
                    "NVT_BROKER_AGENTS_CONFIG": str(private / "agents.json"),
                    "NVT_BROKER_BIND": f"127.0.0.1:{broker_port}",
                    "NVT_BROKER_AUDIT_LOG": str(private / "audit.jsonl"),
                    "NVT_BROKER_TLS_CERT": str(cert),
                    "NVT_BROKER_TLS_KEY": str(key),
                },
                "broker",
            )
            start(
                [EGRESSD],
                {
                    "NVT_EGRESSD_CONFIG": str(private / "egress.json"),
                    "NVT_BROKER_TOKEN": "fixture-egress-token",
                },
                "egress",
            )
            wait_for(lambda: (agent / "ca/ca.crt").exists(), "egress CA")
            bin_dir = agent / "bin"
            bin_dir.mkdir()
            for name, command in {
                "pi": [PI],
                "tmux": ["/usr/bin/tmux", "-S", tmux_socket],
                "agentdctl": ["python3", str(ROOT / "runtime/agentd/agentdctl.py")],
                "nvt-work": [
                    "python3",
                    str(ROOT / "runtime/plugins/work-control/nvt-work.py"),
                ],
            }.items():
                write(
                    bin_dir / name, "#!/bin/sh\nexec " + shlex.join(command) + ' "$@"\n'
                )
                (bin_dir / name).chmod(0o755)
            env = {
                **base_env,
                "PATH": str(bin_dir) + ":" + base_env["PATH"],
                "NVT_STATE_DIR": str(state),
                "NVT_WORKSPACE": str(workspace),
                "NVT_AGENTD_SOCKET": str(agent / "agentd.sock"),
                "AGENT_SESSION": "pi-test",
                "NVT_AGENT_SESSION_STARTUP_GRACE_SECONDS": "1",
                "NODE_EXTRA_CA_CERTS": str(agent / "ca/ca.crt"),
                "TERM": "xterm-256color",
            }
            ready = state / "agentd/session-launched"
            write(ready, "ready")
            start(["python3", str(ROOT / "runtime/agentd/agentd.py")], env, "agentd")
            wait_for(lambda: (agent / "agentd.sock").exists(), "agentd")
            pi_config = {
                "provider": "custom",
                "baseUrl": "https://models.example.test/v1",
                "api": "openai-completions",
                "models": [
                    {"id": "example-model", "contextWindow": 32000, "maxTokens": 1024}
                ],
                "compat": {
                    "supportsDeveloperRole": False,
                    "supportsReasoningEffort": False,
                },
                "extensions": [
                    {
                        "name": "fixture.ts",
                        "content": 'export default function(pi) { pi.on("before_agent_start", async (event) => ({systemPrompt: event.systemPrompt + "\\nEXPLICIT-EXTENSION-SENTINEL"})); }',
                    }
                ],
            }
            raw = {
                "command": "pi",
                "args": ["--model", "custom/example-model", "--thinking", "off"],
                "resume": {
                    "command": "pi",
                    "args": ["--model", "custom/example-model", "--thinking", "off"],
                },
                "pi": pi_config,
                "proxy": {"provider": "model-api"},
            }
            raw_template = json.loads(json.dumps(raw))
            managed = load("pi_runtime", ROOT / "runtime/core/pi_runtime.py").prepare(
                raw,
                {
                    "mode": "mediated",
                    "transport": "forward-proxy",
                    "grants": [
                        {"provider": "model-api", "materialization": "header-inject"}
                    ],
                },
                state,
                workspace,
                f"http://model-api@127.0.0.1:{proxy_port}",
            )
            managed["args"].append("INITIAL-TASK\nINITIAL-LINE-TWO")
            command_file = agent / "command.json"
            write(command_file, managed)

            def launch(mode):
                command = [
                    "env",
                    *[k + "=" + v for k, v in env.items()],
                    "python3",
                    str(ROOT / "runtime/core/start-agent-session.py"),
                    str(command_file),
                    mode,
                ]
                tmux(
                    "new-session",
                    "-d",
                    "-s",
                    "pi-test",
                    "-x",
                    "140",
                    "-y",
                    "40",
                    "-c",
                    str(workspace),
                    shlex.join(command),
                )
                write(ready, str(time.time()))

            def pane():
                return tmux(
                    "capture-pane", "-p", "-S", "-", "-t", "pi-test", check=False
                ).stdout

            def prompt(text):
                subprocess.run(
                    [
                        "python3",
                        str(ROOT / "runtime/agentd/agentdctl.py"),
                        "prompt",
                        "--source",
                        "test:pi",
                        text,
                    ],
                    env=env,
                    check=True,
                    capture_output=True,
                )

            launch("fresh")
            wait_for(
                lambda: (workspace / "proof.txt").exists() and len(seen) >= 2,
                "initial streaming/tool round trip",
            )
            wait_for(lambda: "PI-STREAM-COMPLETE" in pane(), "streamed final text")
            assert not errors, errors
            assert "INITIAL-TASK\\nINITIAL-LINE-TWO" in json.dumps(seen[0])
            assert (
                json.loads((state / "pi/agent/models.json").read_text())["providers"][
                    "custom"
                ]["apiKey"]
                == PLACEHOLDER
            )
            assert json.loads((state / "pi/agent/auth.json").read_text()) == {}
            assert "NVT-GUIDANCE-SENTINEL" in json.dumps(seen[0])
            assert "EXPLICIT-EXTENSION-SENTINEL" in json.dumps(seen[0])
            wait_for(
                lambda: "plugin.work.completed"
                in (state / "agentd/events.jsonl").read_text(),
                "exported work completion",
            )
            prompt("MULTILINE-FIRST\nMULTILINE-SECOND")
            wait_for(
                lambda: any(
                    "MULTILINE-FIRST\\nMULTILINE-SECOND" in json.dumps(b) for b in seen
                ),
                "multiline paste",
            )
            prompt("BUSY")
            wait_for(busy.is_set, "busy request")
            prompt("FOLLOWUP-WHILE-BUSY")
            time.sleep(0.3)
            release.set()
            wait_for(
                lambda: any("FOLLOWUP-WHILE-BUSY" in json.dumps(b) for b in seen),
                "followup while busy",
            )
            busy.clear()
            release.clear()
            prompt("INTERRUPT")
            wait_for(busy.is_set, "interrupt request")
            tmux("send-keys", "-t", "pi-test", "Escape")
            release.set()
            prompt("AFTER-INTERRUPT")
            wait_for(
                lambda: any("AFTER-INTERRUPT" in json.dumps(b) for b in seen),
                "prompt after interruption",
            )
            # Exact session path, never global --continue/--resume discovery.
            time.sleep(0.5)
            tmux("kill-session", "-t", "pi-test")
            before = len(seen)
            launch("resume")
            time.sleep(2)
            assert len(seen) == before, "initial task replayed on resume"
            prompt("AFTER-RESTART")
            wait_for(lambda: len(seen) > before, "restart followup")
            assert "MULTILINE-FIRST" in json.dumps(seen[-1]), "conversation not resumed"
            for message in ["AUTH-FAIL", "RATE-FAIL"]:
                prompt(message)
                wait_for(
                    lambda: message in json.dumps(seen[-1])
                    and "fixture upstream rejected" in pane(),
                    message,
                )
                tmux("send-keys", "-t", "pi-test", "Escape")
            # Raw retrieval and agent-role header retrieval are both denied.
            for path, payload in [
                (
                    "/v1/token",
                    {
                        "provider": "model-api",
                        "target": "models.example.test/repo",
                        "purpose": "git-fetch",
                    },
                ),
                (
                    "/v1/injection/headers",
                    {
                        "capability": "model-api",
                        "host": "models.example.test",
                        "method": "POST",
                        "path": "/v1/chat/completions",
                    },
                ),
            ]:
                connection = http.client.HTTPSConnection(
                    "127.0.0.1",
                    broker_port,
                    context=ssl.create_default_context(cafile=str(cert)),
                )
                connection.request(
                    "POST",
                    path,
                    json.dumps(payload),
                    {
                        "Authorization": "Bearer fixture-agent-token",
                        "Content-Type": "application/json",
                    },
                )
                response = connection.getresponse()
                assert response.status in {401, 403}, (
                    path,
                    response.status,
                    response.read(),
                )
                connection.close()
            assert "PROJECT-EXTENSION-MUST-NOT-LOAD" not in pane()
            # Declarative update replaces settings/auth/catalog and disables a
            # removed extension while preserving the conversation file.
            tmux("kill-session", "-t", "pi-test")
            raw_template["pi"]["extensions"] = []
            raw_template["pi"]["settings"] = {"hideThinkingBlock": True}
            updated = load(
                "pi_runtime_update", ROOT / "runtime/core/pi_runtime.py"
            ).prepare(
                raw_template,
                {
                    "mode": "mediated",
                    "transport": "forward-proxy",
                    "grants": [
                        {"provider": "model-api", "materialization": "header-inject"}
                    ],
                },
                state,
                workspace,
                f"http://model-api@127.0.0.1:{proxy_port}",
            )
            write(command_file, updated)
            launch("resume")
            time.sleep(2)
            prompt("UPDATED-CONFIG")
            wait_for(
                lambda: "UPDATED-CONFIG" in json.dumps(seen[-1]),
                "updated declarative settings",
            )
            system = [
                m for m in seen[-1]["messages"] if m["role"] in {"system", "developer"}
            ]
            assert "EXPLICIT-EXTENSION-SENTINEL" not in json.dumps(system)
            assert (
                json.loads((state / "pi/agent/settings.json").read_text())[
                    "hideThinkingBlock"
                ]
                is True
            )
            assert not (state / "pi/agent/managed-extensions/fixture.ts").exists()
            # Failures use Pi's real fetch/CONNECT path. No authorized upstream
            # request may be observed with wrong CA, denied host, or dead proxy.
            for failure in ["wrong-ca", "unauthorized-host", "dead-proxy"]:
                tmux("kill-session", "-t", "pi-test")
                count = len(seen)
                bad = json.loads(json.dumps(updated))
                bad["args"].append("NEGATIVE-REQUEST")
                if failure == "wrong-ca":
                    bad["env"]["NODE_EXTRA_CA_CERTS"] = str(cert)
                elif failure == "unauthorized-host":
                    models_path = state / "pi/agent/models.json"
                    models = json.loads(models_path.read_text())
                    models["providers"]["custom"][
                        "baseUrl"
                    ] = "https://unauthorized.example.test/v1"
                    write(models_path, models)
                else:
                    bad["env"]["HTTPS_PROXY"] = bad["env"]["https_proxy"] = (
                        "http://127.0.0.1:1"
                    )
                write(command_file, bad)
                launch("fresh")
                wait_for(
                    lambda: any(
                        text in pane().lower()
                        for text in [
                            "fetch failed",
                            "connection error",
                            "request failed",
                        ]
                    ),
                    failure,
                )
                assert len(seen) == count, "direct fallback reached upstream"
            # A missing broker-only key is rejected at broker startup.
            missing_config = json.loads((private / "broker.json").read_text())
            missing_config["providers"][0]["config"]["token-file"] = str(
                private / "missing-key"
            )
            write(private / "missing.json", missing_config)
            result = subprocess.run(
                ["python3", str(ROOT / "broker/brokerd.py")],
                env={
                    **base_env,
                    "NVT_BROKER_CONFIG": str(private / "missing.json"),
                    "NVT_BROKER_AGENTS_CONFIG": str(private / "agents.json"),
                    "NVT_BROKER_BIND": f"127.0.0.1:{free_port()}",
                },
                capture_output=True,
                text=True,
                timeout=5,
            )
            assert result.returncode != 0 and KEY not in result.stdout + result.stderr

            for path in agent.rglob("*"):
                if path.is_file():
                    assert (
                        KEY.encode() not in path.read_bytes()
                    ), "real key leaked into workload artifact"
            for log in logs:
                log.flush()
                log.seek(0)
                assert KEY not in log.read(), "real key leaked into logs"
            print(
                "PASS: Pi 0.85.1 terminal, multiline, busy followup, interrupt, resume, streaming, tool/completion, managed extension, broker-only key, config update, TLS/proxy/destination failures"
            )
        except Exception:
            for log in logs:
                log.flush()
                log.seek(0)
                print(Path(log.name).name + ":\n" + log.read()[-4000:])
            print(
                tmux(
                    "capture-pane", "-p", "-S", "-", "-t", "pi-test", check=False
                ).stdout[-5000:]
            )
            raise
        finally:
            release.set()
            tmux("kill-server", check=False)
            for process in reversed(processes):
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            endpoint.shutdown()
            for log in logs:
                log.close()


if __name__ == "__main__":
    main()
