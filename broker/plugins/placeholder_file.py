"""Shared rendering for the placeholder-file materialization mode.

A placeholder file is a syntactically valid auth/config file that carries only
inert placeholders: the real secret values stay in broker/provider custody and
never reach the agent (docs/phase6.1-placeholder-file-materialization-pr-plan.md).
These helpers render the two placeholder shapes and validate the target path;
they hold no secret state.
"""

import base64
import json
import time

from broker.core.config import fail

# The documented zero-entropy placeholder from protocol/injection.md — the only
# credential-shaped value allowed inside the agent container.
PLACEHOLDER = "NVT-PLACEHOLDER-NOT-A-KEY"

# A JWT signature segment that is obviously not a real signature. It is never
# verified locally (the real bearer token is injected at the edge in 6.2).
PLACEHOLDER_JWT_SIGNATURE = "nvt-placeholder-signature"

# A placeholder JWT's exp is set far in the future so a tool that checks local
# token expiry starts without attempting a refresh.
FAR_FUTURE_SECONDS = 10 * 365 * 24 * 3600


def _b64url(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def far_future_exp(now=None):
    base = int(now if now is not None else time.time())
    return base + FAR_FUTURE_SECONDS


def render_jwt(claims, exp):
    """Render a syntactically valid JWT carrying only non-secret claims plus a
    placeholder signature. The signature is never real material — it is a fixed
    placeholder — so no secret leaks through the token."""
    if not isinstance(claims, dict):
        fail("placeholder jwt claims must be an object")
    header = {"alg": "none", "typ": "JWT"}
    payload = dict(claims)
    payload["exp"] = int(exp)
    header_segment = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_segment = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{header_segment}.{payload_segment}.{PLACEHOLDER_JWT_SIGNATURE}"


def render_plain():
    """Render an opaque placeholder string."""
    return PLACEHOLDER


def validate_mode(mode, field):
    if not isinstance(mode, str) or len(mode) != 4 or any(char not in "01234567" for char in mode):
        fail(f"{field} must be a four-digit octal string")
    return mode


def validate_relative_path(path, field):
    """A placeholder file path is a safe relative path under the agent home.
    Absolute paths and '.'/'..'/empty segments are refused so materialization
    cannot escape the home directory."""
    if not isinstance(path, str) or not path:
        fail(f"{field} is required")
    if path.startswith("/") or path.startswith("\\"):
        fail(f"{field} must be a relative path")
    segments = path.replace("\\", "/").split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        fail(f"{field} must not contain empty, '.', or '..' path segments")
    return path
