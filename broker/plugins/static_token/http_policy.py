"""Token-provider HTTP vocabulary; never interprets bodies or repository scope."""
import re

from broker.core.errors import ProviderError

METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
SEGMENT = re.compile(r"[A-Za-z0-9._~-]+\Z")
MAX_RULES = 128
MAX_PATH = 2048


def host_valid(host):
    return isinstance(host, str) and len(host) <= 253 and all(LABEL.fullmatch(p) for p in host.split("."))


def path_valid(path, pattern=False):
    if not isinstance(path, str) or not path.startswith("/") or len(path) > MAX_PATH:
        return False
    if path == "/":
        return True
    parts = path[1:].split("/")
    return len(parts) <= 64 and all(p not in {".", ".."} and (pattern and p == "*" or SEGMENT.fullmatch(p)) for p in parts)


def policy(value):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {"defaultAction", "rules"} or value.get("defaultAction", "deny") != "deny":
        raise ProviderError("http-policy-invalid", status=403)
    rules = value.get("rules", [])
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise ProviderError("http-policy-invalid", status=403)
    result = []
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {"operation", "resource"}:
            raise ProviderError("http-policy-invalid", status=403)
        op, resource = rule["operation"], rule["resource"]
        if not isinstance(op, str) or op not in {"http." + m for m in METHODS} or not isinstance(resource, str) or not resource.startswith("http/"):
            raise ProviderError("http-policy-invalid", status=403)
        host, slash, path = resource[5:].partition("/")
        if not slash or not host_valid(host) or not path_valid("/" + path, pattern=True):
            raise ProviderError("http-policy-invalid", status=403)
        result.append((op, host, ("/" + path).split("/")))
    if len(set((op, host, tuple(parts)) for op, host, parts in result)) != len(result):
        raise ProviderError("http-policy-invalid", status=403)
    return result


def allows(rules, host, method, path):
    if rules is None:
        return False
    actual = path.split("/")
    return any(op == "http." + method and host == target and len(parts) == len(actual)
               and all(p == a or p == "*" and a != "" for p, a in zip(parts, actual))
               for op, target, parts in rules)
