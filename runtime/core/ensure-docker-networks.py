#!/usr/bin/env python3
"""Validate and reconcile operator-owned Docker bridge networks."""

from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import re
import subprocess
import sys


ENV_NAME = "NVT_DOCKER_REQUIRED_NETWORKS"
MANAGED_POOL = ipaddress.ip_network("172.31.0.0/16")
NAME_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
REAL_DOCKER = os.environ.get("NVT_DOCKER_REAL_BIN", "/usr/bin/docker")
MAX_NETWORKS = 16
MAX_CONFIG_BYTES = 8192


class ContractError(RuntimeError):
    pass


def load_networks(raw: str) -> list[dict[str, str]]:
    if len(raw.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise ContractError("required Docker network configuration is too large")
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ContractError("required Docker network configuration is invalid") from exc
    if not isinstance(value, list) or len(value) > MAX_NETWORKS:
        raise ContractError("required Docker network configuration is invalid")

    result: list[dict[str, str]] = []
    names: set[str] = set()
    subnets: set[ipaddress.IPv4Network] = set()
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {"name", "subnet"}:
            raise ContractError("required Docker network entry is invalid")
        name = entry["name"]
        subnet_text = entry["subnet"]
        if (
            not isinstance(name, str)
            or len(name) > 63
            or NAME_RE.fullmatch(name) is None
            or not isinstance(subnet_text, str)
        ):
            raise ContractError("required Docker network entry is invalid")
        try:
            subnet = ipaddress.ip_network(subnet_text, strict=True)
        except ValueError as exc:
            raise ContractError("required Docker network subnet is invalid") from exc
        if (
            not isinstance(subnet, ipaddress.IPv4Network)
            or subnet.prefixlen != 24
            or not subnet.subnet_of(MANAGED_POOL)
        ):
            raise ContractError("required Docker network subnet is outside the managed IPv4 pool")
        if name in names or subnet in subnets:
            raise ContractError("required Docker network name or subnet is duplicated")
        names.add(name)
        subnets.add(subnet)
        result.append({"name": name, "subnet": str(subnet)})
    return result


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [REAL_DOCKER, *args],
            check=check,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ContractError("Docker network reconciliation failed") from exc


def inspect_network(name: str) -> dict[str, object] | None:
    result = docker("network", "inspect", name, check=False)
    if result.returncode != 0:
        if "No such network" in result.stderr or "not found" in result.stderr.lower():
            return None
        raise ContractError("Docker network inspection failed")
    if len(result.stdout.encode("utf-8")) > 64 * 1024:
        raise ContractError("Docker network inspection response is too large")
    try:
        decoded = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ContractError("Docker network inspection returned invalid data") from exc
    if not isinstance(decoded, list) or len(decoded) != 1 or not isinstance(decoded[0], dict):
        raise ContractError("Docker network inspection returned invalid data")
    return decoded[0]


def validate_existing(actual: dict[str, object], expected: dict[str, str]) -> None:
    ipam = actual.get("IPAM")
    configs = ipam.get("Config") if isinstance(ipam, dict) else None
    subnets = [item.get("Subnet") for item in configs if isinstance(item, dict)] if isinstance(configs, list) else []
    options = actual.get("Options")
    masquerade = options.get("com.docker.network.bridge.enable_ip_masquerade") if isinstance(options, dict) else None
    if (
        actual.get("Name") != expected["name"]
        or actual.get("Driver") != "bridge"
        or actual.get("EnableIPv6") is not False
        or actual.get("Internal") is not False
        or subnets != [expected["subnet"]]
        or masquerade != "true"
    ):
        raise ContractError(f'required Docker network {expected["name"]!r} has incompatible immutable settings')


def ensure(network: dict[str, str]) -> None:
    actual = inspect_network(network["name"])
    if actual is None:
        created = docker(
            "network",
            "create",
            "--driver=bridge",
            f'--subnet={network["subnet"]}',
            "--opt=com.docker.network.bridge.enable_ip_masquerade=true",
            network["name"],
            check=False,
        )
        if created.returncode != 0:
            # A concurrent reconciler may have won the create race. The exact
            # post-create inspection remains authoritative.
            actual = inspect_network(network["name"])
            if actual is None:
                raise ContractError(f'could not create required Docker network {network["name"]!r}')
        else:
            actual = inspect_network(network["name"])
    if actual is None:
        raise ContractError(f'required Docker network {network["name"]!r} is unavailable')
    validate_existing(actual, network)


def main() -> int:
    raw = os.environ.get(ENV_NAME)
    if raw is None:
        return 0
    try:
        networks = load_networks(raw)
        with open("/tmp/nvt-required-docker-networks.lock", "w", encoding="ascii") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            for network in networks:
                ensure(network)
    except ContractError as exc:
        print(f"nvt-docker-network: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
