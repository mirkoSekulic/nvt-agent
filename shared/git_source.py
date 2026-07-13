"""Acquire immutable public HTTPS Git sources into a content-addressed cache."""

import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit, urlunsplit


REVISION_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
DEFAULT_ALLOWED_HOSTS = ("github.com",)


class GitSourceError(Exception):
    pass


def allowed_hosts(environment=None):
    environment = os.environ if environment is None else environment
    raw = environment.get("NVT_GIT_SOURCE_ALLOWED_HOSTS")
    values = DEFAULT_ALLOWED_HOSTS if raw is None else tuple(item.strip().lower() for item in raw.split(",") if item.strip())
    if not values:
        raise GitSourceError("Git source allowed-host policy must not be empty")
    for value in values:
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value):
            raise GitSourceError("Git source allowed-host policy is invalid")
    return frozenset(values)


def parse_source(source, environment=None):
    if not isinstance(source, dict) or set(source) != {"git"}:
        raise GitSourceError("source must contain exactly one git object")
    git = source["git"]
    if not isinstance(git, dict) or set(git) - {"url", "revision", "subdir"}:
        raise GitSourceError("source.git has invalid fields")
    url = git.get("url")
    revision = git.get("revision")
    subdir = git.get("subdir", "")
    if not isinstance(url, str) or not url:
        raise GitSourceError("source.git.url must be a non-empty string")
    if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
        raise GitSourceError("source.git.revision must be a full lowercase commit object ID")
    if not isinstance(subdir, str):
        raise GitSourceError("source.git.subdir must be a string")
    try:
        parsed = urlsplit(url)
    except ValueError as error:
        raise GitSourceError("source.git.url has an unsupported form") from error
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise GitSourceError("source.git.url must be a public HTTPS URL without credentials")
    try:
        port = parsed.port
    except ValueError as error:
        raise GitSourceError("source.git.url has an unsupported form") from error
    if port not in (None, 443) or parsed.query or parsed.fragment or not parsed.path.startswith("/"):
        raise GitSourceError("source.git.url has an unsupported form")
    host = parsed.hostname.lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise GitSourceError("source.git.url must use an allowed public hostname")
    if host not in allowed_hosts(environment):
        raise GitSourceError("source.git.url host is not allowed")
    canonical = urlunsplit(("https", host, parsed.path, "", ""))
    relative = PurePosixPath(subdir)
    if relative.is_absolute() or ".." in relative.parts or "\\" in subdir:
        raise GitSourceError("source.git.subdir must be a safe relative path")
    return canonical, revision, relative


def acquire(source, cache_root, environment=None):
    try:
        canonical, revision, subdir = parse_source(source, environment)
        cache_root = Path(cache_root)
        cache_root.mkdir(parents=True, exist_ok=True)
        key = hashlib.sha256(f"{canonical}\0{revision}".encode("utf-8")).hexdigest()
        checkout = cache_root / key
        lock_path = cache_root / f"{key}.lock"
        with lock_path.open("a+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            if not _valid_checkout(checkout, canonical, revision, environment):
                if checkout.exists() or checkout.is_symlink():
                    _remove_path(checkout)
                for stale in cache_root.glob(f".{key}.tmp-*"):
                    _remove_path(stale)
                _populate(checkout, canonical, revision, cache_root, environment)
            return _select_subdir(checkout, subdir)
    except GitSourceError:
        raise
    except (OSError, ValueError) as error:
        raise GitSourceError("public Git source cache operation failed") from error


def _git_environment(environment=None):
    baseline = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "Never",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ASKPASS": "/bin/false",
        "SSH_ASKPASS": "/bin/false",
        "GIT_LFS_SKIP_SMUDGE": "1",
    }
    return baseline


def _git(args, cwd, environment=None):
    command = [
        "git", "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null",
        "-c", "http.followRedirects=false", "-c", "submodule.recurse=false",
        "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
        "-c", "filter.lfs.smudge=", "-c", "filter.lfs.required=false", *args,
    ]
    try:
        return subprocess.run(
            command, cwd=cwd, env=_git_environment(environment), check=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=120,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise GitSourceError("public Git source acquisition failed") from error


def _populate(destination, canonical, revision, cache_root, environment=None):
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=cache_root))
    try:
        _git(["init", "--quiet"], temporary, environment)
        _git(["remote", "add", "origin", canonical], temporary, environment)
        _git(["fetch", "--quiet", "--no-tags", "--depth=1", "origin", revision], temporary, environment)
        resolved = _git(["rev-parse", "FETCH_HEAD^{commit}"], temporary, environment).lower()
        if resolved != revision:
            raise GitSourceError("public Git source commit verification failed")
        _git(["checkout", "--quiet", "--detach", resolved], temporary, environment)
        _git(["remote", "remove", "origin"], temporary, environment)
        marker = {"url": canonical, "revision": revision}
        (temporary / ".git" / "nvt-source.json").write_text(json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _valid_checkout(checkout, canonical, revision, environment=None):
    try:
        if checkout.is_symlink() or not checkout.is_dir():
            return False
        if (checkout / ".git").is_symlink() or not (checkout / ".git").is_dir():
            return False
        marker = json.loads((checkout / ".git" / "nvt-source.json").read_text(encoding="utf-8"))
        if marker != {"url": canonical, "revision": revision}:
            return False
        if _git(["rev-parse", "HEAD^{commit}"], checkout, environment).lower() != revision:
            return False
        _git(["update-index", "--refresh"], checkout, environment)
        _git(["diff-index", "--quiet", "HEAD", "--"], checkout, environment)
        # Cached content is executable input, so ignored files are no safer
        # than ordinary untracked files. Ignore no repository or local exclude
        # rules when deciding whether the checkout is pristine.
        return not _git(["ls-files", "--others"], checkout, environment)
    except (OSError, ValueError, GitSourceError):
        return False


def _select_subdir(checkout, subdir):
    try:
        root = checkout.resolve(strict=True)
        selected = (checkout / Path(*subdir.parts)).resolve(strict=True)
    except OSError as error:
        raise GitSourceError("source.git.subdir does not exist") from error
    try:
        selected.relative_to(root)
    except ValueError as error:
        raise GitSourceError("source.git.subdir escapes the verified checkout") from error
    if not selected.is_dir():
        raise GitSourceError("source.git.subdir must select a directory")
    return selected


def _remove_path(path):
    if path.is_symlink() or path.is_file():
        path.unlink()
    else:
        shutil.rmtree(path)


def resolve_executable(root, command):
    if not isinstance(command, str) or not command:
        raise GitSourceError("command executable must be a non-empty string")
    candidate = Path(command)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise GitSourceError("Git-sourced command executable must be a safe relative path")
    try:
        resolved = (Path(root) / candidate).resolve(strict=True)
    except OSError as error:
        raise GitSourceError("Git-sourced command executable does not exist") from error
    try:
        resolved.relative_to(Path(root).resolve(strict=True))
    except ValueError as error:
        raise GitSourceError("Git-sourced command executable escapes the selected source") from error
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise GitSourceError("Git-sourced command executable must be an executable file")
    return resolved


def resolve_file(root, relative_path):
    if not isinstance(relative_path, str) or not relative_path:
        raise GitSourceError("Git-sourced file path must be a non-empty string")
    candidate = Path(relative_path)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise GitSourceError("Git-sourced file path must be a safe relative path")
    try:
        resolved = (Path(root) / candidate).resolve(strict=True)
        resolved.relative_to(Path(root).resolve(strict=True))
    except (OSError, ValueError) as error:
        raise GitSourceError("Git-sourced file escapes the selected source") from error
    if not resolved.is_file():
        raise GitSourceError("Git-sourced file does not exist")
    return resolved
