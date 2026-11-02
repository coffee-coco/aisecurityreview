"""Link a git repository as a code source: a validated, shallow, read-only clone.

Safety rules: https URLs only (``file://`` only when ALLOW_LOCAL_GIT=1, for tests), no credentials in the URL,
hosts that resolve to loopback/link-local/metadata addresses are refused, git hooks and prompts are disabled,
an optional access token travels in the process environment (never argv) and is never stored, and the
checkout goes through the same limits as zip uploads (symlinks, vendored folders, size and file count).
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import os
import re
import shutil
import socket
from pathlib import Path
from urllib.parse import urlparse

from .workspace import UnpackError, sanitize_tree

CLONE_TIMEOUT = int(os.getenv("GIT_CLONE_TIMEOUT", "300"))
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\-]{0,199}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]+(:\d{1,5})?$")


class GitError(ValueError):
    pass


def _refused_address(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise GitError(f"Cannot resolve host '{host}'")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            return True
    return False


def validate_url(url: str) -> tuple[str, str]:
    """Return (clean_url, display_name) or raise GitError."""
    url = (url or "").strip()
    if url.startswith("git@") or url.startswith("ssh://"):
        raise GitError("SSH URLs are not supported - use the https:// clone URL (and an access token if private).")
    p = urlparse(url)
    if p.scheme == "file" and os.getenv("ALLOW_LOCAL_GIT") == "1":
        name = Path(p.path).name or "repo"
        return url, re.sub(r"\.git$", "", name)
    if p.scheme != "https" or not p.hostname or not HOST_RE.match(p.netloc):
        raise GitError("Enter an https:// repository URL, e.g. https://github.com/owner/repo")
    if p.username or p.password or "@" in p.netloc:
        raise GitError("Do not put credentials in the URL - use the access token field.")
    if p.query or p.fragment:
        raise GitError("The repository URL must not contain a query string or fragment.")
    if _refused_address(p.hostname):
        raise GitError("That host resolves to a loopback or link-local address and is not allowed.")
    parts = [x for x in p.path.split("/") if x]
    if not parts:
        raise GitError("The URL must point to a repository, e.g. https://github.com/owner/repo")
    name = re.sub(r"\.git$", "", "-".join(parts[-2:]))
    return f"https://{p.netloc}{p.path.rstrip('/')}", re.sub(r"[^A-Za-z0-9_.-]+", "-", name)[:80] or "repo"


def _env(token: str | None) -> dict:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": os.devnull, "GCM_INTERACTIVE": "never"}
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.extraHeader",
                   GIT_CONFIG_VALUE_0=f"Authorization: Basic {basic}")
    return env


async def _git(args: list[str], env: dict, cwd: Path | None = None, timeout: int = CLONE_TIMEOUT) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", *args, cwd=str(cwd) if cwd else None, env=env, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError:
        raise GitError("git is not installed on the server.")
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise GitError(f"git timed out after {timeout}s - the repository may be too large.")
    if proc.returncode:
        text = err.decode("utf-8", "replace")
        msg = [m.strip() for m in text.splitlines() if m.strip()]
        tail = next((m for m in msg if m.startswith(("fatal:", "error:"))), msg[-1] if msg else "git failed")
        tail = re.sub(r"^(fatal|error):\s*", "", tail)
        if re.search(r"Authentication failed|could not read Username|repository .* not found|HTTP (401|403|404)|returned error: (401|403|404)", text):
            tail = "Repository not found or access denied - for a private repository provide an access token."
        raise GitError(tail[:300])
    return out.decode("utf-8", "replace").strip()


async def clone_repo(url: str, dest: Path, ref: str | None = None, token: str | None = None) -> dict:
    """Shallow-clone into ``dest`` and return document metadata. ``dest`` is removed on failure."""
    clean, name = validate_url(url)
    ref = (ref or "").strip() or None
    if ref and not REF_RE.match(ref):
        raise GitError("Branch or tag name contains unsupported characters.")
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    env = _env(token)
    args = ["-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false", "-c", "protocol.version=2"]
    if clean.startswith("file://"):
        args += ["-c", "protocol.file.allow=always"]
    else:
        args += ["-c", "protocol.allow=never", "-c", "protocol.https.allow=always"]
    args += ["clone", "--depth", "1", "--single-branch", "--no-tags", "--quiet"]
    if ref:
        args += ["--branch", ref]
    args += ["--", clean, str(dest)]
    try:
        await _git(args, env)
        commit = await _git(["rev-parse", "HEAD"], env, cwd=dest, timeout=30)
        branch = await _git(["rev-parse", "--abbrev-ref", "HEAD"], env, cwd=dest, timeout=30)
        shutil.rmtree(dest / ".git", ignore_errors=True)
        stats = sanitize_tree(dest)
    except (GitError, UnpackError):
        shutil.rmtree(dest, ignore_errors=True)
        raise
    if not stats["files"]:
        shutil.rmtree(dest, ignore_errors=True)
        raise GitError("The repository contains no reviewable source files.")
    return {"name": name, "url": clean, "ref": ref or branch, "commit": commit, "private": bool(token), **stats}
