"""Authentication (session cookie or API key) and role-based access control.

Roles are per workspace membership: ``read`` < ``write`` < ``admin``. An API key belongs to one workspace and acts
with the lower of its own role and its owner's current role there. Browser sessions must echo their CSRF token in
``X-CSRF-Token`` on unsafe methods; API-key requests carry no ambient credentials and are exempt.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.concurrency import run_in_threadpool

from . import db
from .config import SESSION_COOKIE, SESSION_TTL_HOURS
from .security import hash_secret, new_token, parse_api_key, same, token_digest, verify_secret

log = logging.getLogger("sentinel.auth")

ROLES = ("read", "write", "admin")
ROLE_RANK = {r: i for i, r in enumerate(ROLES, 1)}
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
REVIEW_PATH_PARAMS = ("review_id", "tm_id")
_KEY_CACHE_TTL = 300.0
_verified_keys: dict[str, tuple[int, float]] = {}  # sha256(key) -> (api key id, expiry) - skips repeat argon2
_bearer = HTTPBearer(auto_error=False, description="API key: `Authorization: Bearer sntl_...`")
Bearer = HTTPAuthorizationCredentials | None


@dataclass
class Principal:
    user_id: int
    email: str
    name: str
    via: str                        # session | api_key
    workspace_id: int | None = None
    role: str | None = None
    session_id: str | None = None
    csrf_token: str | None = None
    api_key_id: int | None = None


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def min_role(a: str | None, b: str | None) -> str | None:
    if not a or not b:
        return None
    return a if ROLE_RANK[a] <= ROLE_RANK[b] else b


# ---------------------------------------------------------------------- users / workspaces
def create_user(conn, email: str, password: str, name: str = "", username: str | None = None,
                verified: bool = False) -> int:
    return conn.execute(
        "INSERT INTO users (email, username, name, password_hash, email_verified_at) VALUES (%s, %s, %s, %s, %s) "
        "RETURNING id", (email.strip(), username, name.strip(), hash_secret(password),
                         utcnow() if verified else None)).fetchone()["id"]


def create_workspace(conn, name: str, owner_id: int) -> int:
    ws = conn.execute("INSERT INTO workspaces (name, created_by) VALUES (%s, %s) RETURNING id",
                      (name.strip()[:120] or "My workspace", owner_id)).fetchone()["id"]
    conn.execute("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (%s, %s, 'admin')",
                 (ws, owner_id))
    return ws


def memberships(conn, user_id: int) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT w.id, w.name, m.role FROM workspace_members m JOIN workspaces w ON w.id = m.workspace_id "
        "WHERE m.user_id = %s ORDER BY w.name, w.id", (user_id,))]


# ---------------------------------------------------------------------- sessions
def create_session(conn, user_id: int, workspace_id: int | None, ip: str = "", user_agent: str = "") -> tuple[str, str]:
    """Return (cookie token, csrf token). Only the token's digest is stored."""
    token, csrf = new_token(), new_token(24)
    conn.execute(
        "INSERT INTO sessions (id, user_id, workspace_id, csrf_token, ip, user_agent, expires_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (token_digest(token), user_id, workspace_id, csrf, ip[:64], user_agent[:300],
         utcnow() + timedelta(hours=SESSION_TTL_HOURS)))
    return token, csrf


def _from_session(token: str | None) -> Principal | None:
    if not token:
        return None
    sid = token_digest(token)
    with db.tx() as conn:
        row = conn.execute(
            """SELECT s.id, s.user_id, s.workspace_id, s.csrf_token, s.last_seen_at, u.email, u.name, m.role
               FROM sessions s JOIN users u ON u.id = s.user_id
               LEFT JOIN workspace_members m ON m.workspace_id = s.workspace_id AND m.user_id = s.user_id
               WHERE s.id = %s AND s.expires_at > now() AND u.is_active AND u.email_verified_at IS NOT NULL""",
            (sid,)).fetchone()
        if not row:
            return None
        ws, role = row["workspace_id"], row["role"]
        if role is None:  # removed from the active workspace: fall back to another membership
            first = next(iter(memberships(conn, row["user_id"])), None)
            ws, role = (first["id"], first["role"]) if first else (None, None)
            conn.execute("UPDATE sessions SET workspace_id = %s WHERE id = %s", (ws, sid))
        if utcnow() - row["last_seen_at"] > timedelta(seconds=60):
            conn.execute("UPDATE sessions SET last_seen_at = now(), expires_at = %s WHERE id = %s",
                         (utcnow() + timedelta(hours=SESSION_TTL_HOURS), sid))
    return Principal(user_id=row["user_id"], email=row["email"], name=row["name"], via="session", workspace_id=ws,
                     role=role, session_id=sid, csrf_token=row["csrf_token"])


# ---------------------------------------------------------------------- API keys
def _from_api_key(key: str) -> Principal | None:
    prefix = parse_api_key(key)
    with db.tx() as conn:
        row = conn.execute(
            """SELECT k.id, k.workspace_id, k.user_id, k.key_hash, k.role, k.expires_at, k.revoked_at, k.last_used_at,
                      u.email, u.name, u.is_active, m.role AS member_role
               FROM api_keys k JOIN users u ON u.id = k.user_id
               LEFT JOIN workspace_members m ON m.workspace_id = k.workspace_id AND m.user_id = k.user_id
               WHERE k.prefix = %s""", (prefix,)).fetchone() if prefix else None
        digest = token_digest(key)
        cached = _verified_keys.get(digest)
        if row and cached and cached[0] == row["id"] and cached[1] > time.monotonic():
            ok = True
        else:
            ok = verify_secret(row["key_hash"] if row else None, key)
            if ok:
                if len(_verified_keys) > 10_000:
                    _verified_keys.clear()
                _verified_keys[digest] = (row["id"], time.monotonic() + _KEY_CACHE_TTL)
        if not ok or row["revoked_at"] or not row["is_active"] or (row["expires_at"] and row["expires_at"] <= utcnow()):
            return None
        role = min_role(row["role"], row["member_role"])
        if role is None:
            return None
        if not row["last_used_at"] or utcnow() - row["last_used_at"] > timedelta(minutes=5):
            conn.execute("UPDATE api_keys SET last_used_at = now() WHERE id = %s", (row["id"],))
    return Principal(user_id=row["user_id"], email=row["email"], name=row["name"], via="api_key",
                     workspace_id=row["workspace_id"], role=role, api_key_id=row["id"])


def _api_key_from_headers(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip()
    return request.headers.get("x-api-key") or None


# ---------------------------------------------------------------------- FastAPI dependencies
async def current_principal(request: Request) -> Principal:
    cached = getattr(request.state, "principal", None)
    if cached:
        return cached
    key = _api_key_from_headers(request)
    if key:
        p = await run_in_threadpool(_from_api_key, key)
    else:
        p = await run_in_threadpool(_from_session, request.cookies.get(SESSION_COOKIE))
    if not p:
        raise HTTPException(401, "Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    request.state.principal = p
    return p


def _check_csrf(request: Request, p: Principal) -> None:
    if p.via == "session" and request.method not in SAFE_METHODS:
        sent = request.headers.get("x-csrf-token", "")
        if not sent or not same(sent, p.csrf_token or ""):
            raise HTTPException(403, "Missing or invalid CSRF token")


def _review_in_workspace(review_id: int, ws: int) -> bool:
    with db.tx() as conn:
        return conn.execute("SELECT 1 FROM reviews WHERE id = %s AND workspace_id = %s",
                            (review_id, ws)).fetchone() is not None


async def _enforce(request: Request, p: Principal, needed: str) -> Principal:
    _check_csrf(request, p)
    if p.workspace_id is None or p.role is None:
        raise HTTPException(403, "You are not a member of any workspace")
    if ROLE_RANK[p.role] < ROLE_RANK[needed]:
        raise HTTPException(403, f"This action requires the '{needed}' role (you have '{p.role}')")
    db.set_workspace(p.workspace_id)
    db.set_user(p.user_id)
    for name in REVIEW_PATH_PARAMS:
        raw = request.path_params.get(name)
        if raw is None:
            continue
        try:
            rid = int(raw)
        except (TypeError, ValueError):
            raise HTTPException(404, "Review not found")
        if not await run_in_threadpool(_review_in_workspace, rid, p.workspace_id):
            raise HTTPException(404, "Review not found")
    return p


async def authorize(request: Request, _: Bearer = Depends(_bearer)) -> Principal:
    """Router-wide guard: ``read`` for safe methods, ``write`` for everything else."""
    p = await current_principal(request)
    return await _enforce(request, p, "read" if request.method in SAFE_METHODS else "write")


def require_role(role: str):
    """Stricter per-route requirement, e.g. ``Depends(require_role("admin"))``."""
    async def dep(request: Request, _: Bearer = Depends(_bearer)) -> Principal:
        p = await current_principal(request)
        return await _enforce(request, p, role)
    return dep


async def require_user(request: Request, _: Bearer = Depends(_bearer)) -> Principal:
    """Any authenticated principal, no workspace needed (account endpoints). CSRF still applies."""
    p = await current_principal(request)
    _check_csrf(request, p)
    return p


async def require_session_user(request: Request) -> Principal:
    p = await require_user(request, None)
    if p.via != "session":
        raise HTTPException(403, "This endpoint is only available to signed-in users, not API keys")
    return p
