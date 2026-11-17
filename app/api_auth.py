"""Accounts, sessions, workspaces, members and API keys.

Self-registration creates an unverified account plus a workspace the registrant administers. The email verification
code is printed to the server console (no outbound email) so the operator can hand it over.
"""
from __future__ import annotations

import logging
import re
from datetime import timedelta
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from . import db
from .auth import (
    Principal, ROLE_RANK, create_session, create_user, create_workspace, current_principal, memberships,
    require_role, require_session_user, require_user, utcnow,
)
from .config import (
    ALLOW_REGISTRATION, COOKIE_SECURE, DEMO_USER_ENABLED, LOCKOUT_MINUTES, MAX_LOGIN_FAILURES, SESSION_COOKIE,
    SESSION_TTL_HOURS, VERIFY_CODE_TTL_MINUTES,
)
from .security import hash_secret, needs_rehash, new_api_key, new_verification_code, verify_secret

router = APIRouter(prefix="/api")
log = logging.getLogger("sentinel.auth")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_CODE_ATTEMPTS = 5
Role = Literal["admin", "write", "read"]


# --------------------------------------------------------------------------- models
class RegisterBody(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=8, max_length=256)
    name: str = Field("", max_length=120)
    workspace_name: str = Field("", max_length=120)


class VerifyBody(BaseModel):
    email: str = Field(max_length=254)
    code: str = Field(min_length=6, max_length=6)


class EmailBody(BaseModel):
    email: str = Field(max_length=254)


class LoginBody(BaseModel):
    login: str = Field(max_length=254)  # email or username
    password: str = Field(max_length=256)


class PasswordBody(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(min_length=8, max_length=256)


class WorkspaceSwitch(BaseModel):
    workspace_id: int


class WorkspaceBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class MemberAdd(BaseModel):
    email: str = Field(max_length=254)
    role: Role = "read"


class MemberUpdate(BaseModel):
    role: Role


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    role: Role = "read"
    expires_in_days: Optional[int] = Field(None, ge=1, le=3650)


# --------------------------------------------------------------------------- helpers
def _norm_email(email: str) -> str:
    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(422, "Enter a valid email address")
    return email


def _set_cookie(response: Response, token: str) -> None:
    response.set_cookie(SESSION_COOKIE, token, max_age=int(SESSION_TTL_HOURS * 3600), httponly=True,
                        secure=COOKIE_SECURE, samesite="lax", path="/")


def _issue_code(conn, user_id: int, email: str) -> None:
    code = new_verification_code()
    conn.execute("UPDATE email_verifications SET consumed_at = now() WHERE user_id = %s AND consumed_at IS NULL",
                 (user_id,))
    conn.execute("INSERT INTO email_verifications (user_id, code_hash, expires_at) VALUES (%s, %s, %s)",
                 (user_id, hash_secret(code), utcnow() + timedelta(minutes=VERIFY_CODE_TTL_MINUTES)))
    log.warning("\n%s\n  EMAIL VERIFICATION  %s  ->  code %s  (expires in %d min)\n%s",
                "=" * 64, email, code, VERIFY_CODE_TTL_MINUTES, "=" * 64)


def _start_session(conn, request: Request, response: Response, user_id: int) -> dict:
    ws = next(iter(memberships(conn, user_id)), None)
    token, csrf = create_session(conn, user_id, ws["id"] if ws else None,
                                 request.client.host if request.client else "", request.headers.get("user-agent", ""))
    _set_cookie(response, token)
    return _me_payload(conn, user_id, Principal(user_id=user_id, email="", name="", via="session",
                                                workspace_id=ws["id"] if ws else None,
                                                role=ws["role"] if ws else None, csrf_token=csrf))


def _me_payload(conn, user_id: int, p: Principal) -> dict:
    user = conn.execute("SELECT id, email, username, name FROM users WHERE id = %s", (user_id,)).fetchone()
    ws_list = memberships(conn, user_id)
    if p.via == "api_key":
        ws_list = [w for w in ws_list if w["id"] == p.workspace_id]
    current = next(({**w, "role": p.role} for w in ws_list if w["id"] == p.workspace_id), None)
    return {"user": dict(user), "workspaces": ws_list, "workspace": current, "csrf_token": p.csrf_token,
            "via": p.via}


def _admin_count(conn, ws: int) -> int:
    return conn.execute("SELECT COUNT(*) FROM workspace_members WHERE workspace_id = %s AND role = 'admin'",
                        (ws,)).fetchone()[0]


# --------------------------------------------------------------------------- public
@router.get("/health", include_in_schema=False)
def health():
    with db.tx() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok"}


@router.get("/auth/config")
def auth_config():
    return {"registration": ALLOW_REGISTRATION, "demo": DEMO_USER_ENABLED}


@router.post("/auth/register", status_code=202)
def register(body: RegisterBody):
    if not ALLOW_REGISTRATION:
        raise HTTPException(403, "Self-registration is disabled")
    email = _norm_email(body.email)
    with db.tx() as conn:
        row = conn.execute("SELECT id, email_verified_at FROM users WHERE lower(email) = %s", (email,)).fetchone()
        if row and row["email_verified_at"]:
            log.info("registration attempt for already verified account %s", email)
        elif row:
            _issue_code(conn, row["id"], email)
        else:
            user_id = create_user(conn, email, body.password, body.name or email.split("@")[0])
            create_workspace(conn, body.workspace_name or f"{body.name or email.split('@')[0]}'s workspace", user_id)
            _issue_code(conn, user_id, email)
    return {"status": "verification_required",
            "message": "Check the server console for your verification code, then verify your email."}


@router.post("/auth/resend", status_code=202)
def resend_code(body: EmailBody):
    email = _norm_email(body.email)
    with db.tx() as conn:
        row = conn.execute("SELECT id FROM users WHERE lower(email) = %s AND email_verified_at IS NULL",
                           (email,)).fetchone()
        if row:
            _issue_code(conn, row["id"], email)
    return {"status": "verification_required"}


@router.post("/auth/verify")
def verify_email(body: VerifyBody, request: Request, response: Response):
    email = _norm_email(body.email)
    bad = HTTPException(400, "Invalid or expired verification code")
    with db.tx() as conn:
        user = conn.execute("SELECT id FROM users WHERE lower(email) = %s AND email_verified_at IS NULL AND is_active",
                            (email,)).fetchone()
        ver = conn.execute(
            "SELECT id, code_hash, attempts FROM email_verifications WHERE user_id = %s AND consumed_at IS NULL "
            "AND expires_at > now() ORDER BY id DESC LIMIT 1", (user["id"],)).fetchone() if user else None
        if not ver or ver["attempts"] >= MAX_CODE_ATTEMPTS:
            verify_secret(None, body.code)
            raise bad
        if not verify_secret(ver["code_hash"], body.code.strip()):
            conn.execute("UPDATE email_verifications SET attempts = attempts + 1 WHERE id = %s", (ver["id"],))
            conn.commit()
            raise bad
        conn.execute("UPDATE email_verifications SET consumed_at = now() WHERE id = %s", (ver["id"],))
        conn.execute("UPDATE users SET email_verified_at = now(), updated_at = now() WHERE id = %s", (user["id"],))
        log.info("email verified for %s", email)
        return _start_session(conn, request, response, user["id"])


@router.post("/auth/login")
def login(body: LoginBody, request: Request, response: Response):
    ident = (body.login or "").strip().lower()
    bad = HTTPException(401, "Invalid credentials")
    with db.tx() as conn:
        user = conn.execute(
            "SELECT id, password_hash, is_active, email_verified_at, failed_logins, locked_until FROM users "
            "WHERE lower(email) = %s OR lower(username) = %s ORDER BY id LIMIT 1", (ident, ident)).fetchone()
        if not user:
            verify_secret(None, body.password)
            raise bad
        if user["locked_until"] and user["locked_until"] > utcnow():
            raise HTTPException(429, "Too many failed sign-in attempts - try again later")
        if not verify_secret(user["password_hash"], body.password):
            fails = user["failed_logins"] + 1
            if fails >= MAX_LOGIN_FAILURES:
                conn.execute("UPDATE users SET failed_logins = 0, locked_until = %s WHERE id = %s",
                             (utcnow() + timedelta(minutes=LOCKOUT_MINUTES), user["id"]))
                log.warning("account %s locked for %d min after %d failed sign-ins", user["id"], LOCKOUT_MINUTES, fails)
            else:
                conn.execute("UPDATE users SET failed_logins = %s WHERE id = %s", (fails, user["id"]))
            conn.commit()
            raise bad
        if not user["is_active"]:
            raise bad
        if not user["email_verified_at"]:
            raise HTTPException(403, "Email not verified")
        if needs_rehash(user["password_hash"]):
            conn.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hash_secret(body.password), user["id"]))
        conn.execute("UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = now() WHERE id = %s",
                     (user["id"],))
        return _start_session(conn, request, response, user["id"])


# --------------------------------------------------------------------------- account
@router.post("/auth/logout")
def logout(response: Response, p: Principal = Depends(require_session_user)):
    with db.tx() as conn:
        conn.execute("DELETE FROM sessions WHERE id = %s", (p.session_id,))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/auth/me")
def me(p: Principal = Depends(current_principal)):
    with db.tx() as conn:
        return _me_payload(conn, p.user_id, p)


@router.post("/auth/password")
def change_password(body: PasswordBody, p: Principal = Depends(require_session_user)):
    with db.tx() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE id = %s", (p.user_id,)).fetchone()
        if not verify_secret(row["password_hash"], body.current_password):
            raise HTTPException(400, "Current password is incorrect")
        conn.execute("UPDATE users SET password_hash = %s, updated_at = now() WHERE id = %s",
                     (hash_secret(body.new_password), p.user_id))
        conn.execute("DELETE FROM sessions WHERE user_id = %s AND id != %s", (p.user_id, p.session_id))
    return {"ok": True}


@router.post("/auth/workspace")
def switch_workspace(body: WorkspaceSwitch, p: Principal = Depends(require_session_user)):
    with db.tx() as conn:
        if not any(w["id"] == body.workspace_id for w in memberships(conn, p.user_id)):
            raise HTTPException(404, "Workspace not found")
        conn.execute("UPDATE sessions SET workspace_id = %s WHERE id = %s", (body.workspace_id, p.session_id))
        p.workspace_id = body.workspace_id
        p.role = next(w["role"] for w in memberships(conn, p.user_id) if w["id"] == body.workspace_id)
        return _me_payload(conn, p.user_id, p)


# --------------------------------------------------------------------------- workspaces
@router.get("/workspaces")
def list_workspaces(p: Principal = Depends(require_user)):
    with db.tx() as conn:
        ws = memberships(conn, p.user_id)
    return [w for w in ws if p.via == "session" or w["id"] == p.workspace_id]


@router.post("/workspaces", status_code=201)
def new_workspace(body: WorkspaceBody, p: Principal = Depends(require_session_user)):
    with db.tx() as conn:
        ws = create_workspace(conn, body.name, p.user_id)
        conn.execute("UPDATE sessions SET workspace_id = %s WHERE id = %s", (ws, p.session_id))
        p.workspace_id, p.role = ws, "admin"
        return _me_payload(conn, p.user_id, p)


@router.patch("/workspace")
def rename_workspace(body: WorkspaceBody, p: Principal = Depends(require_role("admin"))):
    with db.tx() as conn:
        conn.execute("UPDATE workspaces SET name = %s WHERE id = %s", (body.name.strip(), p.workspace_id))
        return _me_payload(conn, p.user_id, p)


@router.get("/workspace/members")
def list_members(p: Principal = Depends(require_role("read"))):
    with db.tx() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT u.id AS user_id, u.email, u.name, m.role, m.created_at FROM workspace_members m "
            "JOIN users u ON u.id = m.user_id WHERE m.workspace_id = %s ORDER BY u.email", (p.workspace_id,))]


@router.post("/workspace/members", status_code=201)
def add_member(body: MemberAdd, p: Principal = Depends(require_role("admin"))):
    email = _norm_email(body.email)
    with db.tx() as conn:
        user = conn.execute("SELECT id FROM users WHERE lower(email) = %s AND email_verified_at IS NOT NULL",
                            (email,)).fetchone()
        if not user:
            raise HTTPException(404, "No verified account with that email - ask them to register first")
        conn.execute("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (%s, %s, %s) "
                     "ON CONFLICT (workspace_id, user_id) DO UPDATE SET role = excluded.role",
                     (p.workspace_id, user["id"], body.role))
    return list_members(p)


@router.patch("/workspace/members/{user_id}")
def update_member(user_id: int, body: MemberUpdate, p: Principal = Depends(require_role("admin"))):
    with db.tx() as conn:
        row = conn.execute("SELECT role FROM workspace_members WHERE workspace_id = %s AND user_id = %s",
                           (p.workspace_id, user_id)).fetchone()
        if not row:
            raise HTTPException(404, "Member not found")
        if row["role"] == "admin" and body.role != "admin" and _admin_count(conn, p.workspace_id) <= 1:
            raise HTTPException(400, "A workspace needs at least one admin")
        conn.execute("UPDATE workspace_members SET role = %s WHERE workspace_id = %s AND user_id = %s",
                     (body.role, p.workspace_id, user_id))
    return list_members(p)


@router.delete("/workspace/members/{user_id}")
def remove_member(user_id: int, p: Principal = Depends(require_role("admin"))):
    with db.tx() as conn:
        row = conn.execute("SELECT role FROM workspace_members WHERE workspace_id = %s AND user_id = %s",
                           (p.workspace_id, user_id)).fetchone()
        if not row:
            raise HTTPException(404, "Member not found")
        if row["role"] == "admin" and _admin_count(conn, p.workspace_id) <= 1:
            raise HTTPException(400, "A workspace needs at least one admin")
        conn.execute("DELETE FROM workspace_members WHERE workspace_id = %s AND user_id = %s",
                     (p.workspace_id, user_id))
        conn.execute("UPDATE api_keys SET revoked_at = now() WHERE workspace_id = %s AND user_id = %s "
                     "AND revoked_at IS NULL", (p.workspace_id, user_id))
    return list_members(p)


# --------------------------------------------------------------------------- API keys
def _key_row(r) -> dict:
    return {k: r[k] for k in ("id", "name", "prefix", "role", "created_at", "last_used_at", "expires_at",
                              "revoked_at", "user_id", "email")}


@router.get("/api-keys")
def list_api_keys(p: Principal = Depends(require_role("read"))):
    sql = ("SELECT k.*, u.email FROM api_keys k JOIN users u ON u.id = k.user_id WHERE k.workspace_id = %s")
    args: list = [p.workspace_id]
    if p.role != "admin":
        sql += " AND k.user_id = %s"
        args.append(p.user_id)
    with db.tx() as conn:
        return [_key_row(r) for r in conn.execute(sql + " ORDER BY k.created_at DESC", args)]


@router.post("/api-keys", status_code=201)
def create_api_key(body: ApiKeyCreate, p: Principal = Depends(require_role("read"))):
    if p.via != "session":
        raise HTTPException(403, "API keys cannot create API keys")
    if ROLE_RANK[body.role] > ROLE_RANK[p.role]:
        raise HTTPException(403, f"You cannot create a key with more access than your own role ('{p.role}')")
    key, prefix = new_api_key()
    expires = utcnow() + timedelta(days=body.expires_in_days) if body.expires_in_days else None
    with db.tx() as conn:
        row = conn.execute(
            "INSERT INTO api_keys (workspace_id, user_id, name, prefix, key_hash, role, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING *",
            (p.workspace_id, p.user_id, body.name.strip(), prefix, hash_secret(key), body.role, expires)).fetchone()
    return {**_key_row({**row, "email": p.email}), "key": key}


@router.delete("/api-keys/{key_id}")
def revoke_api_key(key_id: int, p: Principal = Depends(require_role("read"))):
    with db.tx() as conn:
        row = conn.execute("SELECT user_id FROM api_keys WHERE id = %s AND workspace_id = %s",
                           (key_id, p.workspace_id)).fetchone()
        if not row or (row["user_id"] != p.user_id and p.role != "admin"):
            raise HTTPException(404, "API key not found")
        conn.execute("UPDATE api_keys SET revoked_at = now() WHERE id = %s AND revoked_at IS NULL", (key_id,))
    return {"ok": True}
