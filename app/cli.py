"""Operator commands.

    python -m app.cli migrate                 # alembic upgrade head
    python -m app.cli bootstrap               # demo users and workspaces when DEMO_USER_ENABLED=true
    python -m app.cli create-user --email you@example.com --workspace "Security team"   # prompts for a password
"""
from __future__ import annotations

import argparse
import getpass
import sys

from .config import DEMO_USER_ENABLED, ROOT

DEMO_EMAIL = "demo@sentinel.local"
# Non-admin demo users (login = password = username) and their roles in the demo workspaces; ``demo`` is admin of all.
DEMO_USERS = {"alice": "Alice (writer)", "bob": "Bob (writer)", "carol": "Carol (reader)"}
DEMO_WORKSPACES = {
    "Demo workspace": {"alice": "write", "bob": "write", "carol": "read"},
    "Platform team": {"alice": "write", "carol": "read"},
    "Data team": {"bob": "write", "carol": "read"},
}


def migrate() -> None:
    from alembic import command
    from alembic.config import Config

    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")


def _demo_user(conn, username: str, name: str) -> tuple[int, bool]:
    from .auth import create_user

    row = conn.execute("SELECT id FROM users WHERE lower(username) = %s", (username,)).fetchone()
    if row:
        return row["id"], False
    email = DEMO_EMAIL if username == "demo" else f"{username}@sentinel.local"
    return create_user(conn, email, username, name, username=username, verified=True), True


def bootstrap() -> None:
    """Idempotent: the demo admin (``demo`` / ``demo``), the non-admin demo users, the demo workspaces and their
    memberships. Existing memberships are left alone so role changes made in the app stick."""
    if not DEMO_USER_ENABLED:
        return
    from . import db
    from .auth import create_workspace

    created = []
    with db.tx() as conn:
        demo_id, new = _demo_user(conn, "demo", "Demo user")
        created += ["demo / demo (admin)"] if new else []
        users = {}
        for username, name in DEMO_USERS.items():
            users[username], new = _demo_user(conn, username, name)
            created += [f"{username} / {username}"] if new else []
        for ws_name, members in DEMO_WORKSPACES.items():
            row = conn.execute(
                "SELECT w.id FROM workspaces w JOIN workspace_members m ON m.workspace_id = w.id "
                "WHERE w.name = %s AND m.user_id = %s AND m.role = 'admin' ORDER BY w.id LIMIT 1",
                (ws_name, demo_id)).fetchone()
            ws = row["id"] if row else create_workspace(conn, ws_name, demo_id)
            for username, role in members.items():
                conn.execute("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (%s, %s, %s) "
                             "ON CONFLICT (workspace_id, user_id) DO NOTHING", (ws, users[username], role))
    if created:
        print("Created demo users (DEMO_USER_ENABLED=true): " + ", ".join(created))


def create_user_cmd(email: str, name: str, workspace: str) -> None:
    from . import db
    from .auth import create_user, create_workspace

    password = getpass.getpass("Password: ")
    if len(password) < 8 or password != getpass.getpass("Repeat password: "):
        sys.exit("Passwords must match and be at least 8 characters")
    with db.tx() as conn:
        if conn.execute("SELECT 1 FROM users WHERE lower(email) = lower(%s)", (email,)).fetchone():
            sys.exit(f"{email} already exists")
        user_id = create_user(conn, email, password, name or email.split("@")[0], verified=True)
        ws = create_workspace(conn, workspace or f"{name or email.split('@')[0]}'s workspace", user_id)
    print(f"Created {email} (verified) as admin of workspace {ws}")


def main() -> None:
    ap = argparse.ArgumentParser(prog="python -m app.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate")
    sub.add_parser("bootstrap")
    cu = sub.add_parser("create-user")
    cu.add_argument("--email", required=True)
    cu.add_argument("--name", default="")
    cu.add_argument("--workspace", default="")
    args = ap.parse_args()
    from . import db
    try:
        if args.cmd == "migrate":
            migrate()
        elif args.cmd == "bootstrap":
            bootstrap()
        else:
            create_user_cmd(args.email, args.name, args.workspace)
    finally:
        db.close_pool()


if __name__ == "__main__":
    main()
