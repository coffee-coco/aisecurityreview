"""Import an existing SQLite database (data/reviews.db) and its uploads into a Postgres workspace.

Review, item, control and document ids are preserved (promotion links, threat references and upload folders
depend on them), so the import stops if any of those ids already exist in Postgres. Run it against a freshly
migrated database before creating reviews there.

    python scripts/import_sqlite.py --sqlite data/reviews.db --user demo
    python scripts/import_sqlite.py --sqlite data/reviews.db --workspace-id 3 --uploads-src data/uploads

With Docker:

    docker compose run --rm -v "$PWD/data:/import:ro" api \\
        python scripts/import_sqlite.py --sqlite /import/reviews.db --uploads-src /import/uploads --user demo
"""
from __future__ import annotations

import argparse
import shutil
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db  # noqa: E402
from app.config import AI_DEFAULTS, UPLOAD_DIR  # noqa: E402

# (table, keep original ids) in foreign-key order
TABLES = [
    ("reviews", True), ("items", True), ("mitigations", True), ("item_mitigations", True), ("documents", True),
    ("review_checks", True), ("activity", False), ("review_threat_models", True), ("threat_artifacts", True),
    ("code_fixes", True), ("check_links", False), ("ai_cache", True),
]
ID_TABLES = ("reviews", "items", "mitigations", "documents")
WORKSPACE_TABLES = ("reviews", "check_links", "ai_cache")


def pg_columns(conn, table: str) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT column_name FROM information_schema.columns WHERE table_name = %s ORDER BY ordinal_position", (table,))]


def resolve_workspace(conn, workspace_id: int | None, user: str | None) -> int:
    if workspace_id:
        if not conn.execute("SELECT 1 FROM workspaces WHERE id = %s", (workspace_id,)).fetchone():
            sys.exit(f"Workspace {workspace_id} does not exist")
        return workspace_id
    row = conn.execute(
        "SELECT m.workspace_id FROM workspace_members m JOIN users u ON u.id = m.user_id "
        "WHERE (lower(u.email) = lower(%s) OR lower(u.username) = lower(%s)) AND m.role = 'admin' "
        "ORDER BY m.workspace_id LIMIT 1", (user, user)).fetchone()
    if not row:
        sys.exit(f"No workspace administered by '{user}'")
    return row[0]


def relative_upload(path: str, old_dir: str | None) -> Path | None:
    if old_dir and path.startswith(old_dir.rstrip("/") + "/"):
        return Path(path[len(old_dir.rstrip("/")) + 1:])
    if "/uploads/" in path:
        return Path(path.rsplit("/uploads/", 1)[1])
    return None


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sqlite", required=True, help="path to the SQLite reviews.db")
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("--workspace-id", type=int)
    target.add_argument("--user", help="email or username; imports into the first workspace they administer")
    ap.add_argument("--uploads-src", help="folder holding the old uploads (copied into UPLOAD_DIR)")
    ap.add_argument("--old-upload-dir", help="upload folder recorded in the SQLite paths (default: auto-detect)")
    ap.add_argument("--skip-settings", action="store_true", help="do not import AI provider settings")
    args = ap.parse_args()

    src = sqlite3.connect(f"file:{Path(args.sqlite).resolve()}?mode=ro&immutable=1", uri=True)
    src.row_factory = sqlite3.Row
    have = {r[0] for r in src.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "reviews" not in have:
        sys.exit("No reviews table in the SQLite database")

    with db.tx() as conn:
        ws = resolve_workspace(conn, args.workspace_id, args.user)
        for table in ID_TABLES:
            if table not in have:
                continue
            ids = [r[0] for r in src.execute(f"SELECT id FROM {table}")]
            if ids and conn.execute(f"SELECT 1 FROM {table} WHERE id = ANY(%s) LIMIT 1", (ids,)).fetchone():
                sys.exit(f"Some {table} ids already exist in Postgres - import into a fresh database")

        review_ids = [r[0] for r in src.execute("SELECT id FROM reviews")]
        counts: dict[str, int] = {}
        for table, keep_ids in TABLES:
            if table not in have:
                continue
            target_cols = pg_columns(conn, table)
            rows = src.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
            n = 0
            for row in rows:
                data = {k: row[k] for k in row.keys() if k in target_cols and (keep_ids or k != "id")}
                if table in WORKSPACE_TABLES:
                    data["workspace_id"] = ws
                if table == "documents":
                    rel = relative_upload(data["path"], args.old_upload_dir)
                    if rel is not None:
                        data["path"] = str(UPLOAD_DIR / rel)
                cols = list(data)
                cur = conn.execute(
                    f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))}) "
                    "ON CONFLICT DO NOTHING", list(data.values()))
                n += cur.rowcount
            counts[table] = n
        for table in ID_TABLES + ("activity", "check_links"):
            conn.execute(f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
                         f"GREATEST((SELECT COALESCE(MAX(id), 0) FROM {table}), 1))")

    if "settings" in have and not args.skip_settings:
        values = {r["key"]: r["value"] for r in src.execute("SELECT key, value FROM settings")
                  if r["key"] in AI_DEFAULTS and r["value"]}
        if values:
            db.save_settings(values, ws=ws)
            counts["settings"] = len(values)

    if args.uploads_src:
        src_dir = Path(args.uploads_src)
        copied = 0
        for rid in review_ids:
            if (src_dir / str(rid)).is_dir():
                shutil.copytree(src_dir / str(rid), UPLOAD_DIR / str(rid), dirs_exist_ok=True, symlinks=False)
                copied += 1
        counts["upload folders"] = copied

    db.close_pool()
    print(f"Imported into workspace {ws}: " + ", ".join(f"{k} {v}" for k, v in counts.items()))


if __name__ == "__main__":
    main()
