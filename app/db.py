"""SQLite persistence for the review queue."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

from .config import AI_DEFAULTS, DB_PATH

STATUSES = ["new", "in_progress", "awaiting_info", "approved", "rejected"]
REQ_STATUSES = ["open", "met", "partial", "not_met", "na"]
CHECK_STATUSES = ["applicable", "pass", "fail", "na", "exception"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS reviews (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    title               TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    change_type         TEXT NOT NULL DEFAULT 'new',
    requester           TEXT NOT NULL DEFAULT '',
    business_owner      TEXT NOT NULL DEFAULT '',
    reviewer            TEXT NOT NULL DEFAULT '',
    business_unit       TEXT NOT NULL DEFAULT '',
    data_classification TEXT NOT NULL DEFAULT 'internal',
    tech_stack          TEXT NOT NULL DEFAULT '',
    internet_facing     INTEGER NOT NULL DEFAULT 0,
    personal_data       INTEGER NOT NULL DEFAULT 0,
    third_party         INTEGER NOT NULL DEFAULT 0,
    uses_ai             INTEGER NOT NULL DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'new',
    priority            TEXT NOT NULL DEFAULT 'medium',
    risk_rating         TEXT NOT NULL DEFAULT '',
    due_date            TEXT NOT NULL DEFAULT '',
    technologies        TEXT NOT NULL DEFAULT '[]',
    services            TEXT NOT NULL DEFAULT '[]',
    ai_meta             TEXT NOT NULL DEFAULT '{}',
    decision_notes      TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

-- Legacy (v1) table - migrated into `items` once, kept for backwards compatibility.
CREATE TABLE IF NOT EXISTS review_requirements (
    review_id      INTEGER NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    subcategory_id TEXT NOT NULL,
    priority       TEXT NOT NULL DEFAULT 'medium',
    rationale      TEXT NOT NULL DEFAULT '',
    source         TEXT NOT NULL DEFAULT 'manual',
    status         TEXT NOT NULL DEFAULT 'open',
    answer         TEXT NOT NULL DEFAULT '',
    notes          TEXT NOT NULL DEFAULT '',
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (review_id, subcategory_id)
);

-- Every row of a review: NIST CSF questions, custom questions, risks and recommendations.
CREATE TABLE IF NOT EXISTS items (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    review_id          INTEGER NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    kind               TEXT NOT NULL DEFAULT 'question',   -- question | risk | recommendation
    subcategory_id     TEXT,                                -- set for NIST CSF questions
    library_ref        TEXT NOT NULL DEFAULT '',            -- risk-library id / code finding id (dedupe)
    title              TEXT NOT NULL DEFAULT '',            -- custom question / risk title / recommendation title
    answer             TEXT NOT NULL DEFAULT '',
    notes              TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL DEFAULT 'open',        -- open | met | partial | not_met | na
    priority           TEXT NOT NULL DEFAULT 'medium',
    rationale          TEXT NOT NULL DEFAULT '',
    source             TEXT NOT NULL DEFAULT 'manual',      -- ai | heuristic | manual | library | document | code
    is_risk            INTEGER NOT NULL DEFAULT 0,
    is_recommendation  INTEGER NOT NULL DEFAULT 0,
    risk               TEXT NOT NULL DEFAULT '',            -- risk statement
    likelihood         TEXT NOT NULL DEFAULT '',
    impact             TEXT NOT NULL DEFAULT '',
    impact_description TEXT NOT NULL DEFAULT '',
    treatment          TEXT NOT NULL DEFAULT '',            -- mitigate | accept | transfer | avoid
    recommendation     TEXT NOT NULL DEFAULT '',
    rec_status         TEXT NOT NULL DEFAULT '',            -- proposed | agreed | implemented | declined
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_items_csf ON items(review_id, subcategory_id) WHERE subcategory_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_items_review ON items(review_id);

-- Review-level register of mitigating controls; one control can close many items.
CREATE TABLE IF NOT EXISTS mitigations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    review_id   INTEGER NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    state       TEXT NOT NULL DEFAULT 'new',       -- existing | new
    status      TEXT NOT NULL DEFAULT 'proposed',  -- proposed | planned | in_progress | implemented | verified
    owner       TEXT NOT NULL DEFAULT '',
    due_date    TEXT NOT NULL DEFAULT '',
    nist        TEXT NOT NULL DEFAULT '[]',
    library_ref TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT 'manual',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_mit_review ON mitigations(review_id);

CREATE TABLE IF NOT EXISTS item_mitigations (
    item_id       INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    mitigation_id INTEGER NOT NULL REFERENCES mitigations(id) ON DELETE CASCADE,
    PRIMARY KEY (item_id, mitigation_id)
);

CREATE TABLE IF NOT EXISTS documents (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    review_id  INTEGER NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,                  -- document | image | code
    filename   TEXT NOT NULL,
    mime       TEXT NOT NULL DEFAULT '',
    size       INTEGER NOT NULL DEFAULT 0,
    sha256     TEXT NOT NULL DEFAULT '',
    path       TEXT NOT NULL,
    meta       TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS review_checks (
    review_id  INTEGER NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    check_id   TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'applicable',
    note       TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (review_id, check_id)
);

CREATE TABLE IF NOT EXISTS activity (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    review_id INTEGER NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    ts        TEXT NOT NULL,
    action    TEXT NOT NULL,
    detail    TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS jobs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    review_id  INTEGER NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'queued',   -- queued | running | done | error
    progress   REAL NOT NULL DEFAULT 0,
    message    TEXT NOT NULL DEFAULT '',
    result     TEXT NOT NULL DEFAULT '{}',
    error      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Deterministic AI: identical prompt + inputs => identical stored answer.
CREATE TABLE IF NOT EXISTS ai_cache (
    key        TEXT PRIMARY KEY,
    provider   TEXT NOT NULL,
    value      TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

# Columns added after v1 - applied with ALTER TABLE on existing databases.
REVIEW_COLUMNS = {
    "exposure": "TEXT NOT NULL DEFAULT 'internal'",      # internal | partner | public
    "data_types": "TEXT NOT NULL DEFAULT '[]'",
    "interacts_with": "TEXT NOT NULL DEFAULT '[]'",      # classifications of connected systems/data
    "system_types": "TEXT NOT NULL DEFAULT '[]'",
    "design": "TEXT NOT NULL DEFAULT '{}'",              # AI design understanding from documents
    "code_review": "TEXT NOT NULL DEFAULT '{}'",         # latest holistic code review
    "kind": "TEXT NOT NULL DEFAULT 'review'",            # review | threat_model
}

JSON_COLUMNS = ("technologies", "services", "ai_meta", "data_types", "interacts_with", "system_types",
                "design", "code_review")
JSON_OBJECTS = ("ai_meta", "design", "code_review")
BOOL_COLUMNS = ("internet_facing", "personal_data", "third_party", "uses_ai")
ITEM_BOOLS = ("is_risk", "is_recommendation")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def tx() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    from . import mappings, threat_models
    from .threat import store as threat_store

    with tx() as conn:
        conn.executescript(SCHEMA)
        mappings.init_schema(conn)
        threat_store.init_schema(conn)
        threat_models.init_schema(conn)
        have = {r["name"] for r in conn.execute("PRAGMA table_info(reviews)")}
        for col, ddl in REVIEW_COLUMNS.items():
            if col not in have:
                conn.execute(f"ALTER TABLE reviews ADD COLUMN {col} {ddl}")
                if col == "exposure":
                    conn.execute("UPDATE reviews SET exposure = CASE WHEN internet_facing = 1 THEN 'public' "
                                 "ELSE 'internal' END")
        done = conn.execute("SELECT value FROM settings WHERE key = 'migrated_items_v1'").fetchone()
        if not done:
            conn.execute(
                """INSERT OR IGNORE INTO items (review_id, kind, subcategory_id, answer, notes, status, priority,
                                                rationale, source, created_at, updated_at)
                   SELECT review_id, 'question', subcategory_id, answer, notes, status, priority, rationale,
                          source, updated_at, updated_at FROM review_requirements""")
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('migrated_items_v1', '1')")
        threat_models.migrate(conn)


def review_row(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    d = dict(row)
    for col in JSON_COLUMNS:
        if col not in d:
            continue
        empty = {} if col in JSON_OBJECTS else []
        try:
            d[col] = json.loads(d.get(col) or json.dumps(empty))
        except json.JSONDecodeError:
            d[col] = empty
    for col in BOOL_COLUMNS:
        d[col] = bool(d.get(col))
    d["ref"] = f"{'TM' if d.get('kind') == 'threat_model' else 'SR'}-{d['id']:04d}"
    return d


def log_activity(conn: sqlite3.Connection, review_id: int, action: str, detail: str = "") -> None:
    conn.execute("INSERT INTO activity (review_id, ts, action, detail) VALUES (?, ?, ?, ?)",
                 (review_id, now(), action, detail))


def touch(conn: sqlite3.Connection, review_id: int) -> None:
    conn.execute("UPDATE reviews SET updated_at = ? WHERE id = ?", (now(), review_id))


# ---------------------------------------------------------------------- settings
def get_settings() -> dict[str, str]:
    values = dict(AI_DEFAULTS)
    with tx() as conn:
        for row in conn.execute("SELECT key, value FROM settings"):
            values[row["key"]] = row["value"]
    return values


def save_settings(updates: dict[str, Any]) -> None:
    with tx() as conn:
        for k, v in updates.items():
            conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) "
                         "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (k, str(v)))
