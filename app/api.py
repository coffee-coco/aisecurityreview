"""REST API for reviews, catalog browsing and settings."""
from __future__ import annotations

import json
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from . import db, jobs, mappings, profile, threat_models
from .ai.providers import PROVIDERS, ProviderError, build_llm
from .ai.scoping import FLAG_LABELS, scope_review
from .catalog import get_catalog
from .config import DEFAULT_MODELS
from .items import create_item, load_items, load_mitigations
from .report import render_markdown
from .threat import store as threat_store

router = APIRouter(prefix="/api")

Classification = Literal["public", "internal", "confidential", "restricted"]
Priority = Literal["low", "medium", "high", "critical"]
Exposure = Literal["internal", "partner", "public"]


# --------------------------------------------------------------------------- models
class ReviewCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = ""
    change_type: Literal["new", "change"] = "new"
    requester: str = ""
    business_owner: str = ""
    reviewer: str = ""
    business_unit: str = ""
    data_classification: Classification = "internal"
    tech_stack: str = ""
    internet_facing: bool = False
    personal_data: bool = False
    third_party: bool = False
    uses_ai: bool = False
    priority: Priority = "medium"
    due_date: str = ""
    exposure: Optional[Exposure] = None
    data_types: list[str] = []
    interacts_with: list[Classification] = []
    system_types: list[str] = []
    auto_scope: bool = True


class ReviewUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    change_type: Optional[Literal["new", "change"]] = None
    requester: Optional[str] = None
    business_owner: Optional[str] = None
    reviewer: Optional[str] = None
    business_unit: Optional[str] = None
    data_classification: Optional[Classification] = None
    tech_stack: Optional[str] = None
    internet_facing: Optional[bool] = None
    personal_data: Optional[bool] = None
    third_party: Optional[bool] = None
    uses_ai: Optional[bool] = None
    status: Optional[Literal["new", "in_progress", "awaiting_info", "approved", "rejected"]] = None
    priority: Optional[Priority] = None
    risk_rating: Optional[Literal["", "low", "medium", "high", "critical"]] = None
    due_date: Optional[str] = None
    technologies: Optional[list[str]] = None
    services: Optional[list[str]] = None
    decision_notes: Optional[str] = None
    exposure: Optional[Exposure] = None
    data_types: Optional[list[str]] = None
    interacts_with: Optional[list[Classification]] = None
    system_types: Optional[list[str]] = None


class RequirementAdd(BaseModel):
    subcategory_id: str
    priority: Literal["low", "medium", "high"] = "medium"


class RequirementUpdate(BaseModel):
    status: Optional[Literal["open", "met", "partial", "not_met", "na"]] = None
    answer: Optional[str] = None
    notes: Optional[str] = None
    priority: Optional[Literal["low", "medium", "high"]] = None


class CheckUpdate(BaseModel):
    status: Literal["applicable", "pass", "fail", "na", "exception"]
    note: str = ""


class SettingsUpdate(BaseModel):
    ai_provider: Optional[str] = None
    ai_model: Optional[str] = None
    openai_api_key: Optional[str] = None
    openai_base_url: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None
    ollama_base_url: Optional[str] = None


SECRET_KEYS = ("openai_api_key", "anthropic_api_key", "gemini_api_key")
STATUS_LABELS = {"new": "New", "in_progress": "In progress", "awaiting_info": "Awaiting info",
                 "approved": "Approved", "rejected": "Rejected"}
LIST_COLUMNS = ("technologies", "services", "data_types", "interacts_with", "system_types")


def sync_profile(data: dict, current: dict | None = None) -> dict:
    """Keep the legacy boolean flags consistent with the richer profile fields (and vice versa)."""
    cur = current or {}
    if "data_types" in data:
        data["data_types"] = [d for d in dict.fromkeys(data["data_types"] or []) if d in profile.DATA_TYPES]
    if "system_types" in data:
        data["system_types"] = [s for s in dict.fromkeys(data["system_types"] or []) if s in profile.SYSTEM_TYPES]
    if "interacts_with" in data:
        data["interacts_with"] = [c for c in dict.fromkeys(data["interacts_with"] or []) if c in profile.CLASSIFICATIONS]
    if data.get("exposure") is None and "internet_facing" in data:
        data["exposure"] = "public" if data["internet_facing"] else (
            cur.get("exposure") if cur.get("exposure") != "public" else "internal") or "internal"
    elif data.get("exposure") is None:
        data.pop("exposure", None)
    if "exposure" in data:
        data["internet_facing"] = data["exposure"] in ("public", "partner")
    if data.get("data_types"):
        data["personal_data"] = bool(set(data["data_types"]) & profile.PERSONAL_TYPES)
    if "system_types" in data and set(data["system_types"]) & {"ai_agent", "ai_ml"}:
        data["uses_ai"] = True
    if "system_types" in data and "saas" in data["system_types"]:
        data["third_party"] = True
    return data


# --------------------------------------------------------------------------- helpers
def _get_review(conn, review_id: int) -> dict:
    row = db.review_row(conn.execute("SELECT * FROM reviews WHERE id = ?", (review_id,)).fetchone())
    if not row:
        raise HTTPException(404, "Review not found")
    if row.get("kind") != "threat_model":
        _attach_threat_models(conn, row)
    return row


def _attach_threat_models(conn, review: dict) -> None:
    """Linked threat models feed the review's AI steps: a brief of each, and their code review when the review
    has none of its own."""
    tms = [db.review_row(conn.execute("SELECT * FROM reviews WHERE id = ?", (t,)).fetchone())
           for t in threat_models.linked_ids(conn, review["id"])]
    briefs = []
    for tm in tms:
        arts = threat_store.get_artifacts(conn, tm["id"])
        data = (arts.get("threat_model") or {}).get("data") or {}
        dfd = (arts.get("dfd") or {}).get("data") or {}
        briefs.append({
            "id": tm["id"], "ref": tm["ref"], "title": tm["title"], "summary": data.get("summary") or "",
            "threats": [{k: t.get(k) for k in ("id", "title", "category", "component")} for t in data.get("threats") or []],
            "data_flow_diagram": {k: dfd.get(k) for k in ("nodes", "edges", "trust_boundaries")} if dfd.get("nodes") else None,
        })
    review["linked_threat_models"] = briefs
    if not review.get("code_review"):
        review["code_review"] = threat_models.merged_code_review(tms)


def _requirements(conn, review_id: int) -> list[dict]:
    """Legacy shape: the NIST CSF question items of a review."""
    return [i for i in load_items(conn, review_id, get_catalog()) if i["subcategory_id"]]


def _check_states(conn, review_id: int) -> dict[str, dict]:
    return {r["check_id"]: dict(r) for r in conn.execute("SELECT * FROM review_checks WHERE review_id = ?", (review_id,))}


UNTOUCHED_SQL = """source NOT IN ('manual', 'library', 'code', 'document') AND kind = 'question' AND status = 'open'
    AND trim(answer) = '' AND trim(notes) = '' AND is_risk = 0 AND is_recommendation = 0
    AND NOT EXISTS (SELECT 1 FROM item_mitigations im WHERE im.item_id = items.id)"""


def _apply_scope(conn, review: dict, result: dict) -> None:
    review_id = review["id"]
    # Remove untouched AI/heuristic questions; keep anything manual or already worked on.
    conn.execute(f"DELETE FROM items WHERE review_id = ? AND {UNTOUCHED_SQL}", (review_id,))
    ts = db.now()
    for s in result["subcategories"]:
        conn.execute(
            """INSERT INTO items (review_id, kind, subcategory_id, priority, rationale, source, created_at, updated_at)
               VALUES (?, 'question', ?, ?, ?, ?, ?, ?)
               ON CONFLICT(review_id, subcategory_id) WHERE subcategory_id IS NOT NULL DO UPDATE SET
                 priority = excluded.priority, rationale = excluded.rationale""",
            (review_id, s["id"], s["priority"], s["rationale"], result["source"], ts, ts),
        )
    # Project-specific clarifying questions become custom question rows.
    have = {r[0].strip().lower() for r in conn.execute(
        "SELECT title FROM items WHERE review_id = ? AND subcategory_id IS NULL", (review_id,))}
    for q in result.get("clarifying_questions") or []:
        if q.strip() and q.strip().lower() not in have:
            create_item(conn, review_id, {"kind": "question", "title": q.strip(), "source": result["source"],
                                          "rationale": "Project-specific question suggested during scoping",
                                          "priority": "medium"})
    ai_meta = {k: v for k, v in result.items() if k not in ("subcategories", "technologies", "services")}
    conn.execute(
        """UPDATE reviews SET ai_meta = ?, technologies = ?, services = ?, updated_at = ?,
                  risk_rating = CASE WHEN risk_rating = '' THEN ? ELSE risk_rating END
           WHERE id = ?""",
        (json.dumps(ai_meta), json.dumps(result["technologies"]), json.dumps(result["services"]), ts,
         result["inherent_risk"], review_id),
    )
    db.log_activity(conn, review_id, "scoped",
                    f"{len(result['subcategories'])} requirements via {result['provider']}"
                    + (f" - {result['warning']}" if result.get("warning") else ""))


# --------------------------------------------------------------------------- meta / catalog
@router.get("/meta")
def meta():
    cat = get_catalog()
    s = db.get_settings()
    return {
        "catalog": cat.meta,
        "providers": [{"name": p, "count": n} for p, n in cat.providers.most_common()],
        "statuses": [{"id": k, "label": v} for k, v in STATUS_LABELS.items()],
        "flags": FLAG_LABELS,
        "functions": [{"id": f["id"], "title": f["title"], "text": f["text"], "framework": f.get("framework", "csf"),
                       "color": f.get("color", f["id"][:2])} for f in cat.functions],
        "frameworks": getattr(cat, "frameworks", []),
        "ai": {"provider": s.get("ai_provider"), "model": s.get("ai_model") or DEFAULT_MODELS.get(s.get("ai_provider", ""), "")},
        "profile": profile.vocab(),
    }


@router.get("/catalog/tree")
def catalog_tree():
    return get_catalog().tree()


@router.get("/catalog/subcategories/{sid}/checks")
def subcategory_checks(sid: str, providers: str = "", services: str = "", q: str = ""):
    cat = get_catalog()
    if sid not in cat.subcategories:
        raise HTTPException(404, "Unknown subcategory")
    with db.tx() as conn:
        overrides = mappings.overrides(conn, sid)
    checks = cat.subcategory_checks(sid, [p for p in providers.split(",") if p], services.split(","), q, overrides)
    return {"subcategory": cat.subcategory_brief(sid), "checks": checks}


@router.get("/catalog/checks")
def search_checks(q: str = "", provider: str = "", control: str = "", resource: str = "", offset: int = 0,
                  limit: int = 200):
    return get_catalog().search_checks(q, provider, control, min(limit, 2000), resource, offset)


@router.get("/catalog/controls/{cid}")
def control_detail(cid: str):
    cat = get_catalog()
    c = cat.controls.get(cid.upper())
    if not c:
        raise HTTPException(404, "Unknown control")
    subs = [s["id"] for s in cat.subcategories.values() if c["id"].split("(")[0] in s["controls"]]
    checks = cat.search_checks(control=c["id"], limit=2000)
    return {**c, "family_title": cat.families.get(c["family"], ""), "subcategories": subs,
            "check_count": len(checks)}


# --------------------------------------------------------------------------- reviews
@router.get("/stats")
def stats():
    with db.tx() as conn:
        by_status = {r["status"]: r["n"] for r in
                     conn.execute("SELECT status, COUNT(*) n FROM reviews WHERE kind = 'review' GROUP BY status")}
        overdue = conn.execute(
            "SELECT COUNT(*) FROM reviews WHERE kind = 'review' AND due_date != '' AND due_date < date('now') "
            "AND status NOT IN ('approved', 'rejected')").fetchone()[0]
        by_risk = {r["risk_rating"] or "unrated": r["n"] for r in conn.execute(
            "SELECT risk_rating, COUNT(*) n FROM reviews WHERE kind = 'review' AND status NOT IN ('approved','rejected') "
            "GROUP BY risk_rating")}
    return {"by_status": {k: by_status.get(k, 0) for k in STATUS_LABELS}, "overdue": overdue,
            "open_by_risk": by_risk, "total": sum(by_status.values())}


@router.get("/reviews")
def list_reviews(status: str = "", q: str = ""):
    ans = profile.ANSWERED_SQL
    sql = f"""SELECT r.*,
               (SELECT COUNT(*) FROM items x WHERE x.review_id = r.id) AS req_total,
               (SELECT COUNT(*) FROM items x WHERE x.review_id = r.id AND ({ans})) AS req_done,
               (SELECT COUNT(*) FROM items x WHERE x.review_id = r.id AND x.kind = 'question'
                  AND x.status IN ('not_met','partial')) AS req_gaps,
               (SELECT COUNT(*) FROM items x WHERE x.review_id = r.id AND (x.is_risk = 1 OR x.kind = 'risk')) AS risks,
               (SELECT COUNT(*) FROM items x WHERE x.review_id = r.id
                  AND (x.is_recommendation = 1 OR x.kind = 'recommendation')) AS recs,
               (SELECT COUNT(*) FROM mitigations m WHERE m.review_id = r.id) AS controls,
               (SELECT COUNT(*) FROM review_checks c WHERE c.review_id = r.id AND c.status = 'fail') AS checks_failed
             FROM reviews r WHERE r.kind = 'review'"""
    args: list = []
    if status:
        sql += " AND r.status = ?"
        args.append(status)
    if q:
        sql += " AND (r.title LIKE ? OR r.description LIKE ? OR r.business_unit LIKE ? OR r.requester LIKE ?)"
        args += [f"%{q}%"] * 4
    sql += " ORDER BY CASE r.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, r.updated_at DESC"
    with db.tx() as conn:
        rows = []
        for r in conn.execute(sql, args):
            d = db.review_row(r)
            for k in ("ai_meta", "design", "code_review", "linked_threat_models"):
                d.pop(k, None)
            for k in ("req_total", "req_done", "req_gaps", "risks", "recs", "controls", "checks_failed"):
                d[k] = r[k]
            rows.append(d)
    return rows


@router.post("/reviews", status_code=201)
async def create_review(body: ReviewCreate):
    data = sync_profile(body.model_dump())
    auto_scope = data.pop("auto_scope")
    ts = db.now()
    cols = list(data.keys()) + ["created_at", "updated_at"]
    vals = [json.dumps(v) if k in LIST_COLUMNS else int(v) if isinstance(v, bool) else v
            for k, v in data.items()] + [ts, ts]
    with db.tx() as conn:
        cur = conn.execute(f"INSERT INTO reviews ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", vals)
        review_id = cur.lastrowid
        db.log_activity(conn, review_id, "created",
                        f"{'New initiative' if body.change_type == 'new' else 'Change'} submitted by {body.requester or 'unknown'}")
        review = _get_review(conn, review_id)
    if auto_scope:
        await run_scope(review_id)
    return get_review(review_id)


@router.get("/reviews/{review_id}")
def get_review(review_id: int):
    cat = get_catalog()
    with db.tx() as conn:
        review = _get_review(conn, review_id)
        items = load_items(conn, review_id, cat)
        mitigations = load_mitigations(conn, review_id)
        documents = [_doc_row(r) for r in conn.execute(
            "SELECT * FROM documents WHERE review_id = ? ORDER BY id", (review_id,))]
        checks = _check_states(conn, review_id)
        activity = [dict(r) for r in conn.execute(
            "SELECT ts, action, detail FROM activity WHERE review_id = ? ORDER BY id DESC LIMIT 100", (review_id,))]
        linked_reviews = [{"id": r["id"], "ref": f"SR-{r['id']:04d}", "title": r["title"], "status": r["status"]}
                          for r in conn.execute(
                              "SELECT r.id, r.title, r.status FROM review_threat_models l JOIN reviews r ON r.id = l.review_id "
                              "WHERE l.threat_model_id = ? ORDER BY r.id", (review_id,))]
    counts: dict[str, int] = {}
    for c in checks.values():
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    code = review.get("code_review") or {}
    if code.get("inventory"):  # file list is fetched on demand
        code = {**code, "inventory": {k: v for k, v in code["inventory"].items() if k != "file_list"}}
    return {**review, "code_review": code, "items": items, "mitigations": mitigations, "documents": documents,
            "linked_reviews": linked_reviews,
            "requirements": [i for i in items if i["subcategory_id"]],
            "effective_classification": profile.effective_class(review),
            "progress": _progress(items, mitigations), "jobs": jobs.active_jobs(review_id),
            "check_states": checks, "check_counts": counts, "activity": activity}


def _doc_row(r) -> dict:
    d = dict(r)
    try:
        d["meta"] = json.loads(d.get("meta") or "{}")
    except json.JSONDecodeError:
        d["meta"] = {}
    d.pop("path", None)
    return d


def _progress(items: list[dict], mitigations: list[dict]) -> dict:
    out = {"total": len(items), "answered": sum(1 for i in items if i["answered"])}
    for kind in ("question", "risk", "recommendation"):
        rows = [i for i in items if i["kind"] == kind]
        out[kind] = {"total": len(rows), "answered": sum(1 for i in rows if i["answered"])}
    risks = [i for i in items if i["is_risk"]]
    out["risks"] = {r: sum(1 for i in risks if i["risk_rating"] == r) for r in ("critical", "high", "medium", "low")}
    out["risks"]["unrated"] = sum(1 for i in risks if not i["risk_rating"])
    out["risk_total"] = len(risks)
    out["risk_untreated"] = sum(1 for i in risks if not i["treatment"] and not i["mitigation_ids"])
    out["rec_total"] = sum(1 for i in items if i["is_recommendation"])
    out["gaps"] = sum(1 for i in items if i["status"] in ("not_met", "partial"))
    out["controls"] = len(mitigations)
    out["controls_new"] = sum(1 for m in mitigations if m["state"] == "new")
    out["no_control"] = sum(1 for i in items if (i["is_risk"] or i["status"] in ("not_met", "partial"))
                            and not i["mitigation_ids"])
    return out


@router.patch("/reviews/{review_id}")
def update_review(review_id: int, body: ReviewUpdate):
    updates = body.model_dump(exclude_unset=True)
    if not updates:
        return get_review(review_id)
    with db.tx() as conn:
        before = _get_review(conn, review_id)
        updates = sync_profile(updates, before)
        sets, vals = [], []
        for k, v in updates.items():
            sets.append(f"{k} = ?")
            vals.append(json.dumps(v) if k in LIST_COLUMNS else int(v) if isinstance(v, bool) else v)
        sets.append("updated_at = ?")
        vals += [db.now(), review_id]
        conn.execute(f"UPDATE reviews SET {', '.join(sets)} WHERE id = ?", vals)
        if "status" in updates and updates["status"] != before["status"]:
            db.log_activity(conn, review_id, "status",
                            f"{STATUS_LABELS[before['status']]} → {STATUS_LABELS[updates['status']]}")
        if "risk_rating" in updates and updates["risk_rating"] != before["risk_rating"]:
            db.log_activity(conn, review_id, "risk", f"Risk rating set to {updates['risk_rating'] or 'unrated'}")
        if "technologies" in updates:
            db.log_activity(conn, review_id, "scope", "Platforms: " + (", ".join(updates["technologies"]) or "none"))
        changed = [k for k in ("exposure", "data_classification", "data_types", "interacts_with", "system_types")
                   if k in updates and updates[k] != before.get(k)]
        if changed:
            db.log_activity(conn, review_id, "profile", "Updated " + ", ".join(c.replace("_", " ") for c in changed))
    return get_review(review_id)


@router.delete("/reviews/{review_id}", status_code=204)
def delete_review(review_id: int):
    with db.tx() as conn:
        _get_review(conn, review_id)
        conn.execute("DELETE FROM reviews WHERE id = ?", (review_id,))


@router.post("/reviews/{review_id}/scope")
async def run_scope(review_id: int):
    with db.tx() as conn:
        review = _get_review(conn, review_id)
    if review.get("kind") == "threat_model":
        raise HTTPException(400, "Scoping applies to security reviews, not threat models")
    try:
        llm = build_llm(db.get_settings())
    except ProviderError as e:
        raise HTTPException(400, str(e))
    result = await scope_review(review, get_catalog(), llm)
    with db.tx() as conn:
        _apply_scope(conn, review, result)
        if review["status"] == "new":
            conn.execute("UPDATE reviews SET status = 'in_progress' WHERE id = ?", (review_id,))
            db.log_activity(conn, review_id, "status", "New → In progress")
    return get_review(review_id)


@router.post("/reviews/{review_id}/requirements", status_code=201)
def add_requirement(review_id: int, body: RequirementAdd):
    sid = body.subcategory_id.upper()
    if sid not in get_catalog().subcategories:
        raise HTTPException(404, "Unknown requirement")
    with db.tx() as conn:
        _get_review(conn, review_id)
        ts = db.now()
        conn.execute(
            """INSERT INTO items (review_id, kind, subcategory_id, priority, rationale, source, created_at, updated_at)
               VALUES (?, 'question', ?, ?, 'Added manually by reviewer', 'manual', ?, ?)
               ON CONFLICT(review_id, subcategory_id) WHERE subcategory_id IS NOT NULL DO NOTHING""",
            (review_id, sid, body.priority, ts, ts))
        db.log_activity(conn, review_id, "requirement", f"Added {sid}")
    return get_review(review_id)


@router.patch("/reviews/{review_id}/requirements/{sid}")
def update_requirement(review_id: int, sid: str, body: RequirementUpdate):
    updates = body.model_dump(exclude_unset=True)
    with db.tx() as conn:
        row = conn.execute("SELECT * FROM items WHERE review_id = ? AND subcategory_id = ?",
                           (review_id, sid)).fetchone()
        if not row:
            raise HTTPException(404, "Requirement not in this review")
        if updates:
            sets = ", ".join(f"{k} = ?" for k in updates) + ", updated_at = ?"
            conn.execute(f"UPDATE items SET {sets} WHERE id = ?", [*updates.values(), db.now(), row["id"]])
            db.touch(conn, review_id)
            if "status" in updates and updates["status"] != row["status"]:
                db.log_activity(conn, review_id, "requirement", f"{sid} marked {updates['status'].replace('_', ' ')}")
        out = dict(conn.execute("SELECT * FROM items WHERE id = ?", (row["id"],)).fetchone())
    return out


@router.delete("/reviews/{review_id}/requirements/{sid}", status_code=204)
def remove_requirement(review_id: int, sid: str):
    with db.tx() as conn:
        conn.execute("DELETE FROM items WHERE review_id = ? AND subcategory_id = ?", (review_id, sid))
        db.log_activity(conn, review_id, "requirement", f"Removed {sid}")


@router.get("/reviews/{review_id}/requirements/{sid}/checks")
def requirement_checks(review_id: int, sid: str, q: str = "", all_platforms: bool = False,
                       include_removed: bool = False):
    cat = get_catalog()
    with db.tx() as conn:
        review = _get_review(conn, review_id)
        states = _check_states(conn, review_id)
        overrides = mappings.overrides(conn, sid, review_id)
    providers, fallback = ([], False) if all_platforms else cat.normalise_providers(review["technologies"])
    every = cat.subcategory_checks(sid, None, review["services"], q, overrides, keep_excluded=True)
    shown = {c["id"] for c in cat.subcategory_checks(sid, providers, None, q, overrides, keep_excluded=True)}
    checks = [c for c in every if c["id"] in shown and (include_removed or not c["excluded"])]
    for c in checks:
        st = states.get(c["id"])
        c["review_status"] = st["status"] if st else "applicable"
        c["review_note"] = st["note"] if st else ""
    return {"providers": providers, "technologies": review["technologies"], "provider_fallback": fallback,
            "services": review["services"], **cat.link_policy(sid),
            "hidden_by_provider": sum(1 for c in every if c["id"] not in shown and not c["excluded"]),
            "removed": sum(1 for c in every if c["id"] in shown and c["excluded"]), "checks": checks}


@router.put("/reviews/{review_id}/checks/{check_id}")
def set_check(review_id: int, check_id: str, body: CheckUpdate):
    if check_id not in get_catalog().checks_by_id:
        raise HTTPException(404, "Unknown Checkov check")
    with db.tx() as conn:
        _get_review(conn, review_id)
        conn.execute(
            """INSERT INTO review_checks (review_id, check_id, status, note, updated_at) VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(review_id, check_id) DO UPDATE SET status = excluded.status, note = excluded.note,
               updated_at = excluded.updated_at""",
            (review_id, check_id, body.status, body.note, db.now()))
        if body.status in ("fail", "exception"):
            db.log_activity(conn, review_id, "check", f"{check_id} marked {body.status}")
    return {"check_id": check_id, "status": body.status, "note": body.note}


@router.get("/reviews/{review_id}/report.md", response_class=PlainTextResponse)
def report(review_id: int):
    data = get_review(review_id)
    md = render_markdown(data, get_catalog())
    return PlainTextResponse(md, headers={
        "Content-Disposition": f'attachment; filename="{data["ref"]}-security-review.md"'})


# --------------------------------------------------------------------------- settings
def _masked(settings: dict) -> dict:
    out = {}
    for k, v in settings.items():
        if k in SECRET_KEYS:
            out[k] = ""
            out[f"{k}_set"] = bool(v)
            out[f"{k}_hint"] = f"••••{v[-4:]}" if v and len(v) > 8 else ("••••" if v else "")
        else:
            out[k] = v
    out["providers"] = PROVIDERS
    out["default_models"] = DEFAULT_MODELS
    return out


@router.get("/settings")
def get_settings():
    return _masked(db.get_settings())


@router.put("/settings")
def put_settings(body: SettingsUpdate):
    updates = body.model_dump(exclude_unset=True, exclude_none=True)
    if "ai_provider" in updates and updates["ai_provider"] not in PROVIDERS:
        raise HTTPException(400, f"Provider must be one of {PROVIDERS}")
    for k in SECRET_KEYS:  # empty secret = keep existing value
        if k in updates and not updates[k]:
            updates.pop(k)
    db.save_settings(updates)
    return _masked(db.get_settings())


@router.post("/settings/test")
async def test_settings():
    try:
        llm = build_llm(db.get_settings())
        if llm is None:
            return {"ok": True, "message": "Heuristic mode - no AI provider needed."}
        res = await llm.complete_json("You are a health check. Reply with JSON.",
                                      'Return {"status": "ok"} and nothing else.')
        return {"ok": True, "message": f"{llm.label} responded: {json.dumps(res)[:120]}"}
    except ProviderError as e:
        return {"ok": False, "message": str(e)}
