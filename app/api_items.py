"""Line items, the mitigating-control register, AI writing and suggestion endpoints."""
from __future__ import annotations

import json
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from . import db, threat_models
from .ai.assist import deterministic_item_suggestions, item_suggestions, suggest_risks, write_text
from .ai.providers import ProviderError, build_llm
from .api import _get_review, _progress, get_review
from .catalog import get_catalog
from .items import (
    ITEM_FIELDS, MIT_FIELDS, create_item, create_mitigation, link, load_items, load_mitigations,
    mitigation_from_library,
)
from .library import mitigation_library, risk_library
from .profile import IMPACT, LIKELIHOOD, MIT_STATUSES, REC_STATUSES, TREATMENTS

router = APIRouter(prefix="/api")

Kind = Literal["question", "risk", "recommendation"]
ItemStatus = Literal["open", "met", "partial", "not_met", "na"]


# --------------------------------------------------------------------------- models
class ItemBody(BaseModel):
    kind: Optional[Kind] = None
    title: Optional[str] = Field(None, max_length=1000)
    answer: Optional[str] = None
    notes: Optional[str] = None
    rationale: Optional[str] = None
    status: Optional[ItemStatus] = None
    priority: Optional[Literal["low", "medium", "high"]] = None
    is_risk: Optional[bool] = None
    is_recommendation: Optional[bool] = None
    risk: Optional[str] = None
    likelihood: Optional[str] = None
    impact: Optional[str] = None
    impact_description: Optional[str] = None
    treatment: Optional[str] = None
    recommendation: Optional[str] = None
    rec_status: Optional[str] = None


class ItemCreate(ItemBody):
    kind: Kind = "question"
    subcategory_id: Optional[str] = None
    mitigation_ids: list[int] = []
    library_ref: str = ""
    source: str = "manual"


class NewControl(BaseModel):
    title: str = Field(min_length=2, max_length=300)
    description: str = ""
    state: Literal["existing", "new"] = "new"
    status: Optional[str] = None
    owner: str = ""
    due_date: str = ""
    nist: list[str] = []
    library_ref: str = ""
    source: str = "manual"


class LinkBody(BaseModel):
    mitigation_id: Optional[int] = None
    library_id: Optional[str] = None
    new: Optional[NewControl] = None


class MitCreate(NewControl):
    item_ids: list[int] = []


class MitUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    state: Optional[Literal["existing", "new"]] = None
    status: Optional[str] = None
    owner: Optional[str] = None
    due_date: Optional[str] = None
    nist: Optional[list[str]] = None


class BulkLink(BaseModel):
    item_ids: list[int]


class WriteBody(BaseModel):
    review_id: int
    item_id: Optional[int] = None
    mitigation_id: Optional[int] = None
    field: str
    text: str = ""
    mode: Literal["improve", "draft"] = "improve"


class RiskSuggestBody(BaseModel):
    ai: bool = True


class RiskAccept(BaseModel):
    title: str
    risk: str = ""
    likelihood: str = ""
    impact: str = ""
    recommendation: str = ""
    library_ref: str = ""
    csf: list[str] = []
    mitigations: list[str] = []
    rationale: str = ""
    source: str = "library"


class RiskAcceptBody(BaseModel):
    risks: list[RiskAccept]


class AutoMitigateBody(BaseModel):
    item_ids: list[int] = []
    include_library: bool = True


# --------------------------------------------------------------------------- helpers
def _validate(updates: dict) -> dict:
    checks = {"likelihood": LIKELIHOOD, "impact": IMPACT, "treatment": TREATMENTS, "rec_status": REC_STATUSES}
    for k, allowed in checks.items():
        if k in updates and updates[k] not in ("", *allowed):
            raise HTTPException(422, f"{k} must be one of {list(allowed)}")
    return updates


def _item_row(conn, review_id: int, item_id: int):
    row = conn.execute("SELECT * FROM items WHERE id = ? AND review_id = ?", (item_id, review_id)).fetchone()
    if not row:
        raise HTTPException(404, "Line item not found")
    return row


def _mit_row(conn, review_id: int, mid: int):
    row = conn.execute("SELECT * FROM mitigations WHERE id = ? AND review_id = ?", (mid, review_id)).fetchone()
    if not row:
        raise HTTPException(404, "Mitigating control not found")
    return row


def _context(review_id: int, item_id: int | None = None) -> tuple[dict, dict | None, list[dict], list[dict]]:
    cat = get_catalog()
    with db.tx() as conn:
        review = _get_review(conn, review_id)
        items = load_items(conn, review_id, cat)
        mits = load_mitigations(conn, review_id)
    item = None
    if item_id is not None:
        item = next((i for i in items if i["id"] == item_id), None)
        if item is None:
            raise HTTPException(404, "Line item not found")
        _attach_code_context(review, item)
    return review, item, items, mits


def _attach_code_context(review: dict, item: dict) -> None:
    ref = item.get("library_ref") or ""
    if ref.startswith("code:"):
        f = next((f for f in (review.get("code_review") or {}).get("findings", []) if f"code:{f['id']}" == ref), None)
        if f:
            item["code_mitigations"] = f.get("mitigations", [])


def _llm_or_none():
    try:
        return build_llm(db.get_settings())
    except ProviderError as e:
        raise HTTPException(400, str(e))


def _label(kind: str) -> str:
    return {"question": "question", "risk": "risk", "recommendation": "recommendation"}[kind]


# --------------------------------------------------------------------------- items
@router.post("/reviews/{review_id}/items", status_code=201)
def add_item(review_id: int, body: ItemCreate):
    data = _validate(body.model_dump(exclude_none=True))
    cat = get_catalog()
    mids = data.pop("mitigation_ids", [])
    sid = (data.get("subcategory_id") or "").upper() or None
    if sid and sid not in cat.subcategories:
        raise HTTPException(404, "Unknown requirement")
    data["subcategory_id"] = sid
    if not sid and not (data.get("title") or "").strip() and not (data.get("risk") or data.get("recommendation")):
        data["title"] = {"question": "New question", "risk": "New risk",
                         "recommendation": "New recommendation"}[data["kind"]]
    with db.tx() as conn:
        _get_review(conn, review_id)
        if sid and conn.execute("SELECT 1 FROM items WHERE review_id = ? AND subcategory_id = ?",
                                (review_id, sid)).fetchone():
            raise HTTPException(409, f"{sid} is already in this review")
        item_id = create_item(conn, review_id, data)
        for mid in mids:
            _mit_row(conn, review_id, mid)
            link(conn, item_id, mid)
        db.log_activity(conn, review_id, "item", f"Added {_label(data['kind'])}: "
                        f"{sid or (data.get('title') or data.get('risk') or '')[:80]}")
    return {"item_id": item_id, "review": get_review(review_id)}


@router.patch("/reviews/{review_id}/items/{item_id}")
def update_item(review_id: int, item_id: int, body: ItemBody):
    updates = _validate(body.model_dump(exclude_unset=True))
    updates = {k: v for k, v in updates.items() if k in ITEM_FIELDS and v is not None}
    with db.tx() as conn:
        row = _item_row(conn, review_id, item_id)
        if updates.get("kind") == "risk":
            updates["is_risk"] = True
        if updates.get("kind") == "recommendation":
            updates["is_recommendation"] = True
        if updates.get("is_risk") and not row["likelihood"] and "likelihood" not in updates:
            updates.setdefault("likelihood", "possible")
        if updates.get("is_recommendation") and not row["rec_status"] and "rec_status" not in updates:
            updates["rec_status"] = "proposed"
        if updates:
            vals = [int(v) if isinstance(v, bool) else v for v in updates.values()]
            conn.execute(f"UPDATE items SET {', '.join(f'{k} = ?' for k in updates)}, updated_at = ? WHERE id = ?",
                         [*vals, db.now(), item_id])
            db.touch(conn, review_id)
            label = row["subcategory_id"] or (row["title"] or "")[:60]
            if "status" in updates and updates["status"] != row["status"]:
                db.log_activity(conn, review_id, "item", f"{label} marked {updates['status'].replace('_', ' ')}")
            if updates.get("is_risk") and not row["is_risk"]:
                db.log_activity(conn, review_id, "risk", f"{label} flagged as a risk")
            if updates.get("is_recommendation") and not row["is_recommendation"]:
                db.log_activity(conn, review_id, "item", f"{label} flagged as a recommendation")
            if "treatment" in updates and updates["treatment"] != row["treatment"] and updates["treatment"]:
                db.log_activity(conn, review_id, "risk", f"{label}: treatment {updates['treatment']}")
        items = load_items(conn, review_id, get_catalog())
        mits = load_mitigations(conn, review_id)
    item = next(i for i in items if i["id"] == item_id)
    return {"item": item, "progress": _progress(items, mits)}


@router.delete("/reviews/{review_id}/items/{item_id}", status_code=204)
def delete_item(review_id: int, item_id: int):
    with db.tx() as conn:
        row = _item_row(conn, review_id, item_id)
        conn.execute("DELETE FROM items WHERE id = ?", (item_id,))
        _unpromote(conn, review_id, item_id)
        db.touch(conn, review_id)
        db.log_activity(conn, review_id, "item", f"Removed {row['subcategory_id'] or (row['title'] or row['kind'])[:80]}")


def _unpromote(conn, review_id: int, item_id: int) -> None:
    """Forget promotion links (from linked threat models) that pointed at a deleted item."""
    for tm_id in threat_models.linked_ids(conn, review_id):
        links = threat_models.get_links(conn, review_id, tm_id)
        before = json.dumps(links, sort_keys=True)
        links["threats"] = {k: v for k, v in links["threats"].items() if v.get("item_id") != item_id}
        links["findings"] = {k: v for k, v in links["findings"].items() if v != item_id}
        if json.dumps(links, sort_keys=True) != before:
            threat_models.save_links(conn, review_id, tm_id, links)


# --------------------------------------------------------------------------- item <-> control links
@router.post("/reviews/{review_id}/items/{item_id}/mitigations")
def link_mitigation(review_id: int, item_id: int, body: LinkBody):
    with db.tx() as conn:
        row = _item_row(conn, review_id, item_id)
        if body.mitigation_id:
            _mit_row(conn, review_id, body.mitigation_id)
            mid = body.mitigation_id
        elif body.library_id:
            if body.library_id not in mitigation_library():
                raise HTTPException(404, "Unknown library control")
            mid = mitigation_from_library(conn, review_id, body.library_id)
        elif body.new:
            mid = create_mitigation(conn, review_id, body.new.model_dump())
        else:
            raise HTTPException(422, "Provide mitigation_id, library_id or new")
        link(conn, item_id, mid)
        title = conn.execute("SELECT title FROM mitigations WHERE id = ?", (mid,)).fetchone()["title"]
        db.log_activity(conn, review_id, "control",
                        f"Linked “{title}” to {row['subcategory_id'] or (row['title'] or row['kind'])[:60]}")
        db.touch(conn, review_id)
    return {"mitigation_id": mid, "review": get_review(review_id)}


@router.delete("/reviews/{review_id}/items/{item_id}/mitigations/{mid}")
def unlink_mitigation(review_id: int, item_id: int, mid: int):
    with db.tx() as conn:
        _item_row(conn, review_id, item_id)
        conn.execute("DELETE FROM item_mitigations WHERE item_id = ? AND mitigation_id = ?", (item_id, mid))
        db.touch(conn, review_id)
    return get_review(review_id)


# --------------------------------------------------------------------------- control register
@router.post("/reviews/{review_id}/mitigations", status_code=201)
def add_mitigation(review_id: int, body: MitCreate):
    with db.tx() as conn:
        _get_review(conn, review_id)
        data = body.model_dump()
        ids = data.pop("item_ids")
        if data.get("library_ref") and data["library_ref"] in mitigation_library():
            mid = mitigation_from_library(conn, review_id, data["library_ref"], data.get("source") or "library")
        else:
            mid = create_mitigation(conn, review_id, data)
        for iid in ids:
            _item_row(conn, review_id, iid)
            link(conn, iid, mid)
        db.log_activity(conn, review_id, "control", f"Added control “{body.title}”"
                        + (f" closing {len(ids)} item(s)" if ids else ""))
    return {"mitigation_id": mid, "review": get_review(review_id)}


@router.patch("/reviews/{review_id}/mitigations/{mid}")
def update_mitigation(review_id: int, mid: int, body: MitUpdate):
    updates = {k: v for k, v in body.model_dump(exclude_unset=True).items() if k in MIT_FIELDS and v is not None}
    if "status" in updates and updates["status"] not in MIT_STATUSES:
        raise HTTPException(422, f"status must be one of {list(MIT_STATUSES)}")
    with db.tx() as conn:
        row = _mit_row(conn, review_id, mid)
        if "nist" in updates:
            updates["nist"] = json.dumps(updates["nist"])
        if updates.get("state") == "existing" and row["status"] in ("proposed", "planned"):
            updates.setdefault("status", "implemented")
        if updates:
            conn.execute(f"UPDATE mitigations SET {', '.join(f'{k} = ?' for k in updates)}, updated_at = ? "
                         f"WHERE id = ?", [*updates.values(), db.now(), mid])
            db.touch(conn, review_id)
            if "status" in updates and updates["status"] != row["status"]:
                db.log_activity(conn, review_id, "control", f"“{row['title']}” → {MIT_STATUSES[updates['status']]}")
    return get_review(review_id)


@router.delete("/reviews/{review_id}/mitigations/{mid}")
def delete_mitigation(review_id: int, mid: int):
    with db.tx() as conn:
        row = _mit_row(conn, review_id, mid)
        conn.execute("DELETE FROM mitigations WHERE id = ?", (mid,))
        db.log_activity(conn, review_id, "control", f"Removed control “{row['title']}”")
        db.touch(conn, review_id)
    return get_review(review_id)


@router.post("/reviews/{review_id}/mitigations/{mid}/links")
def bulk_link(review_id: int, mid: int, body: BulkLink):
    """Apply one control to many line items - one control closing multiple questions/risks/recs."""
    with db.tx() as conn:
        row = _mit_row(conn, review_id, mid)
        current = {r[0] for r in conn.execute("SELECT item_id FROM item_mitigations WHERE mitigation_id = ?", (mid,))}
        wanted = set(body.item_ids)
        for iid in wanted - current:
            _item_row(conn, review_id, iid)
            link(conn, iid, mid)
        for iid in current - wanted:
            conn.execute("DELETE FROM item_mitigations WHERE item_id = ? AND mitigation_id = ?", (iid, mid))
        db.log_activity(conn, review_id, "control", f"“{row['title']}” now closes {len(wanted)} item(s)")
        db.touch(conn, review_id)
    return get_review(review_id)


@router.get("/mitigations/org")
def org_mitigations(q: str = "", exclude_review: int = 0, limit: int = 60):
    """Controls already recorded in other reviews (org-wide reuse) plus the library."""
    sql = """SELECT m.title, m.description, m.state, m.status, m.nist, m.library_ref, m.owner, r.id AS review_id,
                    r.title AS review_title, m.updated_at
             FROM mitigations m JOIN reviews r ON r.id = m.review_id WHERE m.review_id != ?"""
    args: list = [exclude_review]
    if q:
        sql += " AND (m.title LIKE ? OR m.description LIKE ?)"
        args += [f"%{q}%", f"%{q}%"]
    sql += " ORDER BY m.updated_at DESC"
    groups: dict[str, dict] = {}
    with db.tx() as conn:
        for r in conn.execute(sql, args):
            key = (r["library_ref"] or r["title"].strip().lower())
            g = groups.get(key)
            if not g:
                g = groups[key] = {"title": r["title"], "description": r["description"], "state": r["state"],
                                   "status": r["status"], "nist": json.loads(r["nist"] or "[]"),
                                   "library_ref": r["library_ref"], "owner": r["owner"], "reviews": []}
            if len(g["reviews"]) < 6:
                g["reviews"].append({"id": r["review_id"], "ref": f"SR-{r['review_id']:04d}",
                                     "title": r["review_title"]})
            g["count"] = g.get("count", 0) + 1
    org = sorted(groups.values(), key=lambda g: (-g["count"], g["title"]))[:limit]
    ql = q.lower()
    lib = [{"library_id": k, **{f: v[f] for f in ("title", "description", "nist")}}
           for k, v in mitigation_library().items()
           if not ql or ql in v["title"].lower() or ql in v["description"].lower()
           or any(ql in kw for kw in v["keywords"])]
    return {"org": org, "library": lib}


@router.get("/library/mitigations")
def library_mitigations():
    return list(mitigation_library().values())


@router.get("/library/risks")
def library_risks_list():
    return risk_library()


# --------------------------------------------------------------------------- AI writing
@router.post("/ai/write")
async def ai_write(body: WriteBody):
    review, item, _items, mits = _context(body.review_id, body.item_id)
    if body.mitigation_id:
        m = next((m for m in mits if m["id"] == body.mitigation_id), None)
        if m:
            item = {"kind": "control", "display_title": m["title"], "mitigation_ids": [m["id"]],
                    "label": "control", "answer": m["description"]}
    llm = _llm_or_none()
    return await write_text(review, item, body.field, body.text, body.mode, mits, llm)


# --------------------------------------------------------------------------- suggestions
@router.get("/reviews/{review_id}/items/{item_id}/suggestions")
async def suggestions_for_item(review_id: int, item_id: int, ai: bool = False):
    review, item, _items, mits = _context(review_id, item_id)
    if not ai:
        return deterministic_item_suggestions(review, item, mits, get_catalog())
    return await item_suggestions(review, item, mits, get_catalog(), _llm_or_none())


@router.get("/reviews/{review_id}/suggestions")
def suggestions_all(review_id: int):
    """Deterministic top suggestions for every item that still needs a control (drives inline hints)."""
    review, _item, items, mits = _context(review_id)
    cat = get_catalog()
    out = {}
    for it in items:
        needs = (it["is_risk"] or it["status"] in ("not_met", "partial")) and not it["mitigation_ids"]
        if not needs:
            continue
        _attach_code_context(review, it)
        s = deterministic_item_suggestions(review, it, mits, cat)
        top = [{"type": "existing", "mitigation_id": e["mitigation_id"], "title": e["title"], "reason": e["reason"],
                "shared": e["shared"]} for e in s["existing"][:2]]
        top += [{"type": "library", "library_id": l["library_id"], "title": l["title"], "reason": l["reason"]}
                for l in s["library"][:max(0, 3 - len(top))]]
        if top:
            out[it["id"]] = {"controls": top, "recommendation": s["recommendation"]}
    return out


@router.post("/reviews/{review_id}/auto-mitigate")
def auto_mitigate(review_id: int, body: AutoMitigateBody):
    """Link the best deterministic control (preferring reuse of the register) to items lacking one."""
    review, _item, items, mits = _context(review_id)
    cat = get_catalog()
    targets = [i for i in items if (not body.item_ids or i["id"] in body.item_ids) and not i["mitigation_ids"]
               and (i["is_risk"] or i["status"] in ("not_met", "partial") or body.item_ids)]
    linked = 0
    with db.tx() as conn:
        for it in targets:
            _attach_code_context(review, it)
            mits = load_mitigations(conn, review_id)  # refresh so newly-created controls are reused
            s = deterministic_item_suggestions(review, it, mits, cat)
            if s["existing"]:
                link(conn, it["id"], s["existing"][0]["mitigation_id"])
                linked += 1
            elif body.include_library and s["library"]:
                mid = mitigation_from_library(conn, review_id, s["library"][0]["library_id"], "heuristic")
                link(conn, it["id"], mid)
                linked += 1
        if linked:
            db.log_activity(conn, review_id, "control", f"Auto-linked suggested controls to {linked} item(s)")
            db.touch(conn, review_id)
    return {"linked": linked, "review": get_review(review_id)}


@router.post("/reviews/{review_id}/risks/suggest")
async def risks_suggest(review_id: int, body: RiskSuggestBody):
    review, _item, items, mits = _context(review_id)
    llm = _llm_or_none() if body.ai else None
    return await suggest_risks(review, items, mits, get_catalog(), llm)


@router.post("/reviews/{review_id}/risks/accept")
def risks_accept(review_id: int, body: RiskAcceptBody):
    lib = mitigation_library()
    created = []
    with db.tx() as conn:
        review = _get_review(conn, review_id)
        code = review.get("code_review") or {}
        have = {r[0] for r in conn.execute("SELECT library_ref FROM items WHERE review_id = ? AND library_ref != ''",
                                           (review_id,))}
        for r in body.risks:
            if r.library_ref and r.library_ref in have:
                continue
            lk = r.likelihood if r.likelihood in LIKELIHOOD else "possible"
            ik = r.impact if r.impact in IMPACT else "moderate"
            item_id = create_item(conn, review_id, {
                "kind": "risk", "title": r.title[:300], "risk": r.risk, "likelihood": lk, "impact": ik,
                "recommendation": r.recommendation, "is_recommendation": bool(r.recommendation),
                "rec_status": "proposed" if r.recommendation else "", "library_ref": r.library_ref,
                "rationale": r.rationale, "source": r.source if r.source in ("library", "ai", "code") else "library",
                "priority": "high" if IMPACT[ik] * LIKELIHOOD[lk] >= 12 else "medium"})
            for mref in r.mitigations:
                if mref in lib:
                    link(conn, item_id, mitigation_from_library(conn, review_id, mref, r.source))
            if r.library_ref.startswith("code:"):
                for f in code.get("findings", []):
                    if f"code:{f['id']}" == r.library_ref:
                        f["item_id"] = item_id
            created.append(item_id)
        if code:
            conn.execute("UPDATE reviews SET code_review = ? WHERE id = ?", (json.dumps(code), review_id))
        if created:
            db.log_activity(conn, review_id, "risk", f"Added {len(created)} suggested risk(s)")
    return {"created": created, "review": get_review(review_id)}
