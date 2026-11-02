"""REST API for the requirement <-> Checkov check mappings page (and on-the-fly edits in a review)."""
from __future__ import annotations

from typing import Literal, Optional

import yaml
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from . import db, mappings
from .catalog import get_catalog

router = APIRouter(prefix="/api")


class LinkUpdate(BaseModel):
    action: Literal["include", "exclude"]
    note: str = ""
    review_id: Optional[int] = None


class LinkImport(BaseModel):
    content: str
    replace: bool = False


# --------------------------------------------------------------------------- helpers
def _requirement(rid: str) -> dict:
    cat = get_catalog()
    if rid not in cat.subcategories:
        raise HTTPException(404, "Unknown requirement")
    return cat.subcategories[rid]


def _check_review(conn, review_id: int | None) -> None:
    if review_id is not None and not conn.execute("SELECT 1 FROM reviews WHERE id = ?", (review_id,)).fetchone():
        raise HTTPException(404, "Review not found")


def _framework(s: dict) -> tuple[str, str]:
    return s.get("framework_id") or "csf", s.get("framework_short") or "CSF"


# --------------------------------------------------------------------------- requirements
@router.get("/mappings/requirements")
def list_requirements(framework: str = "", function: str = "", q: str = ""):
    cat = get_catalog()
    with db.tx() as conn:
        user = mappings.global_by_requirement(conn)
    ql = q.lower().strip()
    rows, frameworks, functions = [], {}, {}
    for rid, s in sorted(cat.subcategories.items(), key=lambda kv: cat.order.get(kv[0], 0)):
        fid, fshort = _framework(s)
        frameworks.setdefault(fid, {"id": fid, "short": fshort, "name": s.get("framework_name") or fshort, "count": 0})
        frameworks[fid]["count"] += 1
        functions.setdefault(s["function_id"], {"id": s["function_id"], "title": s["function_title"], "framework_id": fid})
        if (framework and fid != framework) or (function and s["function_id"] != function):
            continue
        if ql and ql not in f"{rid} {s.get('title', '')} {s['text']} {s['category_title']}".lower():
            continue
        auto = set(cat.auto_links(rid))
        g = user.get(rid, {"include": set(), "exclude": set()})
        policy = cat.link_policy(rid)
        rows.append({
            "id": rid, "title": s.get("title", rid), "text": s["text"], "framework_id": fid, "framework_short": fshort,
            "function_id": s["function_id"], "function_title": s["function_title"],
            "category_id": s["category_id"], "category_title": s["category_title"],
            "policy": policy["policy"], "why": policy["why"], "auto": len(auto),
            "included": len(g["include"]), "excluded": len(g["exclude"] & auto),
            "total": len((auto - g["exclude"]) | g["include"]),
        })
    return {"frameworks": list(frameworks.values()), "functions": list(functions.values()), "requirements": rows}


@router.get("/mappings/requirements/{rid}")
def requirement_detail(rid: str, review_id: Optional[int] = None, provider: str = "", q: str = ""):
    cat = get_catalog()
    s = _requirement(rid)
    with db.tx() as conn:
        _check_review(conn, review_id)
        rows = mappings.overrides(conn, rid, review_id)
    providers = [p for p in provider.split(",") if p]
    checks = cat.subcategory_checks(rid, providers, None, q, rows, keep_excluded=True)
    fid, fshort = _framework(s)
    counts = {f"{scope}_{action}": sum(1 for r in rows if r["action"] == action
                                        and (r["review_id"] is None) == (scope == "global"))
              for scope in ("global", "review") for action in ("include", "exclude")}
    return {"requirement": {**cat.subcategory_brief(rid), "title": s.get("title", rid), "framework_id": fid,
                            "framework_short": fshort},
            **cat.link_policy(rid), "auto": len(cat.auto_links(rid)), "counts": counts, "checks": checks}


@router.put("/mappings/requirements/{rid}/checks/{check_id}")
def put_link(rid: str, check_id: str, body: LinkUpdate):
    _requirement(rid)
    if check_id not in get_catalog().checks_by_id:
        raise HTTPException(404, "Unknown Checkov check")
    with db.tx() as conn:
        _check_review(conn, body.review_id)
        row = mappings.set_link(conn, rid, check_id, body.action, body.note, body.review_id)
        if body.review_id is not None:
            db.log_activity(conn, body.review_id, "check",
                            f"{check_id} {'added to' if body.action == 'include' else 'removed from'} {rid}")
    return row


@router.delete("/mappings/requirements/{rid}/checks/{check_id}", status_code=204)
def delete_link(rid: str, check_id: str, review_id: Optional[int] = None):
    with db.tx() as conn:
        if not mappings.delete_link(conn, rid, check_id, review_id):
            raise HTTPException(404, "No reviewer link for this check")


# --------------------------------------------------------------------------- check search
@router.get("/mappings/checks")
def search_checks(q: str = "", provider: str = "", resource: str = "", control: str = "", offset: int = 0,
                  limit: int = 50, requirement_id: str = "", review_id: Optional[int] = None):
    cat = get_catalog()
    hits = cat.find_checks(q, provider, control, resource)
    offset, limit = max(offset, 0), min(max(limit, 1), 500)
    linked: set[str] = set()
    if requirement_id in cat.subcategories:
        with db.tx() as conn:
            rows = mappings.overrides(conn, requirement_id, review_id)
        linked = {c["id"] for c in cat.subcategory_checks(requirement_id, overrides=rows)}
    return {"total": len(hits), "offset": offset, "limit": limit,
            "checks": [{**cat.public_check(c), "linked": c["id"] in linked} for c in hits[offset:offset + limit]]}


# --------------------------------------------------------------------------- export / import
@router.get("/mappings/export", response_class=PlainTextResponse)
def export_links(include_reviews: bool = False):
    with db.tx() as conn:
        rows = mappings.all_links(conn, include_reviews=include_reviews)
    links = [{"requirement": r["requirement_id"], "check": r["check_id"], "action": r["action"], "note": r["note"],
              **({"review_id": r["review_id"]} if r["review_id"] is not None else {})} for r in rows]
    text = "# Requirement <-> Checkov check links (reviewer overrides on top of catalog/csf_check_links.yaml)\n" + \
        yaml.safe_dump({"version": 1, "exported_at": db.now(), "links": links}, sort_keys=False, allow_unicode=True)
    return PlainTextResponse(text, headers={"Content-Disposition": 'attachment; filename="check-links.yaml"'})


@router.post("/mappings/import")
def import_links(body: LinkImport):
    cat = get_catalog()
    try:
        doc = yaml.safe_load(body.content) or {}
    except yaml.YAMLError as e:
        raise HTTPException(400, f"Not valid YAML: {e}")
    items = doc.get("links") if isinstance(doc, dict) else doc
    if not isinstance(items, list):
        raise HTTPException(400, "Expected a `links:` list")
    imported, skipped = 0, []
    with db.tx() as conn:
        if body.replace:
            conn.execute("DELETE FROM check_links WHERE review_id IS NULL")
        reviews = {r[0] for r in conn.execute("SELECT id FROM reviews")}
        for i, x in enumerate(items):
            x = x if isinstance(x, dict) else {}
            rid, cid, action = str(x.get("requirement", "")), str(x.get("check", "")), x.get("action")
            review_id = x.get("review_id")
            if review_id is not None:
                review_id = int(review_id) if str(review_id).isdigit() else -1
            reason = ("unknown requirement" if rid not in cat.subcategories else
                      "unknown check" if cid not in cat.checks_by_id else
                      "action must be include or exclude" if action not in ("include", "exclude") else
                      "unknown review" if review_id is not None and review_id not in reviews else "")
            if reason:
                skipped.append({"index": i, "requirement": rid, "check": cid, "reason": reason})
                continue
            mappings.set_link(conn, rid, cid, action, str(x.get("note") or ""), review_id)
            imported += 1
    return {"imported": imported, "skipped": skipped}
