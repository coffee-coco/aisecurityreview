"""Threat models page and linking: list / create threat models, link them to security reviews, and promote their
threats, mitigations and code findings into a review's risk and control registers."""
from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from . import db, threat_models
from .api import LIST_COLUMNS, _get_review, get_review, sync_profile
from .api_files import _docs
from .catalog import get_catalog
from .items import create_item, create_mitigation, link, load_mitigations, mitigation_from_library
from .library import mitigation_library
from .profile import CLASS_IMPACT, IMPACT, LIKELIHOOD, SEVERITY_TO_LI, effective_class, risk_rating, similarity
from .threat import KINDS, store

router = APIRouter(prefix="/api")

COUNT_KEYS = {"threat_model": "threats", "attack_tree": "nodes", "dfd": "nodes", "mitigations": "mitigations",
              "dread": "assessments", "test_cases": "test_cases"}
HINT_LIKELIHOOD = {"high": "likely", "medium": "possible", "low": "unlikely"}


class ThreatModelCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = ""
    tech_stack: str = ""
    exposure: Literal["internal", "partner", "public"] = "internal"
    uses_ai: bool = False
    system_types: list[str] = []


class LinkBody(BaseModel):
    threat_model_id: int


class PromoteThreatsBody(BaseModel):
    threat_ids: list[str] = []


class PromoteMitigationsBody(BaseModel):
    ids: list[str] = []


# --------------------------------------------------------------------------- helpers
def _get_tm(conn, tm_id: int) -> dict:
    tm = _get_review(conn, tm_id)
    if tm.get("kind") != "threat_model":
        raise HTTPException(404, "Threat model not found")
    return tm


def _get_sr(conn, review_id: int) -> dict:
    review = _get_review(conn, review_id)
    if review.get("kind") == "threat_model":
        raise HTTPException(404, "Review not found")
    return review


def _summary(conn, tm: dict, arts: dict | None = None) -> dict:
    arts = arts if arts is not None else store.get_artifacts(conn, tm["id"])
    code = tm.get("code_review") or {}
    sources = [{"type": d["meta"].get("type") or "files", "name": d["filename"], "url": d["meta"].get("url"),
                "ref": d["meta"].get("ref"), "commit": d["meta"].get("commit"), "files": d["meta"].get("files")}
               for d in _docs(conn, tm["id"], ("code",))]
    reviews = [{"id": r["id"], "ref": f"SR-{r['id']:04d}", "title": r["title"], "status": r["status"]}
               for r in conn.execute("SELECT r.id, r.title, r.status FROM review_threat_models l JOIN reviews r "
                                     "ON r.id = l.review_id WHERE l.threat_model_id = ? ORDER BY r.id", (tm["id"],))]
    return {
        "id": tm["id"], "ref": tm["ref"], "title": tm["title"], "description": tm["description"],
        "updated_at": tm["updated_at"], "sources": sources, "documents": len(_docs(conn, tm["id"], ("document", "image"))),
        "counts": {k: len(((arts.get(k) or {}).get("data") or {}).get(COUNT_KEYS[k]) or []) for k in KINDS},
        "updated": {k: (arts.get(k) or {}).get("updated_at") for k in KINDS},
        "code_review": {"ran_at": code.get("ran_at"), "findings": len(code.get("findings") or []),
                        "summary": code.get("summary") or "", "files": (code.get("inventory") or {}).get("files"),
                        "checkov": {k: (code.get("checkov") or {}).get(k) for k in ("ran", "passed", "failed")}},
        "linked_reviews": reviews,
    }


def _select(requested: list[str], valid: list[str]) -> list[str]:
    """Requested ids (all when empty); unknown ids are a 404."""
    if not requested:
        return valid
    want = list(dict.fromkeys(str(x).strip().upper() for x in requested))
    unknown = [x for x in want if x not in valid]
    if unknown:
        raise HTTPException(404, f"Unknown id(s): {', '.join(unknown)}")
    return want


def _band(x: float, labels: list[str]) -> str:
    return labels[min(int(x // 2), len(labels) - 1)]


def _likelihood_impact(threat: dict, dread: dict | None, review: dict) -> tuple[str, str]:
    if dread:
        lk = _band((dread["reproducibility"] + dread["exploitability"] + dread["discoverability"]) / 3,
                   list(LIKELIHOOD))
        return lk, _band((dread["damage"] + dread["affected_users"]) / 2, list(IMPACT))
    return HINT_LIKELIHOOD.get(threat.get("likelihood_hint"), "possible"), CLASS_IMPACT[effective_class(review)]


def _valid(conn, review_id: int) -> tuple[set[int], set[int]]:
    items = {r[0] for r in conn.execute("SELECT id FROM items WHERE review_id = ?", (review_id,))}
    mits = {r[0] for r in conn.execute("SELECT id FROM mitigations WHERE review_id = ?", (review_id,))}
    return items, mits


def _overlaid(conn, review_id: int, tm: dict, links: dict) -> tuple[dict, list[dict]]:
    """The threat model's artifacts and code findings with this review's promotion state applied."""
    items, mits = _valid(conn, review_id)
    arts = store.get_artifacts(conn, tm["id"])
    tdata = (arts.get("threat_model") or {}).get("data") or {}
    mdata = (arts.get("mitigations") or {}).get("data") or {}
    threat_models.overlay(tdata.get("threats") or [], links["threats"], "item_id", items)
    threat_models.overlay(mdata.get("mitigations") or [], links["mitigations"], "mitigation_id", mits)
    findings = [dict(f) for f in (tm.get("code_review") or {}).get("findings") or []]
    for f in findings:
        iid = links["findings"].get(str(f["id"]))
        f["item_id"] = iid if iid in items else None
    return arts, findings


def _linked_payload(review_id: int) -> dict:
    with db.tx() as conn:
        _get_sr(conn, review_id)
        linked, ids = [], threat_models.linked_ids(conn, review_id)
        for tm_id in ids:
            tm = _get_review(conn, tm_id)
            arts, findings = _overlaid(conn, review_id, tm, threat_models.get_links(conn, review_id, tm_id))
            linked.append({**_summary(conn, tm, arts), "artifacts": arts, "findings": findings})
        available = [_summary(conn, db.review_row(r)) for r in conn.execute(
            "SELECT * FROM reviews WHERE kind = 'threat_model' ORDER BY updated_at DESC")
            if r["id"] not in ids]
    return {"linked": linked, "available": available}


# --------------------------------------------------------------------------- threat models
@router.get("/threat-models")
def list_threat_models():
    with db.tx() as conn:
        return [_summary(conn, db.review_row(r)) for r in conn.execute(
            "SELECT * FROM reviews WHERE kind = 'threat_model' ORDER BY updated_at DESC")]


@router.post("/threat-models", status_code=201)
def create_threat_model(body: ThreatModelCreate):
    data = sync_profile(body.model_dump())
    ts = db.now()
    cols = list(data.keys()) + ["kind", "created_at", "updated_at"]
    vals = [json.dumps(v) if k in LIST_COLUMNS else int(v) if isinstance(v, bool) else v
            for k, v in data.items()] + ["threat_model", ts, ts]
    with db.tx() as conn:
        tm_id = conn.execute(f"INSERT INTO reviews ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                             vals).lastrowid
        db.log_activity(conn, tm_id, "created", "Threat model created")
    return get_review(tm_id)


# --------------------------------------------------------------------------- linking
@router.get("/reviews/{review_id}/threat-models")
def linked_threat_models(review_id: int):
    return _linked_payload(review_id)


@router.post("/reviews/{review_id}/threat-models", status_code=201)
def link_threat_model(review_id: int, body: LinkBody):
    cat = get_catalog()
    with db.tx() as conn:
        review = _get_sr(conn, review_id)
        tm = _get_tm(conn, body.threat_model_id)
        if threat_models.get_links(conn, review_id, tm["id"]) is not None:
            raise HTTPException(409, f"{tm['ref']} is already linked to this review")
        conn.execute("INSERT INTO review_threat_models (review_id, threat_model_id, links, linked_at) "
                     "VALUES (?, ?, '{}', ?)", (review_id, tm["id"], db.now()))
        threat_models.apply_checkov(conn, review_id, tm.get("code_review") or {}, cat.checks_by_id)
        db.log_activity(conn, review_id, "threat", f"Linked threat model {tm['ref']}: {tm['title']}")
        db.log_activity(conn, tm["id"], "threat", f"Linked to review {review['ref']}: {review['title']}")
        db.touch(conn, review_id)
    return {**_linked_payload(review_id), "review": get_review(review_id)}


@router.delete("/reviews/{review_id}/threat-models/{tm_id}")
def unlink_threat_model(review_id: int, tm_id: int):
    with db.tx() as conn:
        review = _get_sr(conn, review_id)
        tm = _get_tm(conn, tm_id)
        conn.execute("DELETE FROM review_threat_models WHERE review_id = ? AND threat_model_id = ?",
                     (review_id, tm_id))
        db.log_activity(conn, review_id, "threat", f"Unlinked threat model {tm['ref']} (promoted risks and "
                        "controls stay)")
        db.log_activity(conn, tm_id, "threat", f"Unlinked from review {review['ref']}")
        db.touch(conn, review_id)
    return {**_linked_payload(review_id), "review": get_review(review_id)}


def _link_ctx(conn, review_id: int, tm_id: int) -> tuple[dict, dict, dict]:
    review = _get_sr(conn, review_id)
    tm = _get_tm(conn, tm_id)
    links = threat_models.get_links(conn, review_id, tm_id)
    if links is None:
        raise HTTPException(404, f"{tm['ref']} is not linked to this review")
    return review, tm, links


def _promote_threats(conn, review: dict, tm: dict, arts: dict, ids: list[str], links: dict) -> list[int]:
    """Create a risk item in the review per threat (skipping ones already promoted)."""
    review_id = review["id"]
    threats = {t["id"]: t for t in ((arts.get("threat_model") or {}).get("data") or {}).get("threats") or []}
    dread = {a["threat_id"]: a for a in ((arts.get("dread") or {}).get("data") or {}).get("assessments") or []}
    mits = ((arts.get("mitigations") or {}).get("data") or {}).get("mitigations") or []
    created = []
    for tid in ids:
        t = threats.get(tid)
        if not t or t.get("item_id"):
            continue
        d = dread.get(tid)
        lk, ik = _likelihood_impact(t, d, review)
        rating = risk_rating(lk, ik)
        refs = [t.get("owasp_top10"), t.get("owasp_llm"), t.get("owasp_asi"), *(t.get("mitre_attack") or []),
                *(t.get("mitre_atlas") or [])]
        notes = [f"Component: {t['component']}" if t.get("component") else "",
                 f"Framework mappings: {', '.join(r for r in refs if r)}" if any(refs) else "",
                 f"Code: {', '.join(t['evidence'])}" if t.get("evidence") else ""]
        rationale = (f"Threat model {tm['ref']} {tid} ({t['category']})"
                     + (f"; CSF {', '.join(t['csf'])}" if t.get("csf") else "")
                     + (f"; DREAD {d['score']} ({d['rating']})" if d else ""))
        item_id = create_item(conn, review_id, {
            "kind": "risk", "title": t["title"][:300],
            "risk": t["scenario"] + (f"\n\nImpact: {t['impact']}" if t.get("impact") else ""),
            "impact_description": t.get("impact") or "", "likelihood": lk, "impact": ik,
            "notes": "\n".join(n for n in notes if n), "library_ref": f"threat:{tm['ref']}:{tid}", "source": "threat",
            "rationale": rationale,
            "priority": "high" if rating in ("critical", "high") else "low" if rating == "low" else "medium"})
        for m in mits:
            if tid in m.get("threat_ids", []) and m.get("mitigation_id"):
                link(conn, item_id, m["mitigation_id"])
        t["item_id"] = item_id
        links["threats"][tid] = {"item_id": item_id, "title": t["title"]}
        created.append(item_id)
    if created:
        db.log_activity(conn, review_id, "risk", f"Promoted {len(created)} threat(s) from {tm['ref']} to the risk "
                        "register")
    return created


@router.post("/reviews/{review_id}/threat-models/{tm_id}/promote")
def promote_threats(review_id: int, tm_id: int, body: PromoteThreatsBody):
    with db.tx() as conn:
        review, tm, links = _link_ctx(conn, review_id, tm_id)
        arts, _ = _overlaid(conn, review_id, tm, links)
        threats = ((arts["threat_model"] or {}).get("data") or {}).get("threats") or []
        if not threats:
            raise HTTPException(400, f"{tm['ref']} has no threats yet - generate them on the Threat models page.")
        created = _promote_threats(conn, review, tm, arts, _select(body.threat_ids, [t["id"] for t in threats]), links)
        threat_models.save_links(conn, review_id, tm_id, links)
        db.touch(conn, review_id)
    return {"created": created, **_linked_payload(review_id), "review": get_review(review_id)}


@router.post("/reviews/{review_id}/threat-models/{tm_id}/mitigations/promote")
def promote_mitigations(review_id: int, tm_id: int, body: PromoteMitigationsBody):
    """Add mitigations to the review's control register, linked to the risks of the threats they address."""
    lib = mitigation_library()
    with db.tx() as conn:
        review, tm, links = _link_ctx(conn, review_id, tm_id)
        arts, _ = _overlaid(conn, review_id, tm, links)
        mits = ((arts["mitigations"] or {}).get("data") or {}).get("mitigations") or []
        threats = ((arts["threat_model"] or {}).get("data") or {}).get("threats") or []
        if not mits or not threats:
            raise HTTPException(400, f"{tm['ref']} has no mitigations yet - generate them on the Threat models page.")
        ids = _select(body.ids, [m["id"] for m in mits])
        selected = [m for m in mits if m["id"] in ids]
        needed = {tid for m in selected for tid in m["threat_ids"]}
        _promote_threats(conn, review, tm, arts, [t["id"] for t in threats if t["id"] in needed], links)
        item_of = {t["id"]: t.get("item_id") for t in threats}
        register = load_mitigations(conn, review_id)
        created = []
        for m in selected:
            mid = m.get("mitigation_id")
            if mid is None:
                reuse = next((r for r in register if (m.get("library_ref") and r["library_ref"] == m["library_ref"])
                              or similarity(r["title"], m["title"]) >= 0.6), None)
                if reuse:
                    mid = reuse["id"]
                else:
                    ref = m.get("library_ref") or ""
                    mid = create_mitigation(conn, review_id, {
                        "title": m["title"], "description": m["description"], "state": "new", "status": "proposed",
                        "nist": m["nist"] or lib.get(ref, {}).get("nist", []), "library_ref": ref, "source": "threat"})
                    register.append({"id": mid, "title": m["title"], "library_ref": ref})
                    created.append(mid)
            for tid in m["threat_ids"]:
                if item_of.get(tid):
                    link(conn, item_of[tid], mid)
            links["mitigations"][str(m["id"])] = {"mitigation_id": mid, "title": m["title"]}
        threat_models.save_links(conn, review_id, tm_id, links)
        db.log_activity(conn, review_id, "control", f"Added {len(selected)} mitigation(s) from {tm['ref']} to the "
                        f"control register ({len(created)} new)")
        db.touch(conn, review_id)
    return {"created": created, **_linked_payload(review_id), "review": get_review(review_id)}


@router.post("/reviews/{review_id}/threat-models/{tm_id}/findings/{fid:path}/promote")
def promote_finding(review_id: int, tm_id: int, fid: str):
    lib = mitigation_library()
    with db.tx() as conn:
        _, tm, links = _link_ctx(conn, review_id, tm_id)
        _, findings = _overlaid(conn, review_id, tm, links)
        f = next((x for x in findings if x["id"] == fid), None)
        if not f:
            raise HTTPException(404, "Finding not found")
        if f.get("item_id"):
            raise HTTPException(409, "Finding already added as a risk")
        lk, ik = SEVERITY_TO_LI.get(f["severity"], ("possible", "moderate"))
        ev = "\n".join(f"- {e['file']}:{e.get('line', '')} {e.get('snippet', '')}".rstrip()
                       for e in (f.get("evidence") or [])[:8])
        desc = f.get("description") or f["title"]
        item_id = create_item(conn, review_id, {
            "kind": "risk", "title": f["title"][:300],
            "risk": f"There is a risk that {desc[0].lower() + desc[1:]}" if desc else f["title"],
            "likelihood": lk, "impact": ik, "recommendation": f.get("recommendation", ""),
            "is_recommendation": bool(f.get("recommendation")), "rec_status": "proposed" if f.get("recommendation") else "",
            "notes": ("Evidence:\n" + ev) if ev else "", "library_ref": f"code:{tm['ref']}:{fid}", "source": "code",
            "rationale": f"Code review finding in {tm['ref']} ({f.get('source')})",
            "priority": "high" if f["severity"] in ("critical", "high") else "medium"})
        for mref in f.get("mitigations", []):
            if mref in lib:
                link(conn, item_id, mitigation_from_library(conn, review_id, mref, "code"))
        links["findings"][fid] = item_id
        threat_models.save_links(conn, review_id, tm_id, links)
        db.log_activity(conn, review_id, "risk", f"Code finding from {tm['ref']} promoted to risk: {f['title'][:80]} "
                        f"({risk_rating(lk, ik)})")
    return {"item_id": item_id, **_linked_payload(review_id), "review": get_review(review_id)}
