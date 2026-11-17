"""Devil's advocate and AI review of individual entries (risk, control, question, finding, threat-model element,
design summary, description).

- Devil's advocate: the reviewer argues an entry is wrong or not aligned with the application; the AI adjudicates the
  challenge against the application's evidence and may propose corrected text or removal.
- AI review: a constructive check that an entry is accurate and specific to the application, with improved text.

One entry is handled synchronously; a selection of entries runs as a background job. The reviewer then applies the
AI text, overrides it or removes the entry. Every outcome is logged on the record that owns the entry.
"""
from __future__ import annotations

import asyncio
import copy
import json
import logging
from dataclasses import dataclass, field
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from . import db, jobs
from .ai.providers import LLM, ProviderError, build_llm
from .api import _get_review
from .api_items import _unpromote
from .catalog import get_catalog
from .config import AI_BATCH_CONCURRENCY
from .items import load_items, load_mitigations
from .profile import profile_summary
from .threat import DOWNSTREAM, store
from .threat.context import detect_app_type
from .threat.normalize import normalize_artifact

router = APIRouter(prefix="/api")
log = logging.getLogger("sentinel.devil")

TargetType = Literal["item", "mitigation", "finding", "threat", "design", "review"]
FIELD_LABELS = {
    "title": "Title", "answer": "Team response", "notes": "Reviewer notes", "rationale": "Why it's in scope",
    "risk": "Risk statement", "impact_description": "Impact", "recommendation": "Recommendation",
    "description": "Description", "scenario": "Scenario", "impact": "Impact", "gherkin": "Test scenario (Gherkin)",
    "label": "Label", "summary": "Summary",
}
SINGLE_LINE = {"title", "label"}
# threat-model artifact kind -> (list key, id key, editable text fields, label)
THREAT_SPEC = {
    "threat_model": ("threats", "id", ("title", "scenario", "impact"), "Threat"),
    "mitigations": ("mitigations", "id", ("title", "description"), "Threat mitigation"),
    "test_cases": ("test_cases", "id", ("title", "gherkin"), "Security test case"),
    "dread": ("assessments", "threat_id", ("rationale",), "DREAD assessment"),
    "attack_tree": ("nodes", "id", ("label",), "Attack tree node"),
    "dfd": ("nodes", "id", ("label",), "Data flow diagram element"),
}
Mode = Literal["devil", "review"]
VERDICTS = {"devil": ("upheld", "partly_upheld", "rejected", "inconclusive"),
            "review": ("aligned", "needs_improvement", "not_applicable", "inconclusive")}
ACTIONS = ("keep", "revise", "remove")
MODE_LABEL = {"devil": "Devil's advocate", "review": "AI review"}
DEFAULT_CHALLENGE = "This entry is not accurate or not aligned with this application - justify it or correct it."
MAX_BATCH = 300

DEVIL_SYSTEM = """You are an impartial principal security architect adjudicating a devil's-advocate challenge in a
security design review. A reviewer has challenged ONE entry (a risk, mitigating control, question, code finding,
threat-model element, design summary or description), arguing it is wrong, exaggerated, unsupported or not aligned
with this application.

Test the challenge against the evidence in "application" - do not agree by default and do not defend the entry by
default.
- Uphold the challenge when the application context does not support the entry or contradicts it.
- Reject it when the context does support the entry, and cite the specific evidence (description, technologies,
  profile, design, code findings, linked threat models).
- If the entry is partly right, correct only what is wrong so it fits this application and keep what is supported.
- Never invent technologies, components, data or facts that are not in the context. If the context is too thin to
  decide, say so (verdict "inconclusive"), recommend "keep" and state what evidence would settle it.
- Recommend "remove" only when the entry has no basis for this application at all and entry.can_remove is true.

Return JSON only:
{"verdict": "upheld" | "partly_upheld" | "rejected" | "inconclusive",
 "recommendation": "keep" | "revise" | "remove",
 "reasoning": "2-5 sentences addressed to the reviewer",
 "evidence": ["short facts or quotes from the context that decided it"],
 "fields": {"<field name>": "complete replacement text"}}
"fields" may only use names from entry.editable_fields and only when recommendation is "revise"."""

REVIEW_SYSTEM = """You are a principal security architect doing a quality review of ONE entry in a security design
review (a risk, mitigating control, question, code finding, threat-model element, design summary or description).
Check that it is accurate, specific to this application, clearly written and actionable, using only the evidence in
"application". If the reviewer gave "instructions", follow them.
- Accurate and specific: say so (verdict "aligned", recommendation "keep").
- Can be improved: rewrite only the fields that need it, naming the application's actual components, data and
  technologies from the context (verdict "needs_improvement", recommendation "revise").
- Does not apply to this application at all: explain why (verdict "not_applicable", recommendation "remove" when
  entry.can_remove is true, otherwise "revise").
- Never invent technologies, components, data or facts that are not in the context; if the context is too thin,
  use verdict "inconclusive" and recommendation "keep".

Return JSON only:
{"verdict": "aligned" | "needs_improvement" | "not_applicable" | "inconclusive",
 "recommendation": "keep" | "revise" | "remove",
 "reasoning": "2-4 sentences addressed to the reviewer",
 "evidence": ["short facts or quotes from the context that support the verdict"],
 "fields": {"<field name>": "complete replacement text"}}
"fields" may only use names from entry.editable_fields and only when recommendation is "revise"."""
SYSTEMS = {"devil": DEVIL_SYSTEM, "review": REVIEW_SYSTEM}


# --------------------------------------------------------------------------- models
class Target(BaseModel):
    type: TargetType
    ref: str = Field("", max_length=200)
    kind: str = Field("", max_length=40)
    owner: int | None = None  # record that owns the entry (batch only; single-entry routes use the path id)


class ChallengeBody(BaseModel):
    target: Target
    question: str = Field("", max_length=2000)
    mode: Mode = "devil"


class BatchBody(BaseModel):
    targets: list[Target] = Field(min_length=1, max_length=MAX_BATCH)
    question: str = Field("", max_length=2000)
    mode: Mode = "devil"


class ApplyBody(BaseModel):
    target: Target
    fields: dict[str, str]
    question: str = Field("", max_length=2000)
    source: Literal["ai", "override"] = "override"
    verdict: str = Field("", max_length=40)
    mode: Mode = "devil"


class RemoveBody(BaseModel):
    target: Target
    question: str = Field("", max_length=2000)
    verdict: str = Field("", max_length=40)
    mode: Mode = "devil"


@dataclass
class Entry:
    label: str
    type_label: str
    fields: dict[str, str]
    can_remove: bool = True
    related: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- adapters
def _item(conn, owner: int, ref: str) -> dict:
    item = next((i for i in load_items(conn, owner, get_catalog()) if str(i["id"]) == ref), None)
    if not item:
        raise HTTPException(404, "Line item not found")
    return item


def _item_fields(i: dict) -> tuple[str, ...]:
    if i["kind"] == "risk" or i["is_risk"]:
        base, extra = ("title", "risk"), ("impact_description", "recommendation", "notes")
    elif i["kind"] == "recommendation" or i["is_recommendation"]:
        base, extra = ("title", "recommendation"), ("notes",)
    elif i["subcategory_id"]:
        base, extra = ("rationale",), ("answer", "notes")
    else:
        base, extra = ("title",), ("answer", "notes", "rationale")
    return base + tuple(f for f in extra if (i.get(f) or "").strip())


def _threat_entry(conn, owner: int, kind: str, ref: str) -> tuple[dict, dict, dict]:
    if kind not in THREAT_SPEC:
        raise HTTPException(404, "Unknown threat-model artifact")
    arts = store.get_artifacts(conn, owner)
    data = copy.deepcopy((arts.get(kind) or {}).get("data") or {})
    key, idk, _, _ = THREAT_SPEC[kind]
    entry = next((e for e in data.get(key) or [] if str(e.get(idk)) == ref), None)
    if entry is None:
        raise HTTPException(404, "Threat-model entry not found")
    return arts, data, entry


def _threat_titles(arts: dict) -> dict[str, str]:
    return {str(t["id"]): t.get("title", "") for t in ((arts.get("threat_model") or {}).get("data") or {}).get("threats") or []}


def _finding(review_row: dict, ref: str) -> tuple[dict, dict]:
    code = review_row.get("code_review") or {}
    f = next((x for x in code.get("findings") or [] if str(x.get("id")) == ref), None)
    if f is None:
        raise HTTPException(404, "Finding not found")
    return code, f


def _own_row(conn, owner: int) -> dict:
    """The owner's stored row (without linked threat-model data merged in)."""
    _get_review(conn, owner)
    return db.review_row(conn.execute("SELECT * FROM reviews WHERE id = %s", (owner,)).fetchone())


def load_entry(conn, owner: int, t: Target) -> Entry:
    if t.type == "item":
        i = _item(conn, owner, t.ref)
        mits = {m["id"]: m["title"] for m in load_mitigations(conn, owner)}
        related = [f"Linked controls: {', '.join(mits[m] for m in i['mitigation_ids'] if m in mits) or 'none'}"]
        if i.get("subcategory"):
            related.insert(0, f"NIST CSF {i['subcategory_id']}: {i['subcategory']['text']}")
        if i["is_risk"]:
            related.append(f"Rated {i['likelihood'] or '?'} likelihood x {i['impact'] or '?'} impact")
        kind = "Risk" if i["is_risk"] else i["kind"].capitalize()
        return Entry(f"{i['label']} {i['display_title']}".strip(), kind, {f: i.get(f) or "" for f in _item_fields(i)},
                     related=related)
    if t.type == "mitigation":
        m = next((m for m in load_mitigations(conn, owner) if str(m["id"]) == t.ref), None)
        if not m:
            raise HTTPException(404, "Mitigating control not found")
        items = {i["id"]: f"{i['label']} {i['display_title']}" for i in load_items(conn, owner, get_catalog())}
        related = [f"Closes: {'; '.join(items[x] for x in m['item_ids'] if x in items) or 'nothing yet'}",
                   f"NIST SP 800-53: {', '.join(m['nist']) or 'none'}", f"State: {m['state']}, status: {m['status']}"]
        return Entry(m["title"], "Mitigating control", {"title": m["title"], "description": m["description"]},
                     related=related)
    if t.type == "finding":
        _, f = _finding(_own_row(conn, owner), t.ref)
        files = sorted({e.get("file", "") for e in f.get("evidence") or [] if e.get("file")})
        related = [f"Severity {f.get('severity')}, category {f.get('category')}, source {f.get('source')}",
                   f"Evidence files: {', '.join(files[:10]) or 'none'}"]
        fields = {k: f.get(k) or "" for k in ("title", "description", "recommendation")}
        return Entry(f["title"], "Code finding", fields, related=related)
    if t.type == "threat":
        arts, _, e = _threat_entry(conn, owner, t.kind, t.ref)
        _, idk, names, type_label = THREAT_SPEC[t.kind]
        titles = _threat_titles(arts)
        refs = [str(x) for x in (e.get("threat_ids") or ([e["threat_id"]] if e.get("threat_id") else []))]
        related = [f"Addresses threats: {'; '.join(f'{r} {titles.get(r, '')}' for r in refs)}"] if refs else []
        if t.kind == "threat_model":
            related.append(f"Category {e.get('category')}, component {e.get('component') or 'unspecified'}")
        if t.kind == "dread":
            related.append("Scores: " + ", ".join(f"{k} {e.get(k)}" for k in
                                                 ("damage", "reproducibility", "exploitability", "affected_users",
                                                  "discoverability")))
        name = e.get("title") or e.get("label") or titles.get(str(e.get("threat_id")), "")
        return Entry(f"{e.get(idk)} {name}".strip(), type_label, {k: str(e.get(k) or "") for k in names},
                     related=related)
    if t.type == "design":
        d = _own_row(conn, owner).get("design") or {}
        if not d.get("analyzed_at"):
            raise HTTPException(404, "No design understanding yet")
        return Entry("Design understanding", "Design summary", {"summary": d.get("summary") or ""},
                     related=[f"Notable concerns: {'; '.join(d.get('notable_concerns') or []) or 'none'}"])
    r = _own_row(conn, owner)
    return Entry(f"{r['ref']} {r['title']}", "Threat model" if r["kind"] == "threat_model" else "Security review",
                 {"title": r["title"], "description": r["description"]}, can_remove=False)


def save_entry(conn, owner: int, t: Target, fields: dict[str, str]) -> None:
    ts = db.now()
    if t.type == "item":
        _item(conn, owner, t.ref)
        conn.execute(f"UPDATE items SET {', '.join(f'{k} = %s' for k in fields)}, updated_at = %s WHERE id = %s",
                     [*fields.values(), ts, int(t.ref)])
    elif t.type == "mitigation":
        conn.execute(f"UPDATE mitigations SET {', '.join(f'{k} = %s' for k in fields)}, updated_at = %s "
                     "WHERE id = %s AND review_id = %s", [*fields.values(), ts, int(t.ref), owner])
    elif t.type == "finding":
        code, f = _finding(_own_row(conn, owner), t.ref)
        f.update(fields)
        conn.execute("UPDATE reviews SET code_review = %s WHERE id = %s", (json.dumps(code), owner))
    elif t.type == "threat":
        arts, data, e = _threat_entry(conn, owner, t.kind, t.ref)
        e.update(fields)
        _store_threat(conn, owner, t.kind, arts, data)
    elif t.type == "design":
        d = _own_row(conn, owner).get("design") or {}
        d.update(fields)
        conn.execute("UPDATE reviews SET design = %s WHERE id = %s", (json.dumps(d), owner))
    else:
        conn.execute(f"UPDATE reviews SET {', '.join(f'{k} = %s' for k in fields)} WHERE id = %s",
                     [*fields.values(), owner])
    db.touch(conn, owner)


def remove_entry(conn, owner: int, t: Target, entry: Entry) -> None:
    if not entry.can_remove:
        raise HTTPException(400, f"A {entry.type_label.lower()} cannot be removed here")
    if t.type == "item":
        _item(conn, owner, t.ref)
        conn.execute("DELETE FROM items WHERE id = %s", (int(t.ref),))
        _unpromote(conn, owner, int(t.ref))
    elif t.type == "mitigation":
        conn.execute("DELETE FROM mitigations WHERE id = %s AND review_id = %s", (int(t.ref), owner))
    elif t.type == "finding":
        code, f = _finding(_own_row(conn, owner), t.ref)
        code["findings"] = [x for x in code["findings"] if x is not f]
        conn.execute("UPDATE reviews SET code_review = %s WHERE id = %s", (json.dumps(code), owner))
    elif t.type == "threat":
        arts, data, e = _threat_entry(conn, owner, t.kind, t.ref)
        key = THREAT_SPEC[t.kind][0]
        data[key] = [x for x in data[key] if x is not e]
        _store_threat(conn, owner, t.kind, arts, data)
    elif t.type == "design":
        conn.execute("UPDATE reviews SET design = '{}' WHERE id = %s", (owner,))
    db.touch(conn, owner)


def _store_threat(conn, owner: int, kind: str, arts: dict, data: dict) -> None:
    """Validate and save an edited artifact like the editor does; after a threat-model change, re-validate the
    downstream artifacts so references to removed threats are dropped (their provenance is kept)."""
    review = _get_review(conn, owner)
    register = load_mitigations(conn, owner)
    clean = normalize_artifact(kind, data, app_type=detect_app_type(review), prior=arts, register=register)
    store.put_artifact(conn, owner, kind, clean, "manual", "")
    if kind == "threat_model":
        arts = store.get_artifacts(conn, owner)
        for k in DOWNSTREAM:
            if arts.get(k):
                store.update_data(conn, owner, k, normalize_artifact(
                    k, arts[k]["data"], app_type=detect_app_type(review), prior=arts, register=register))


# --------------------------------------------------------------------------- helpers
def _context(review: dict) -> dict:
    design, code = review.get("design") or {}, review.get("code_review") or {}
    ctx = {
        "title": review.get("title"), "kind": "threat model" if review.get("kind") == "threat_model" else "security review",
        "description": (review.get("description") or "")[:3000], "tech_stack": review.get("tech_stack"),
        "technologies": review.get("technologies"), "services": review.get("services"),
        "profile": profile_summary(review),
    }
    if design.get("analyzed_at"):
        ctx["design"] = {k: design.get(k) for k in ("summary", "components", "integrations", "data_flows",
                                                    "notable_concerns") if design.get(k)}
    if code.get("ran_at") or code.get("findings"):
        ctx["code_review"] = {"summary": (code.get("summary") or "")[:1500],
                              "findings": [f"[{f.get('severity')}] {f.get('title')}" for f in code.get("findings") or []][:25]}
    if review.get("linked_threat_models"):
        ctx["linked_threat_models"] = [{"ref": t["ref"], "title": t["title"], "summary": (t.get("summary") or "")[:600],
                                        "threats": [x.get("title") for x in t.get("threats") or []][:15]}
                                       for t in review["linked_threat_models"]]
    return ctx


def _clean_result(res: dict, entry: Entry, mode: str) -> dict:
    verdict = str(res.get("verdict") or "").lower().replace(" ", "_").replace("-", "_")
    action = str(res.get("recommendation") or "").lower()
    fields = {k: str(v).strip()[:8000] for k, v in (res.get("fields") or {}).items()
              if k in entry.fields and isinstance(v, (str, int, float)) and str(v).strip()
              and str(v).strip() != entry.fields[k].strip()} if isinstance(res.get("fields"), dict) else {}
    action = action if action in ACTIONS else "revise" if fields else "keep"
    if action == "remove" and not entry.can_remove:
        action = "revise" if fields else "keep"
    if action == "revise" and not fields:
        action = "keep"
    if action != "revise":
        fields = {}
    return {"verdict": verdict if verdict in VERDICTS[mode] else "inconclusive", "recommendation": action,
            "reasoning": str(res.get("reasoning") or "")[:2500],
            "evidence": [str(e)[:300] for e in (res.get("evidence") or []) if isinstance(e, (str, int, float))][:6],
            "fields": fields}


def _validate_fields(entry: Entry, fields: dict[str, str]) -> dict[str, str]:
    unknown = set(fields) - set(entry.fields)
    if unknown:
        raise HTTPException(422, f"Not editable here: {', '.join(sorted(unknown))}")
    if not fields:
        raise HTTPException(422, "Nothing to change")
    out = {k: v.strip()[:8000] for k, v in fields.items()}
    for k in ("title", "label"):
        if k in out and not out[k]:
            raise HTTPException(422, f"{FIELD_LABELS[k]} cannot be empty")
    return out


def _log(conn, owner: int, entry: Entry, mode: str, question: str, verdict: str, outcome: str) -> None:
    q = f" - “{question.strip()[:200]}”" if question.strip() else ""
    v = f" (AI verdict: {verdict.replace('_', ' ')})" if verdict in VERDICTS[mode] else ""
    db.log_activity(conn, owner, "devil" if mode == "devil" else "review",
                    f"{MODE_LABEL[mode]} on {entry.type_label.lower()} {entry.label[:80]}{q}{v}: {outcome}")


def _llm():
    try:
        return build_llm(db.get_settings())
    except ProviderError:
        return None


def _require_llm() -> LLM:
    llm = _llm()
    if llm is None:
        raise HTTPException(400, "Configure an AI provider in Settings to use AI review or devil's advocate - you can "
                                 "still override the text or remove the entry yourself.")
    return llm


def _entry_payload(entry: Entry) -> dict:
    return {"label": entry.label, "type_label": entry.type_label, "can_remove": entry.can_remove,
            "fields": [{"name": k, "label": FIELD_LABELS.get(k, k), "value": v, "multiline": k not in SINGLE_LINE}
                       for k, v in entry.fields.items()]}


async def adjudicate(llm: LLM, context: dict, entry: Entry, mode: str, question: str) -> dict:
    payload = {"application": context,
               "entry": {"type": entry.type_label, "label": entry.label, "can_remove": entry.can_remove,
                         "editable_fields": entry.fields, "related": entry.related}}
    if mode == "devil":
        payload["challenge"] = question.strip() or DEFAULT_CHALLENGE
    elif question.strip():
        payload["instructions"] = question.strip()
    res = await llm.complete_json(SYSTEMS[mode], json.dumps(payload, indent=1), tag=mode)
    return _clean_result(res if isinstance(res, dict) else {}, entry, mode)


# --------------------------------------------------------------------------- routes
@router.get("/reviews/{review_id}/devil")
def devil_entry(review_id: int, type: TargetType, ref: str = "", kind: str = ""):
    with db.tx() as conn:
        entry = load_entry(conn, review_id, Target(type=type, ref=ref, kind=kind))
    return {**_entry_payload(entry), "ai_enabled": _llm() is not None}


@router.post("/reviews/{review_id}/devil/challenge")
async def devil_challenge(review_id: int, body: ChallengeBody):
    llm = _require_llm()
    with db.tx() as conn:
        review = _get_review(conn, review_id)
        entry = load_entry(conn, review_id, body.target)
    try:
        res = await adjudicate(llm, _context(review), entry, body.mode, body.question)
    except ProviderError as e:
        raise HTTPException(502, str(e)) from e
    return {**res, "provider": llm.label}


@router.post("/reviews/{review_id}/devil/batch")
def devil_batch(review_id: int, body: BatchBody):
    """Queue an AI review or devil's advocate pass over several entries (possibly owned by linked threat models)."""
    _require_llm()
    targets = [t.model_copy(update={"owner": t.owner or review_id}) for t in body.targets]
    owners = sorted({t.owner for t in targets})
    with db.tx() as conn:
        found = {r[0] for r in conn.execute("SELECT id FROM reviews WHERE id = ANY(%s) AND workspace_id = %s",
                                            (owners, db.workspace_id()))}
    if set(owners) - found:
        raise HTTPException(404, "Review not found")
    return {"job_id": jobs.start_job(review_id, f"devil_{body.mode}", "devil_batch", mode=body.mode,
                                     question=body.question, targets=[t.model_dump() for t in targets])}


@jobs.handler("devil_batch")
async def devil_batch_job(progress, mode: str, question: str, targets: list[dict]):
    llm = _require_llm()
    contexts: dict[int, dict] = {}
    entries: list[tuple[Target, Entry | None, str]] = []
    with db.tx() as conn:
        for raw in targets:
            t = Target(**raw)
            try:
                if t.owner not in contexts:
                    contexts[t.owner] = _context(_get_review(conn, t.owner))
                entries.append((t, load_entry(conn, t.owner, t), ""))
            except HTTPException as e:
                entries.append((t, None, str(e.detail)))
    total, done = len(entries), 0
    sem = asyncio.Semaphore(AI_BATCH_CONCURRENCY)
    await progress(0.03, f"{MODE_LABEL[mode]}: {total} entr{'y' if total == 1 else 'ies'}, "
                         f"{min(AI_BATCH_CONCURRENCY, total)} at a time…")

    async def one(t: Target, entry: Entry | None, error: str) -> dict:
        nonlocal done
        out = {"target": t.model_dump(), **(_entry_payload(entry) if entry else {"label": t.ref, "fields": []})}
        if entry is not None:
            async with sem:
                try:
                    res = await adjudicate(llm, contexts[t.owner], entry, mode, question)
                    proposed = res.pop("fields")
                    out.update(res, proposed=proposed)
                except ProviderError as e:
                    error = str(e)[:500]
                    log.warning("%s failed for %s %s: %s", mode, t.type, t.ref, e)
        if error:
            out["error"] = error
        done += 1
        await progress(0.05 + 0.9 * done / total, f"{done}/{total} reviewed")
        return out

    results = await asyncio.gather(*(one(*e) for e in entries))
    return {"mode": mode, "question": question, "results": results, "provider": llm.label}


@router.post("/reviews/{review_id}/devil/apply")
def devil_apply(review_id: int, body: ApplyBody):
    with db.tx() as conn:
        entry = load_entry(conn, review_id, body.target)
        fields = _validate_fields(entry, body.fields)
        save_entry(conn, review_id, body.target, fields)
        changed = ", ".join(FIELD_LABELS.get(k, k).lower() for k in fields)
        _log(conn, review_id, entry, body.mode, body.question, body.verdict,
             f"applied the AI correction ({changed})" if body.source == "ai" else f"text overridden ({changed})")
    return {"ok": True}


@router.post("/reviews/{review_id}/devil/remove")
def devil_remove(review_id: int, body: RemoveBody):
    with db.tx() as conn:
        entry = load_entry(conn, review_id, body.target)
        remove_entry(conn, review_id, body.target, entry)
        _log(conn, review_id, entry, body.mode, body.question, body.verdict, "removed")
    return {"ok": True}
