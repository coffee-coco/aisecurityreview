"""Threat model artifacts on a threat-model record: generation jobs, reviewer edits, diagram import and markdown
export. Promotion into a security review's registers lives in ``api_threat_models``."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from . import db, jobs
from .ai.providers import Attachment, ProviderError, build_llm
from .api import _get_review
from .api_files import _docs, _read_limited
from .items import load_mitigations
from .threat import DOWNSTREAM, KINDS, store
from .threat.context import build_context, detect_app_type
from .threat.drawio import DiagramError, parse_drawio
from .threat.export import render_export
from .threat.generators import GENERATORS, MissingThreatModel, dfd_from_image, require_threats
from .threat.normalize import normalize_artifact, normalize_dfd
from .threat.references import select_cards
from .threat.source import assess_inputs

router = APIRouter(prefix="/api")

NO_AI = "Configure an AI provider in Settings to generate a threat model."
LABELS = {"threat_model": "Threat model", "attack_tree": "Attack tree", "dfd": "Data flow diagram",
          "mitigations": "Threat mitigations", "dread": "DREAD assessment", "test_cases": "Security test cases"}
IMAGE_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp",
               ".gif": "image/gif"}
XML_TYPES = (".drawio", ".xml")


# --------------------------------------------------------------------------- models
class GenerateBody(BaseModel):
    instructions: str = ""
    refine: bool = False


class ArtifactBody(BaseModel):
    data: dict


# --------------------------------------------------------------------------- helpers
def _get_tm(conn, tm_id: int) -> dict:
    tm = _get_review(conn, tm_id)
    if tm.get("kind") != "threat_model":
        raise HTTPException(404, "Threat models live on the Threat models page; link one to this review instead")
    return tm



def _check_kind(kind: str) -> None:
    if kind not in KINDS:
        raise HTTPException(404, "Unknown threat-model artifact")


def _llm_required():
    try:
        llm = build_llm(db.get_settings())
    except ProviderError as e:
        raise HTTPException(400, str(e))
    if llm is None:
        raise HTTPException(400, NO_AI)
    return llm


def _artifacts(review_id: int) -> dict:
    with db.tx() as conn:
        _get_tm(conn, review_id)
        return store.get_artifacts(conn, review_id)


def _save(review_id: int, kind: str, data: dict, source: str, model: str, activity: str) -> dict:
    with db.tx() as conn:
        art = store.put_artifact(conn, review_id, kind, data, source, model)
        db.log_activity(conn, review_id, "threat", activity)
    return art


# --------------------------------------------------------------------------- read
@router.get("/reviews/{review_id}/threats")
def get_threats(review_id: int):
    with db.tx() as conn:
        review = _get_tm(conn, review_id)
        arts = store.get_artifacts(conn, review_id)
        code_docs = _docs(conn, review_id, ("code",))
        docs_count = len(_docs(conn, review_id, ("document", "image")))
    try:
        ai_enabled = build_llm(db.get_settings()) is not None
    except ProviderError:
        ai_enabled = False
    app_type = detect_app_type(review)
    inputs = assess_inputs(review, code_docs, docs_count, bool(((arts.get("dfd") or {}).get("data") or {}).get("nodes")))
    return {"artifacts": arts, "jobs": [j for j in jobs.active_jobs(review_id) if j["kind"].startswith("threat_")],
            "ai_enabled": ai_enabled, "app_type": app_type, "cards": select_cards(app_type), "inputs": inputs}


@router.get("/reviews/{review_id}/threats/export.md", response_class=PlainTextResponse)
def export_threats(review_id: int):
    with db.tx() as conn:
        review = _get_tm(conn, review_id)
        arts = store.get_artifacts(conn, review_id)
    return PlainTextResponse(render_export(review, arts), headers={
        "Content-Disposition": f'attachment; filename="{review["ref"]}-threat-model.md"'})


# --------------------------------------------------------------------------- generate
@router.post("/reviews/{review_id}/threats/all/generate")
async def generate_all(review_id: int, body: Optional[GenerateBody] = None):
    body = body or GenerateBody()
    _artifacts(review_id)
    llm = _llm_required()

    async def work(progress):
        await progress(0.03, "Reading linked source code and review context…")
        ctx = await asyncio.to_thread(build_context, review_id, llm)
        steps = ["threat_model", *DOWNSTREAM, "dfd"]
        done, errors = [], {}
        for i, kind in enumerate(steps):
            prior = _artifacts(review_id)
            if kind == "dfd" and (prior["dfd"] or {}).get("source") == "manual":
                continue  # never overwrite a reviewer-edited or imported diagram
            await progress(0.05 + 0.9 * i / len(steps), f"AI generating {LABELS[kind].lower()}…")
            try:
                data = await GENERATORS[kind](llm, ctx, prior, body.instructions, body.refine)
            except (ProviderError, MissingThreatModel) as e:
                if kind == "threat_model":
                    raise
                errors[kind] = str(e)
                continue
            with db.tx() as conn:
                store.put_artifact(conn, review_id, kind, data, "ai", llm.label)
            done.append(kind)
        with db.tx() as conn:
            db.log_activity(conn, review_id, "threat", f"Threat model generated via {llm.label}: "
                            + ", ".join(LABELS[k].lower() for k in done)
                            + (f" ({len(errors)} failed)" if errors else ""))
        return {"generated": done, "errors": errors}

    return {"job_id": jobs.start_job(review_id, "threat_all", work)}


@router.post("/reviews/{review_id}/threats/{kind}/generate")
async def generate_artifact(review_id: int, kind: str, body: Optional[GenerateBody] = None):
    _check_kind(kind)
    body = body or GenerateBody()
    prior = _artifacts(review_id)
    llm = _llm_required()
    if kind in DOWNSTREAM:
        try:
            require_threats(prior)
        except MissingThreatModel as e:
            raise HTTPException(400, str(e))

    async def work(progress):
        await progress(0.1, "Reading linked source code and review context…")
        ctx = await asyncio.to_thread(build_context, review_id, llm)
        await progress(0.3, f"AI {'refining' if body.refine else 'generating'} {LABELS[kind].lower()}…")
        data = await GENERATORS[kind](llm, ctx, _artifacts(review_id), body.instructions, body.refine)
        art = _save(review_id, kind, data, "ai", llm.label,
                    f"{LABELS[kind]} {'refined' if body.refine else 'generated'} via {llm.label}")
        return {"kind": kind, "artifact": art}

    return {"job_id": jobs.start_job(review_id, f"threat_{kind}", work)}


@router.post("/reviews/{review_id}/threats/dfd/import")
async def import_dfd(review_id: int, file: UploadFile = File(...)):
    _artifacts(review_id)
    name = Path(file.filename or "diagram").name
    ext = Path(name).suffix.lower()
    if ext not in IMAGE_TYPES and ext not in XML_TYPES:
        raise HTTPException(415, "Upload a PNG, JPEG, WebP or GIF image, or a draw.io (.drawio / .xml) file")
    raw = await _read_limited(file)
    if ext in XML_TYPES:
        try:
            dfd = normalize_dfd(parse_drawio(raw.decode("utf-8", "replace")))
        except DiagramError as e:
            raise HTTPException(400, str(e))

        async def work(progress):
            await progress(0.5, f"Importing {name}…")
            art = _save(review_id, "dfd", dfd, "manual", "", f"Data flow diagram imported from {name}")
            return {"kind": "dfd", "artifact": art}
    else:
        llm = _llm_required()
        if not llm.supports("image"):
            raise HTTPException(400, f"{llm.label} cannot read images - import a draw.io file instead")
        image = Attachment(IMAGE_TYPES[ext], raw, name)

        async def work(progress):
            await progress(0.2, f"AI reading {name}…")
            data = await dfd_from_image(llm, image)
            art = _save(review_id, "dfd", data, "ai", llm.label,
                        f"Data flow diagram imported from {name} via {llm.label}")
            return {"kind": "dfd", "artifact": art}

    return {"job_id": jobs.start_job(review_id, "threat_dfd", work)}


# --------------------------------------------------------------------------- edit
@router.put("/reviews/{review_id}/threats/{kind}")
def save_artifact(review_id: int, kind: str, body: ArtifactBody):
    _check_kind(kind)
    with db.tx() as conn:
        review = _get_tm(conn, review_id)
        prior = store.get_artifacts(conn, review_id)
        if kind in DOWNSTREAM:
            try:
                require_threats(prior)
            except MissingThreatModel as e:
                raise HTTPException(400, str(e))
        data = normalize_artifact(kind, body.data, app_type=detect_app_type(review), prior=prior,
                                  register=load_mitigations(conn, review_id))
        art = store.put_artifact(conn, review_id, kind, data, "manual", "")
        db.log_activity(conn, review_id, "threat", f"{LABELS[kind]} edited")
    return art


@router.delete("/reviews/{review_id}/threats/{kind}")
def delete_artifact(review_id: int, kind: str):
    _check_kind(kind)
    with db.tx() as conn:
        _get_tm(conn, review_id)
        store.delete_artifact(conn, review_id, kind)
        db.log_activity(conn, review_id, "threat", f"{LABELS[kind]} removed")
    return {"ok": True}
