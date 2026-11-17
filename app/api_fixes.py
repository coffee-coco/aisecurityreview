"""Remediation for code-review findings: generate a patch, a proof-of-vulnerability Python test and a
markdown explanation per finding (one at a time or in bulk), and download everything as a zip."""
from __future__ import annotations

import asyncio
import io
import logging
import re
import time
import zipfile

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from . import db, jobs
from .ai.providers import LLM, ProviderError, build_llm
from .api_files import _code_roots, _get_code_owner
from .code import fixstore
from .code.fixgen import generate_fix
from .config import FIX_CONCURRENCY

router = APIRouter(prefix="/api")
log = logging.getLogger("sentinel.fixes")


def _llm():
    try:
        return build_llm(db.get_settings())
    except ProviderError as e:
        raise HTTPException(400, str(e))


def _owner_and_findings(review_id: int) -> tuple[dict, dict[str, dict]]:
    with db.tx() as conn:
        review = _get_code_owner(conn, review_id)
    findings = {f["id"]: f for f in (review.get("code_review") or {}).get("findings") or []}
    return review, findings


def _require_llm_and_roots(review_id: int) -> tuple[LLM, list]:
    roots = _code_roots(review_id)
    if not roots:
        raise HTTPException(400, "Upload code first")
    llm = _llm()
    if llm is None:
        raise HTTPException(400, "Configure an AI provider in Settings to generate fixes.")
    return llm, roots


@router.get("/reviews/{review_id}/fixes")
def list_fixes(review_id: int):
    with db.tx() as conn:
        _get_code_owner(conn, review_id)
        return fixstore.get_fixes(conn, review_id)


# NOTE: the literal routes below (generate-all, download.zip) MUST be registered before the
# `{finding_id:path}` routes further down - a `:path` converter matches any remaining segment(s), including
# "generate-all" or "download.zip", so FastAPI/Starlette would otherwise route those requests to the
# single-finding handlers instead (first matching route wins).
class GenerateAllBody(BaseModel):
    severities: list[str] = []
    only_missing: bool = True


@router.post("/reviews/{review_id}/fixes/generate-all")
async def generate_all(review_id: int, body: GenerateAllBody):
    _, findings_by_id = _owner_and_findings(review_id)
    findings = list(findings_by_id.values())
    _require_llm_and_roots(review_id)
    if body.severities:
        findings = [f for f in findings if f["severity"] in body.severities]
    if body.only_missing:
        with db.tx() as conn:
            existing = fixstore.get_fixes(conn, review_id)
        findings = [f for f in findings if existing.get(f["id"], {}).get("status") != "ready"]
    if not findings:
        raise HTTPException(400, "Nothing to generate")
    return {"job_id": jobs.start_job(review_id, "fix_gen", "fix_gen", review_id=review_id,
                                     finding_ids=[f["id"] for f in findings], only_missing=body.only_missing)}


@jobs.handler("fix_gen")
async def generate_all_job(progress, review_id: int, finding_ids: list[str], only_missing: bool = False):
    _, findings_by_id = _owner_and_findings(review_id)
    findings = [findings_by_id[fid] for fid in finding_ids if fid in findings_by_id]
    if only_missing:  # re-checked here so a redelivered job does not regenerate fixes it already made
        with db.tx() as conn:
            existing = fixstore.get_fixes(conn, review_id)
        findings = [f for f in findings if existing.get(f["id"], {}).get("status") != "ready"]
    if not findings:
        return {"done": 0, "errors": 0, "total": 0}
    llm, roots = _require_llm_and_roots(review_id)
    total = len(findings)
    counts = {"done": 0, "errors": 0}
    sem = asyncio.Semaphore(FIX_CONCURRENCY)
    log.info("TM-%04d: generating %d fix(es), %d in parallel via %s", review_id, total, FIX_CONCURRENCY,
             llm.label)
    await progress(0.02, f"Generating {total} fixes, {min(FIX_CONCURRENCY, total)} at a time…")

    async def one(f: dict) -> None:
        async with sem:
            t0 = time.monotonic()
            log.info("TM-%04d: start %s (%s)", review_id, f["id"], f["title"][:80])
            try:
                result = await generate_fix(f, roots, llm)
                with db.tx() as conn:
                    fixstore.put_fix(conn, review_id, f["id"], status="ready", **result)
                counts["done"] += 1
                log.info("TM-%04d: ready %s in %.1fs (%d file(s) patched, test=%s)", review_id, f["id"],
                         time.monotonic() - t0, len(result["files"]), bool(result["test_code"]))
            except Exception as e:  # noqa: BLE001 - one bad finding must not stop the batch
                with db.tx() as conn:
                    fixstore.put_fix(conn, review_id, f["id"], status="error", error=str(e)[:1000])
                counts["errors"] += 1
                log.warning("TM-%04d: failed %s after %.1fs: %s", review_id, f["id"], time.monotonic() - t0, e)
            finished = counts["done"] + counts["errors"]
            await progress(finished / total, f"{finished}/{total} finished ({counts['done']} ready, "
                                             f"{counts['errors']} failed)")

    await asyncio.gather(*(one(f) for f in findings))
    with db.tx() as conn:
        db.log_activity(conn, review_id, "fix", f"Generated {counts['done']} fix(es)"
                        + (f", {counts['errors']} failed" if counts["errors"] else ""))
    log.info("TM-%04d: batch finished - %d ready, %d failed", review_id, counts["done"], counts["errors"])
    return {**counts, "total": total}


def _safe_dir(finding_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", finding_id)[:80] or "finding"


@router.get("/reviews/{review_id}/fixes/download.zip")
def download_fixes(review_id: int):
    review, findings = _owner_and_findings(review_id)
    with db.tx() as conn:
        fixes = fixstore.get_fixes(conn, review_id)
    ready = {fid: fx for fid, fx in fixes.items() if fx["status"] == "ready"}
    if not ready:
        raise HTTPException(400, "No generated fixes yet")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        index = [f"# Fixes for {review['ref']}: {review['title']}", "",
                 f"{len(ready)} finding(s) with a generated fix.", "",
                 "Each folder is independent. If multiple fixes touch the same file, apply and test them one "
                 "at a time - patches were generated against the original file, so applying several at once "
                 "to the same file may conflict.", ""]
        for fid, fx in sorted(ready.items()):
            title = findings.get(fid, {}).get("title", fid)
            d = _safe_dir(fid)
            index.append(f"- `{d}/` - {title}")
            if fx["patch"]:
                z.writestr(f"{d}/patch.diff", fx["patch"])
            if fx["test_code"]:
                z.writestr(f"{d}/{fx['test_filename'] or 'test_fix.py'}", fx["test_code"])
            z.writestr(f"{d}/FIX.md", fx["explanation"] or "")
        z.writestr("README.md", "\n".join(index))
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/zip",
                             headers={"Content-Disposition": f'attachment; filename="{review["ref"]}-fixes.zip"'})


@router.get("/reviews/{review_id}/fixes/{finding_id:path}")
def get_one_fix(review_id: int, finding_id: str):
    with db.tx() as conn:
        _get_code_owner(conn, review_id)
        fix = fixstore.get_fix(conn, review_id, finding_id)
    if not fix:
        raise HTTPException(404, "No fix generated yet for this finding")
    return fix


@router.post("/reviews/{review_id}/fixes/{finding_id:path}")
async def create_fix(review_id: int, finding_id: str):
    _, findings = _owner_and_findings(review_id)
    finding = findings.get(finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    llm, roots = _require_llm_and_roots(review_id)
    try:
        result = await generate_fix(finding, roots, llm)
        with db.tx() as conn:
            fix = fixstore.put_fix(conn, review_id, finding_id, status="ready", **result)
            db.log_activity(conn, review_id, "fix", f"Generated a fix for: {finding['title'][:80]}")
        return fix
    except ProviderError as e:
        with db.tx() as conn:
            fix = fixstore.put_fix(conn, review_id, finding_id, status="error", error=str(e)[:1000])
        raise HTTPException(502, str(e)) from e


@router.delete("/reviews/{review_id}/fixes/{finding_id:path}")
def delete_fix(review_id: int, finding_id: str):
    with db.tx() as conn:
        _get_code_owner(conn, review_id)
        fixstore.delete_fix(conn, review_id, finding_id)
    return {"ok": True}
