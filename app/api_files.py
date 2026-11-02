"""Uploads (architecture documents, images, code), design analysis, code review and job polling."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from . import db, jobs, threat_models
from .ai.design import analyze_design
from .ai.providers import ProviderError, build_llm
from .api import _get_review, get_review, run_scope
from .catalog import get_catalog
from .code.gitsource import GitError, clone_repo, validate_url
from .code.review import review_codebase
from .code.workspace import UnpackError, extract_archive, is_archive, save_file, snippet_filename
from .config import MAX_UPLOAD_MB, UPLOAD_DIR
from .ingest import classify_upload, extract_text, mime_for
from .profile import CLASSIFICATIONS, EXPOSURES, class_level, profile_summary
from .threat import store
from .threat.export import render_export

router = APIRouter(prefix="/api")
TEXT_SUFFIX = ".extracted.txt"


def _safe_name(name: str) -> str:
    name = Path(name or "file").name
    return re.sub(r"[^A-Za-z0-9._ -]+", "_", name)[:120] or "file"


def _review_dir(review_id: int, sub: str) -> Path:
    d = UPLOAD_DIR / str(review_id) / sub
    d.mkdir(parents=True, exist_ok=True)
    return d


async def _read_limited(f: UploadFile) -> bytes:
    data = await f.read(MAX_UPLOAD_MB * 1024 * 1024 + 1)
    if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"{f.filename} is larger than {MAX_UPLOAD_MB} MB")
    return data


def _insert_doc(conn, review_id: int, kind: str, filename: str, mime: str, size: int, sha: str, path: Path,
                meta: dict) -> int:
    return conn.execute(
        "INSERT INTO documents (review_id, kind, filename, mime, size, sha256, path, meta, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (review_id, kind, filename, mime, size, sha, str(path), json.dumps(meta), db.now())).lastrowid


def _docs(conn, review_id: int, kinds: tuple[str, ...]) -> list[dict]:
    q = f"SELECT * FROM documents WHERE review_id = ? AND kind IN ({','.join('?' * len(kinds))}) ORDER BY id"
    out = []
    for r in conn.execute(q, (review_id, *kinds)):
        d = dict(r)
        d["meta"] = json.loads(d["meta"] or "{}")
        out.append(d)
    return out


def _get_code_owner(conn, review_id: int) -> dict:
    review = _get_review(conn, review_id)
    if review.get("kind") != "threat_model":
        raise HTTPException(400, "Code is linked on a threat model. Open Threat models, link the repository there, "
                                 "then link the threat model to this review.")
    return review


def _llm():
    try:
        return build_llm(db.get_settings())
    except ProviderError as e:
        raise HTTPException(400, str(e))


# --------------------------------------------------------------------------- documents
@router.post("/reviews/{review_id}/documents", status_code=201)
async def upload_documents(review_id: int, files: list[UploadFile] = File(...)):
    with db.tx() as conn:
        _get_review(conn, review_id)
    added, rejected = [], []
    for f in files:
        kind = classify_upload(f.filename or "")
        if kind == "unknown":
            rejected.append(f"{f.filename}: unsupported type (use Code upload for source code / zips)")
            continue
        data = await _read_limited(f)
        sha = hashlib.sha256(data).hexdigest()
        name = _safe_name(f.filename)
        with db.tx() as conn:
            dup = conn.execute("SELECT id FROM documents WHERE review_id = ? AND sha256 = ? AND kind != 'code'",
                               (review_id, sha)).fetchone()
        if dup:
            rejected.append(f"{name}: already uploaded")
            continue
        path = _review_dir(review_id, "docs") / f"{sha[:12]}_{name}"
        path.write_bytes(data)
        text, meta = extract_text(name, data)
        if text:
            path.with_name(path.name + TEXT_SUFFIX).write_text(text)
        meta["preview"] = text[:600]
        with db.tx() as conn:
            did = _insert_doc(conn, review_id, kind, name, mime_for(name), len(data), sha, path, meta)
            db.log_activity(conn, review_id, "document", f"Uploaded {name}")
        added.append(did)
    return {"added": added, "rejected": rejected, "review": get_review(review_id)}


@router.delete("/reviews/{review_id}/documents/{doc_id}")
def delete_document(review_id: int, doc_id: int):
    with db.tx() as conn:
        row = conn.execute("SELECT * FROM documents WHERE id = ? AND review_id = ?", (doc_id, review_id)).fetchone()
        if not row:
            raise HTTPException(404, "Document not found")
        conn.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
        db.log_activity(conn, review_id, "document", f"Removed {row['filename']}")
    p = Path(row["path"])
    if p.resolve().is_relative_to(UPLOAD_DIR.resolve()):
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
        else:
            p.unlink(missing_ok=True)
            p.with_name(p.name + TEXT_SUFFIX).unlink(missing_ok=True)
    return get_review(review_id)


def _doc(review_id: int, doc_id: int) -> dict:
    with db.tx() as conn:
        row = conn.execute("SELECT * FROM documents WHERE id = ? AND review_id = ?", (doc_id, review_id)).fetchone()
    if not row:
        raise HTTPException(404, "Document not found")
    return dict(row)


@router.get("/reviews/{review_id}/documents/{doc_id}/raw")
def document_raw(review_id: int, doc_id: int):
    d = _doc(review_id, doc_id)
    if d["kind"] == "code":
        raise HTTPException(400, "Use the code file viewer")
    return FileResponse(d["path"], media_type=d["mime"], filename=d["filename"],
                        content_disposition_type="inline")


@router.get("/reviews/{review_id}/documents/{doc_id}/text", response_class=PlainTextResponse)
def document_text(review_id: int, doc_id: int):
    d = _doc(review_id, doc_id)
    p = Path(d["path"])
    t = p.with_name(p.name + TEXT_SUFFIX)
    return PlainTextResponse(t.read_text() if t.exists() else "")


# --------------------------------------------------------------------------- design understanding
def _load_doc_inputs(review_id: int) -> list[dict]:
    """Uploaded documents, plus one text document per linked threat model so design analysis sees the whole
    picture (threats, data flow diagram, mitigations, code review)."""
    with db.tx() as conn:
        docs = _docs(conn, review_id, ("document", "image"))
        linked = [(_get_review(conn, t), store.get_artifacts(conn, t)) for t in threat_models.linked_ids(conn, review_id)]
    for d in docs:
        p = Path(d["path"])
        t = p.with_name(p.name + TEXT_SUFFIX)
        d["text"] = t.read_text() if t.exists() else ""
    for tm, arts in linked:
        code = tm.get("code_review") or {}
        text = render_export(tm, arts)
        if code.get("summary"):
            text += "\n\n## Code review\n" + code["summary"] + "\n" + "\n".join(
                f"- [{f['severity']}] {f['title']}" for f in (code.get("findings") or [])[:40])
        docs.append({"id": f"tm-{tm['id']}", "filename": f"Linked threat model {tm['ref']} - {tm['title']}",
                     "kind": "document", "mime": "text/markdown", "path": "", "meta": {"threat_model_id": tm["id"]},
                     "text": text})
    return docs


@router.post("/reviews/{review_id}/design/analyze")
async def design_analyze(review_id: int):
    with db.tx() as conn:
        _get_review(conn, review_id)
    llm = _llm()

    async def work(progress):
        docs = _load_doc_inputs(review_id)
        await progress(0.15, f"Reading {len(docs)} document(s)…")
        with db.tx() as conn:
            review = _get_review(conn, review_id)
        await progress(0.3, "AI building design understanding…" if llm else "Detecting design characteristics…")
        design = await analyze_design(review, docs, get_catalog(), llm)
        design["analyzed_at"] = db.now()
        with db.tx() as conn:
            conn.execute("UPDATE reviews SET design = ?, updated_at = ? WHERE id = ?",
                         (json.dumps(design), db.now(), review_id))
            db.log_activity(conn, review_id, "design", f"Design analysed from {len(docs)} document(s) via "
                            f"{design.get('provider')}")
        return {"design": design}

    return {"job_id": jobs.start_job(review_id, "design", work)}


class DesignApply(BaseModel):
    fields: list[str] = ["system_types", "data_types", "exposure", "data_classification", "technologies",
                         "services", "flags", "description"]
    rescope: bool = False
    source: str = "design"  # design | code


@router.post("/reviews/{review_id}/design/apply")
async def design_apply(review_id: int, body: DesignApply):
    from .api import LIST_COLUMNS, sync_profile
    with db.tx() as conn:
        review = _get_review(conn, review_id)
    src = review.get("design") if body.source == "design" else review.get("code_review")
    src = src or {}
    if not src:
        raise HTTPException(400, "Nothing to apply - analyse documents or code first")
    up: dict = {}
    f = set(body.fields)
    if "system_types" in f and src.get("system_types"):
        up["system_types"] = list(dict.fromkeys((review.get("system_types") or []) + src["system_types"]))
    if "data_types" in f and src.get("data_types"):
        up["data_types"] = list(dict.fromkeys((review.get("data_types") or []) + src["data_types"]))
    if "exposure" in f and src.get("exposure") in EXPOSURES:
        up["exposure"] = src["exposure"]
    if "data_classification" in f and src.get("suggested_classification") in CLASSIFICATIONS:
        up["data_classification"] = src["suggested_classification"]
    for k in ("technologies", "services"):
        if k in f and src.get(k):
            up[k] = list(dict.fromkeys((review.get(k) or []) + list(src[k])))
    if "flags" in f:
        if src.get("uses_ai"):
            up["uses_ai"] = True
        if src.get("third_party"):
            up["third_party"] = True
    if "description" in f and src.get("summary") and not (review.get("description") or "").strip():
        up["description"] = src["summary"]
    up = sync_profile(up, review)
    if up:
        with db.tx() as conn:
            sets = ", ".join(f"{k} = ?" for k in up)
            vals = [json.dumps(v) if k in LIST_COLUMNS else int(v) if isinstance(v, bool) else v for k, v in up.items()]
            conn.execute(f"UPDATE reviews SET {sets}, updated_at = ? WHERE id = ?", [*vals, db.now(), review_id])
            db.log_activity(conn, review_id, "profile", f"Applied {body.source} analysis: "
                            + ", ".join(k.replace("_", " ") for k in up if k not in ("internet_facing", "personal_data")))
    if body.rescope:
        return await run_scope(review_id)
    return get_review(review_id)


# --------------------------------------------------------------------------- code
@router.post("/reviews/{review_id}/code", status_code=201)
async def upload_code(review_id: int, files: list[UploadFile] = File(default=[]),
                      snippet: Optional[str] = Form(None), snippet_name: Optional[str] = Form(None),
                      language: Optional[str] = Form(None)):
    with db.tx() as conn:
        _get_code_owner(conn, review_id)
    added, rejected = [], []
    loose: list[tuple[str, bytes]] = []
    for f in files:
        data = await _read_limited(f)
        name = f.filename or "file"
        if is_archive(name):
            with db.tx() as conn:
                did = _insert_doc(conn, review_id, "code", _safe_name(name), "application/zip", len(data),
                                  hashlib.sha256(data).hexdigest(), Path("pending"), {"type": "archive"})
            dest = _review_dir(review_id, "code") / str(did)
            try:
                stats = extract_archive(name, data, dest)
            except UnpackError as e:
                with db.tx() as conn:
                    conn.execute("DELETE FROM documents WHERE id = ?", (did,))
                rejected.append(f"{name}: {e}")
                continue
            with db.tx() as conn:
                conn.execute("UPDATE documents SET path = ?, meta = ? WHERE id = ?",
                             (str(dest), json.dumps({"type": "archive", **stats}), did))
                db.log_activity(conn, review_id, "code", f"Uploaded {name} ({stats['files']} files)")
            added.append(did)
        else:
            loose.append((name, data))
    if loose:
        label = loose[0][0] if len(loose) == 1 else f"{len(loose)} files"
        with db.tx() as conn:
            did = _insert_doc(conn, review_id, "code", _safe_name(label), "text/plain",
                              sum(len(d) for _, d in loose), hashlib.sha256(b"".join(d for _, d in loose)).hexdigest(),
                              Path("pending"), {"type": "files"})
        dest = _review_dir(review_id, "code") / str(did)
        for name, data in loose:
            save_file(name, data, dest)
        with db.tx() as conn:
            conn.execute("UPDATE documents SET path = ?, meta = ? WHERE id = ?",
                         (str(dest), json.dumps({"type": "files", "files": len(loose)}), did))
            db.log_activity(conn, review_id, "code", f"Uploaded {label}")
        added.append(did)
    if snippet and snippet.strip():
        fname = snippet_filename(snippet_name or "snippet", language or "text")
        data = snippet.encode()
        with db.tx() as conn:
            did = _insert_doc(conn, review_id, "code", fname, "text/plain", len(data),
                              hashlib.sha256(data).hexdigest(), Path("pending"),
                              {"type": "snippet", "language": language or "text", "files": 1})
        dest = _review_dir(review_id, "code") / str(did)
        save_file(fname, data, dest)
        with db.tx() as conn:
            conn.execute("UPDATE documents SET path = ? WHERE id = ?", (str(dest), did))
            db.log_activity(conn, review_id, "code", f"Added snippet {fname}")
        added.append(did)
    if not added and not rejected:
        raise HTTPException(422, "Upload files, a zip, or paste a snippet")
    return {"added": added, "rejected": rejected, "review": get_review(review_id)}


class GitLinkBody(BaseModel):
    url: str
    ref: str = ""
    token: str = ""  # used for this clone only - never stored or logged


@router.post("/reviews/{review_id}/code/git", status_code=201)
async def link_git_repo(review_id: int, body: GitLinkBody):
    """Shallow-clone a repository as a code source. Linking the same URL again refreshes the checkout."""
    with db.tx() as conn:
        _get_code_owner(conn, review_id)
        try:
            clean, _ = validate_url(body.url)
        except GitError as e:
            raise HTTPException(422, str(e))
        old = [d for d in _docs(conn, review_id, ("code",)) if d["meta"].get("type") == "git"
               and d["meta"].get("url") == clean]
        did = _insert_doc(conn, review_id, "code", "pending", "application/x-git", 0, "", Path("pending"),
                          {"type": "git", "url": clean})
    dest = _review_dir(review_id, "code") / str(did)
    try:
        meta = await clone_repo(clean, dest, body.ref, body.token or None)
    except (GitError, UnpackError) as e:
        with db.tx() as conn:
            conn.execute("DELETE FROM documents WHERE id = ?", (did,))
        raise HTTPException(422, str(e))
    with db.tx() as conn:
        for d in old:
            shutil.rmtree(d["path"], ignore_errors=True)
            conn.execute("DELETE FROM documents WHERE id = ?", (d["id"],))
        conn.execute("UPDATE documents SET filename = ?, size = ?, sha256 = ?, path = ?, meta = ? WHERE id = ?",
                     (meta["name"], meta["bytes"], meta["commit"], str(dest),
                      json.dumps({"type": "git", **{k: v for k, v in meta.items() if k != "name"}}), did))
        db.log_activity(conn, review_id, "code", f"Linked {clean} @ {meta['ref']} ({meta['commit'][:8]}, "
                        f"{meta['files']} files)")
    return {"added": [did], "rejected": [], "review": get_review(review_id)}


def _code_roots(review_id: int) -> list[tuple[str, Path]]:
    with db.tx() as conn:
        docs = _docs(conn, review_id, ("code",))
    roots, seen = [], set()
    for d in docs:
        label = re.sub(r"\.(zip|tar\.gz|tgz|tar|[A-Za-z0-9]{1,6})$", "", d["filename"], flags=re.I) or f"upload-{d['id']}"
        while label in seen:
            label = f"{label}-{d['id']}"
        seen.add(label)
        roots.append((label, Path(d["path"])))
    return roots


class CodeReviewBody(BaseModel):
    ai: bool = True
    checkov: bool = True


@router.post("/reviews/{review_id}/code/review")
async def code_review(review_id: int, body: CodeReviewBody):
    with db.tx() as conn:
        _get_code_owner(conn, review_id)
    roots = _code_roots(review_id)
    if not roots:
        raise HTTPException(400, "Upload code first")
    llm = _llm() if body.ai else None
    cat = get_catalog()

    async def work(progress):
        with db.tx() as conn:
            review = _get_review(conn, review_id)
        result = await review_codebase(roots, cat, llm, profile_summary(review), progress,
                                       use_ai=body.ai, use_checkov=body.checkov)
        result["ran_at"] = db.now()
        result["sources"] = [label for label, _ in roots]
        ck = result.get("checkov") or {}
        with db.tx() as conn:
            ts = db.now()
            for rid in threat_models.linking_reviews(conn, review_id):
                threat_models.apply_checkov(conn, rid, result, cat.checks_by_id)
            conn.execute("UPDATE reviews SET code_review = ?, updated_at = ? WHERE id = ?",
                         (json.dumps(result), ts, review_id))
            n = len(result["findings"])
            db.log_activity(conn, review_id, "code", f"Code review: {result['inventory']['files']} files, {n} "
                            f"finding{'s' if n != 1 else ''} via {result['provider']}"
                            + (f", Checkov {ck.get('failed', 0)} failed / {ck.get('passed', 0)} passed"
                               if ck.get("ran") else ""))
        return {"findings": len(result["findings"])}

    return {"job_id": jobs.start_job(review_id, "code_review", work)}


@router.get("/reviews/{review_id}/code/files")
def code_files(review_id: int):
    with db.tx() as conn:
        review = _get_review(conn, review_id)
    inv = (review.get("code_review") or {}).get("inventory") or {}
    return {"files": inv.get("file_list", [])}


@router.get("/reviews/{review_id}/code/file", response_class=PlainTextResponse)
def code_file(review_id: int, path: str):
    roots = _code_roots(review_id)
    multi = len(roots) > 1
    for label, root in roots:
        rel = path
        if multi:
            if not path.startswith(label + "/"):
                continue
            rel = path[len(label) + 1:]
        target = (root / rel).resolve()
        if target.is_relative_to(root.resolve()) and target.is_file():
            data = target.read_bytes()[:1_000_000]
            if b"\x00" in data[:8192]:
                raise HTTPException(415, "Binary file")
            return PlainTextResponse(data.decode("utf-8", "replace"))
    raise HTTPException(404, "File not found")


# --------------------------------------------------------------------------- jobs
@router.get("/jobs/{job_id}")
def job_status(job_id: int):
    j = jobs.get_job(job_id)
    if not j:
        raise HTTPException(404, "Job not found")
    return j
