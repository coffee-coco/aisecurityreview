"""Real source code for the threat model, plus an honest assessment of how much input the model has.

``gather_source`` picks the files that matter most for threat modelling (authentication, routes, data access,
AI/agent code, infrastructure, configuration) and numbers their lines, within a character budget.
``assess_inputs`` rates the review's inputs so the reviewer knows when a threat model rests on thin evidence.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..code.review import CODE_LANGS_FOR_AI, _numbered, _priority
from ..code.workspace import read_text

PER_FILE_CHARS = 14_000
README_CHARS = 6_000
MAX_TREE = 400
LOCK_FILES = re.compile(r"(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|"
                        r"composer\.lock|Cargo\.lock|go\.sum|.*\.min\.(js|css))$", re.I)
EXTRA_BOOST = ((re.compile(r"(^|/)readme(\.\w+)?$", re.I), 6),
               (re.compile(r"openapi|swagger|\.proto$|schema\.(graphql|json|sql)$", re.I), 4),
               (re.compile(r"(^|/)(dockerfile|docker-compose[\w.-]*\.ya?ml)$|\.tf$|(^|/)k8s/|helm", re.I), 3))


def _rank(f: dict, hit_files: set[str]) -> float:
    s = _priority(f["path"], f["lang"], f["bytes"], hit_files)
    return s + sum(w for rx, w in EXTRA_BOOST if rx.search(f["path"]))


def gather_source(inv: dict, abs_paths: dict[str, Path], budget: int, hit_files: set[str] | None = None) -> dict:
    """Return {"tree", "text", "stats"} for the highest-value files that fit ``budget`` characters."""
    hit_files = hit_files or set()
    files = [f for f in inv.get("file_list") or []
             if not LOCK_FILES.search(f["path"])
             and (f["lang"] in CODE_LANGS_FOR_AI or re.search(r"readme", f["path"], re.I))
             and not (f["lang"] == "Markdown" and not re.search(r"readme", f["path"], re.I))]
    files.sort(key=lambda f: (-_rank(f, hit_files), f["path"]))
    parts, used, included, trimmed = [], 0, [], 0
    for f in files:
        if used >= budget:
            break
        p = abs_paths.get(f["path"])
        text = read_text(p) if p else None
        if not text or not text.strip():
            continue
        cap = README_CHARS if re.search(r"readme", f["path"], re.I) else PER_FILE_CHARS
        if len(text) > cap:
            text, trimmed = text[:cap] + "\n[... file truncated ...]", trimmed + 1
        block = f"\n===== FILE: {f['path']} =====\n{_numbered(text)}\n"
        if used + len(block) > budget:
            continue  # a smaller, lower-ranked file may still fit
        parts.append(block)
        used += len(block)
        included.append(f["path"])
    tree = [f"{f['path']} ({f['lines']} lines)" for f in inv.get("file_list") or []][:MAX_TREE]
    return {"tree": tree, "text": "".join(parts), "included": included,
            "stats": {"files_total": len(files), "files_included": len(included),
                      "files_trimmed": trimmed, "chars": used, "budget": budget}}


def assess_inputs(review: dict, code_docs: list[dict], docs_count: int, has_dfd: bool,
                  source: dict | None = None, ai_context: int | None = None) -> dict:
    """Rate the inputs: {level: good|limited|thin, sources: {...}, warnings: [...]}.

    ``code_docs`` are the stored code sources (uploads or linked repos); ``source`` is the gather_source
    result when the source was actually prepared for a generation run.
    """
    files = sum(int((d.get("meta") or {}).get("files") or 0) for d in code_docs)
    repos = [d for d in code_docs if (d.get("meta") or {}).get("type") == "git"]
    design = review.get("design") or {}
    desc_len = len((review.get("description") or "").strip())
    sources = {"code_sources": len(code_docs), "code_files": files, "git_repos": len(repos),
               "documents": docs_count, "design_analysis": bool(design.get("summary")),
               "data_flow_diagram": has_dfd, "code_review_run": bool((review.get("code_review") or {}).get("ran_at"))}
    warnings: list[str] = []
    if not code_docs:
        warnings.append("No source code or git repository is linked, so threats are inferred from the description "
                        "and documents only. Link a repository or upload code for a threat model grounded in the "
                        "real implementation.")
    elif files and files < 5:
        warnings.append(f"Only {files} source file(s) are linked, which is unlikely to show the whole system.")
    if source:
        st = source["stats"]
        if st["files_included"] < st["files_total"]:
            warnings.append(f"{st['files_included']} of {st['files_total']} files fit the AI model's context; the "
                            f"highest-value ones (authentication, routes, data access, AI, infrastructure) were "
                            f"chosen. A larger-context model reads more.")
        if st["files_trimmed"]:
            warnings.append(f"{st['files_trimmed']} large file(s) were cut to their first {PER_FILE_CHARS:,} characters.")
    if not docs_count and not design.get("summary"):
        warnings.append("No architecture or design document is uploaded, so intended trust boundaries and "
                        "external integrations are inferred from code only." if code_docs else
                        "No architecture or design document is uploaded.")
    if desc_len < 200 and not code_docs:
        warnings.append("The description is short; add detail or upload material for a more accurate threat model.")
    if not has_dfd and not code_docs:
        warnings.append("No data flow diagram exists yet; generating one first improves the threat model.")
    if code_docs and not sources["code_review_run"]:
        warnings.append("The code review has not been run; the inventory is built automatically, but static-rule "
                        "and Checkov findings will not inform the threats.")
    if not code_docs and not docs_count:
        level = "thin"
    elif not code_docs or (files and files < 5):
        level = "limited"
    else:
        level = "good"
    return {"level": level, "sources": sources, "warnings": warnings}
