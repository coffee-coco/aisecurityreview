"""Remediation for a single code-review finding: an AI-generated patch, a self-contained Python test that
proves the vulnerability existed, and a markdown explanation.

The model is given the full current content of every file the finding's evidence points to and asked to
return the *complete corrected file* for each one it changes - not a hand-written diff, since line-numbered
diff hunks are exactly the kind of thing models get subtly wrong. The unified diff shown to the reviewer and
saved to disk is computed deterministically from (original, fixed) with ``difflib``, so it is always valid.
"""
from __future__ import annotations

import difflib
import json
import re
from pathlib import Path

from ..ai.providers import LLM, ProviderError
from .workspace import iter_sources, read_text

MAX_FILES = 6
MAX_FILE_CHARS = 60_000  # per file sent to the model

FIX_SYSTEM = """You are a principal application security engineer fixing ONE security finding from a code
review. You are given the finding, its evidence, and the full current content of every file the evidence
points to (numbered for reference only - do not include the numbers in your output).

Produce:
1. For every file that needs a change, the COMPLETE corrected file content with the minimal change needed to
   remediate this finding. Preserve all unrelated code, comments, formatting and behaviour exactly. Only
   include a file in "files" if you actually changed it.
2. A self-contained Python test (using the standard `unittest` module) that PROVES the vulnerability existed:
   written so it FAILS against the original vulnerable code and PASSES once the fix is applied. Prefer
   exercising the real vulnerable logic directly (import and call the vulnerable function/endpoint with a
   malicious input and assert the unsafe behaviour does NOT happen). If the finding is in non-Python
   infrastructure or config, instead read and parse the affected file(s) from disk and assert the insecure
   setting is absent / the secure setting is present. Locate files with
   `REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))` at the top, joined with the exact relative
   paths given in evidence. Add one short comment at the top on how to run it (`pytest <file>` from the root
   of the reviewed repository, or with REPO_ROOT set).
3. A markdown explanation: what the vulnerability is, why it is exploitable here (cite the evidence), what the
   fix changes and why that remediates it, and how to verify.

Only change what is necessary to fix THIS finding - do not fix unrelated issues. If no single file can be
sensibly patched (e.g. a purely architectural, process or missing-dependency finding), return an empty
"files" list and instead give concrete, specific guidance in "explanation" (and still write the best test you
can, e.g. one that checks for the missing control).
Return ONLY JSON:
{"files": [{"path": "exact relative path given", "fixed_content": "full corrected file content"}],
 "test_filename": "test_xxx.py", "test_code": "...", "explanation": "..."}"""


def _numbered(text: str, max_lines: int = 4000) -> str:
    lines = text.split("\n")[:max_lines]
    return "\n".join(f"{i:>5}| {ln[:400]}" for i, ln in enumerate(lines, 1))


def _gather_sources(finding: dict, roots: list[tuple[str, Path]], budget: int) -> dict[str, str]:
    abs_paths = dict(iter_sources(roots))
    paths = list(dict.fromkeys(e["file"] for e in (finding.get("evidence") or []) if e.get("file")))[:MAX_FILES]
    sources: dict[str, str] = {}
    used = 0
    for p in paths:
        ap = abs_paths.get(p)
        if ap is None:
            continue
        text = read_text(ap)
        if text is None:
            continue
        text = text[:MAX_FILE_CHARS]
        if sources and used + len(text) > budget:
            break
        sources[p] = text
        used += len(text)
    return sources


def _diff(path: str, before: str, after: str) -> str:
    a, b = before.splitlines(keepends=True), after.splitlines(keepends=True)
    return "".join(difflib.unified_diff(a, b, fromfile=f"a/{path}", tofile=f"b/{path}"))


def _safe_filename(name: str) -> str:
    name = Path(str(name or "test_fix.py")).name  # strip any directory traversal
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", name) or "test_fix.py"
    return name if name.lower().endswith(".py") else f"{name}.py"


async def generate_fix(finding: dict, roots: list[tuple[str, Path]], llm: LLM) -> dict:
    """Generate (patch, test, explanation) for one finding. Raises ProviderError on failure."""
    sources = _gather_sources(finding, roots, int(llm.context_chars * 0.5))
    user = json.dumps({
        "finding": {k: finding.get(k) for k in
                    ("title", "severity", "category", "description", "recommendation", "csf", "nist")},
        "evidence": [{"file": e.get("file"), "line": e.get("line"), "snippet": e.get("snippet")}
                     for e in (finding.get("evidence") or [])[:15]],
        "files_available_to_patch": list(sources),
    }, indent=1) + "".join(f"\n\n## FILE: {p}\n{_numbered(t)}" for p, t in sources.items())

    res = await llm.complete_json(FIX_SYSTEM, user, tag=f"fix:{finding.get('id', '')}")

    files_out: list[str] = []
    patch_parts: list[str] = []
    for item in res.get("files") or []:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path", "")).strip().replace("\\", "/").lstrip("./")
        fixed = item.get("fixed_content")
        if path not in sources or not isinstance(fixed, str) or not fixed.strip() or fixed == sources[path]:
            continue  # only accept fixes to files we actually sent, that actually changed something
        patch_parts.append(_diff(path, sources[path], fixed))
        files_out.append(path)

    test_code = str(res.get("test_code") or "").strip()[:20000]
    explanation = str(res.get("explanation") or "").strip()[:8000]
    patch = "".join(patch_parts)
    if not patch and not test_code and not explanation:
        raise ProviderError("The model returned no usable fix")
    return {"patch": patch, "files": files_out, "test_filename": _safe_filename(res.get("test_filename")),
            "test_code": test_code, "explanation": explanation, "provider": llm.label}
