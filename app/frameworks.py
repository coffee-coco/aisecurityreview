"""Additional requirement frameworks (NIST AI RMF, OWASP Top 10 lists, ...) loaded at runtime from
catalog/frameworks/*.yaml and registered next to the NIST CSF 2.0 subcategories.

Every framework requirement is added to ``Catalog.subcategories`` in the same shape as a CSF
subcategory, so review items, scoping, reports and check lookups treat them alike.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from .config import ROOT
from .library import condition_matches

if TYPE_CHECKING:
    from .catalog import Catalog

FRAMEWORK_DIR = ROOT / "catalog" / "frameworks"
CSF_ID = "csf"
CSF_SOURCE = "https://www.nist.gov/cyberframework"
ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9.\-]*$")
SCOPES = ("project", "org")

log = logging.getLogger(__name__)


def _load(path: Path) -> dict:
    data = yaml.safe_load(path.read_text()) or {}
    if "functions" not in data:  # flat list: one function, one category per requirement
        fn = data["function"]
        data["functions"] = [{**fn, "categories": [
            {"id": r["id"], "title": r.get("title", r["id"]), "text": "", "requirements": [r]}
            for r in data.get("requirements") or []]}]
    return data


def _requirement(cat: Catalog, r: dict, fw: dict, fn: dict, c: dict, csf_ids: set[str], where: str) -> dict:
    sid = str(r["id"])
    if not ID_RE.match(sid):
        raise ValueError(f"{where}: requirement id {sid!r} must be upper-case and URL-path safe")
    if sid in cat.subcategories:
        raise ValueError(f"{where}: requirement id {sid!r} is already defined")
    scope = r.get("scope", "project")
    if scope not in SCOPES:
        raise ValueError(f"{where}: {sid} scope must be one of {SCOPES}")
    controls = [x for x in r.get("controls") or [] if x in cat.controls]
    unknown = [x for x in r.get("controls") or [] if x not in cat.controls]
    if unknown:
        log.warning("%s: %s - dropped unknown SP 800-53 controls %s", where, sid, ", ".join(unknown))
    return {
        "id": sid, "title": r.get("title", sid), "text": str(r["text"]).strip(),
        "question": str(r["question"]).strip(), "scope": scope, "baseline": bool(r.get("baseline")),
        "triggers": list(r.get("triggers") or []), "controls": controls,
        "examples": list(r.get("examples") or []),
        "csf": [x for x in r.get("csf") or [] if x in csf_ids], "cwe": list(r.get("cwe") or []),
        "function_id": fn["id"], "function_title": fn["title"],
        "category_id": c["id"], "category_title": c["title"],
        "framework_id": fw["id"], "framework_name": fw["name"], "framework_short": fw["short"],
    }


def register_frameworks(cat: Catalog, directory: Path = FRAMEWORK_DIR) -> None:
    """Add every catalog/frameworks/*.yaml framework to the catalog (after the CSF subcategories)."""
    csf = {"id": CSF_ID, "name": "NIST Cybersecurity Framework", "short": "CSF",
           "version": str(cat.meta.get("csf_version", "2.0")), "source": CSF_SOURCE, "applies_when": {}}
    for f in cat.functions:
        f.setdefault("framework", CSF_ID)
        f.setdefault("color", f["id"][:2])
        for c in f["categories"]:
            for s in c["subcategories"]:
                s.setdefault("title", s["id"])
                s.update(framework_id=CSF_ID, framework_name=csf["name"], framework_short=csf["short"])
    csf_ids = set(cat.subcategories)
    frameworks = [{**csf, "count": len(csf_ids)}]
    fn_ids = {f["id"] for f in cat.functions}

    docs = [(p.name, _load(p)) for p in sorted(directory.glob("*.yaml"))]
    for name, data in sorted(docs, key=lambda d: (d[1].get("order", 999), d[0])):
        fid = str(data.get("id") or "")
        if not fid or fid in {fw["id"] for fw in frameworks}:
            raise ValueError(f"{name}: missing or duplicate framework id {fid!r}")
        fw = {"id": fid, "name": data["name"], "short": data.get("short") or data["name"],
              "version": str(data.get("version", "")), "source": data.get("source", ""),
              "applies_when": data.get("applies_when") or {}}
        count = 0
        for fn in data["functions"]:
            if fn["id"] in fn_ids:
                raise ValueError(f"{name}: function id {fn['id']!r} is already defined")
            fn_ids.add(fn["id"])
            cats = []
            for c in fn["categories"]:
                subs = []
                for r in c.get("requirements") or []:
                    s = _requirement(cat, r, fw, fn, c, csf_ids, name)
                    cat.order[s["id"]] = len(cat.order)
                    cat.subcategories[s["id"]] = s
                    subs.append(s)
                cats.append({"id": c["id"], "title": c["title"], "text": c.get("text", ""), "subcategories": subs})
                count += len(subs)
            cat.functions.append({"id": fn["id"], "title": fn["title"], "text": fn.get("text", ""),
                                  "color": fn.get("color", "GV"), "framework": fid, "categories": cats})
        frameworks.append({**fw, "count": count})
    cat.frameworks = frameworks


# --------------------------------------------------------------------------- helpers
def framework_of(cat: Catalog, sid: str) -> str:
    """Framework id of a requirement ('csf' for CSF subcategories and unknown ids)."""
    return (cat.subcategories.get(sid) or {}).get("framework_id", CSF_ID)


def framework_meta(cat: Catalog, fid: str) -> dict | None:
    return next((fw for fw in getattr(cat, "frameworks", []) if fw["id"] == fid), None)


def applicable_frameworks(cat: Catalog, tokens: set[str], text: str) -> set[str]:
    """Framework ids whose ``applies_when`` condition matches the review profile (empty = always)."""
    tokens = {t.lower() for t in tokens}
    out = {CSF_ID}
    for fw in getattr(cat, "frameworks", []):
        when = fw.get("applies_when") or {}
        if not when or condition_matches(when, tokens, text.lower())[0]:
            out.add(fw["id"])
    return out


def framework_tree(cat: Catalog, fid: str) -> list[dict]:
    """``Catalog.tree()`` restricted to one framework, with requirement titles / CWE / CSF links."""
    ids = {f["id"] for f in cat.functions if f.get("framework", CSF_ID) == fid}
    out = []
    for f in cat.tree():
        if f["id"] not in ids:
            continue
        for c in f["categories"]:
            for s in c["subcategories"]:
                src = cat.subcategories[s["id"]]
                s.update(title=src.get("title", s["id"]), cwe=src.get("cwe", []), csf=src.get("csf", []))
        out.append({**f, "framework": fid})
    return out
