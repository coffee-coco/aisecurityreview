#!/usr/bin/env python
"""Build ``data/catalog.json`` - the knowledge base used by the review tool.

Sources
-------
* NIST CSF 2.0 Reference Tool export (functions, categories, subcategories,
  implementation examples and official SP 800-53 Rev 5 informative references)
* NIST SP 800-53 Rev 5 OSCAL catalog (control titles + statements)
* Checkov source tree (every CKV_* check id, name, category, resources)
* catalog/csf_questions.yaml      - review questions per subcategory
* catalog/checkov_nist_rules.yaml - Checkov -> 800-53 mapping rules (with per-control provenance)
* catalog/csf_check_links.yaml    - curated requirement -> check link specs (validated here, read at runtime)

Usage
-----
    python scripts/build_catalog.py                 # use cached downloads if present
    python scripts/build_catalog.py --refresh       # re-download NIST sources
    python scripts/build_catalog.py --checkov-path /path/to/checkov-main
"""
from __future__ import annotations

import argparse
import ast
import datetime as dt
import json
import re
import sys
import urllib.request
import warnings
from collections import defaultdict
from pathlib import Path

import openpyxl
import yaml

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
RAW = DATA / "raw"
CATALOG_SRC = ROOT / "catalog"

CSF_XLSX_URL = "https://csrc.nist.gov/extensions/nudp/services/json/csf/download?olirids=all"
SP80053_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)

# Checkov id prefix -> human readable platform / provider
PROVIDERS = {
    "AWS": "AWS", "AZURE": "Azure", "GCP": "GCP", "K8S": "Kubernetes", "DOCKER": "Docker",
    "GHA": "GitHub Actions", "GIT": "GitHub", "GITHUB": "GitHub", "GLB": "GitLab",
    "GITLABCI": "GitLab CI", "BITBUCKET": "Bitbucket", "BITBUCKETPIPELINES": "Bitbucket Pipelines",
    "AZUREPIPELINES": "Azure Pipelines", "CIRCLECIPIPELINES": "CircleCI", "ARGO": "Argo Workflows",
    "OCI": "Oracle Cloud", "ALI": "Alibaba Cloud", "DIO": "DigitalOcean", "LIN": "Linode",
    "OPENSTACK": "OpenStack", "PAN": "Palo Alto", "TC": "Tencent Cloud", "YC": "Yandex Cloud",
    "NCP": "Naver Cloud", "OPENAPI": "OpenAPI", "SECRET": "Secrets", "TF": "Terraform",
    "OKTA": "Okta", "ANSIBLE": "Ansible", "IBM": "IBM Cloud", "HELM": "Helm", "SLS": "Serverless",
}

FRAMEWORK_LABELS = {
    "terraform": "Terraform", "terraform_json": "Terraform", "cloudformation": "CloudFormation",
    "kubernetes": "Kubernetes", "helm": "Helm", "kustomize": "Kustomize", "arm": "ARM",
    "bicep": "Bicep", "dockerfile": "Dockerfile", "serverless": "Serverless", "cdk": "CDK",
    "openapi": "OpenAPI", "ansible": "Ansible", "github_actions": "GitHub Actions",
    "github": "GitHub", "gitlab": "GitLab", "gitlab_ci": "GitLab CI", "bitbucket": "Bitbucket",
    "bitbucket_pipelines": "Bitbucket Pipelines", "azure_pipelines": "Azure Pipelines",
    "circleci_pipelines": "CircleCI", "argo_workflows": "Argo Workflows", "secrets": "Secrets",
}


# --------------------------------------------------------------------------- utils
def log(msg: str) -> None:
    print(f"  • {msg}")


def download(url: str, dest: Path, refresh: bool) -> Path:
    if dest.exists() and not refresh:
        log(f"using cached {dest.relative_to(ROOT)}")
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    log(f"downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "aisecurityreview-catalog-builder/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        dest.write_bytes(resp.read())
    return dest


_CTRL_RE = re.compile(r"^([A-Za-z]{2})-0*(\d+)(?:[(.]0*(\d+)\)?)?$")


def norm_control(raw: str) -> str | None:
    """'AC-02' -> 'AC-2', 'ac-2.1' -> 'AC-2(1)', 'AC-02(01)' -> 'AC-2(1)'."""
    m = _CTRL_RE.match(raw.strip())
    if not m:
        return None
    fam, num, enh = m.groups()
    return f"{fam.upper()}-{int(num)}" + (f"({int(enh)})" if enh else "")


# --------------------------------------------------------------------------- NIST CSF 2.0
def parse_csf(xlsx: Path) -> list[dict]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        wb = openpyxl.load_workbook(xlsx, read_only=True)
    ws = wb["CSF 2.0"]
    functions: list[dict] = []
    fn = cat = None
    head_re = re.compile(r"^(.*?)\s*\(([A-Z]{2}(?:\.[A-Z]{2})?)\)\s*:\s*(.*)$", re.S)
    for row in ws.iter_rows(min_row=3, values_only=True):
        c_fn, c_cat, c_sub, c_ex, c_ref = (list(row) + [None] * 5)[:5]
        if c_fn:
            m = head_re.match(str(c_fn).strip())
            if m:
                fn = {"id": m.group(2), "title": m.group(1).strip().title(), "text": m.group(3).strip(), "categories": []}
                functions.append(fn)
        elif c_cat and fn is not None:
            m = head_re.match(str(c_cat).strip())
            if m:
                text = m.group(3).strip()
                cat = {"id": m.group(2), "title": m.group(1).strip(), "text": text, "subcategories": [],
                       "withdrawn": "withdrawn" in text.lower() or "moved to" in text.lower()}
                fn["categories"].append(cat)
        elif c_sub and cat is not None:
            sid, _, text = str(c_sub).partition(":")
            text = text.strip()
            if "withdrawn" in text.lower():
                continue
            examples = [e.strip() for e in re.split(r"(?:^|\n)\s*Ex\d+\s*:\s*", str(c_ex or "")) if e.strip()]
            controls: set[str] = set()
            for line in str(c_ref or "").splitlines():
                if line.startswith("SP 800-53"):
                    cid = norm_control(line.split(":", 1)[1])
                    if cid:
                        controls.add(cid)
            cat["subcategories"].append({
                "id": sid.strip(), "text": text, "examples": examples,
                "controls": sorted(controls, key=control_sort_key),
            })
    # drop CSF 1.1 categories that only exist as withdrawn placeholders
    for f in functions:
        f["categories"] = [c for c in f["categories"] if c["subcategories"]]
        for c in f["categories"]:
            c.pop("withdrawn", None)
    return functions


def control_sort_key(cid: str):
    m = re.match(r"([A-Z]{2})-(\d+)(?:\((\d+)\))?", cid)
    if not m:
        return (cid, 0, 0)
    return (m.group(1), int(m.group(2)), int(m.group(3) or 0))


# --------------------------------------------------------------------------- SP 800-53
def parse_80053(path: Path) -> tuple[dict, dict, str]:
    cat = json.loads(path.read_text())["catalog"]
    version = cat.get("metadata", {}).get("version", "5")
    families: dict[str, str] = {}
    controls: dict[str, dict] = {}

    def render_params(text: str, params: dict) -> str:
        def sub(m):
            p = params.get(m.group(1))
            if not p:
                return "[Assignment: organization-defined value]"
            if "select" in p:
                choices = p["select"].get("choice", [])
                how = "one or more" if p["select"].get("how-many") == "one-or-more" else ""
                return f"[Selection{' (' + how + ')' if how else ''}: {'; '.join(render_params(c, params) for c in choices)}]"
            return f"[Assignment: {p.get('label', 'organization-defined value')}]"
        return re.sub(r"\{\{\s*insert:\s*param,\s*([\w.\-]+)\s*\}\}", sub, text)

    def statement(parts: list, params: dict, depth=0) -> list[str]:
        out = []
        for part in parts or []:
            if part.get("name") not in ("statement", "item"):
                continue
            label = next((p["value"] for p in part.get("props", []) if p["name"] == "label"), "")
            prose = render_params(part.get("prose", ""), params).strip()
            if prose:
                out.append(("  " * max(depth - 1, 0)) + (f"{label} " if label else "") + prose)
            out.extend(statement(part.get("parts"), params, depth + 1))
        return out

    def walk(ctrl: dict, fam_id: str, inherited_params: dict):
        props = {p["name"]: p.get("value") for p in ctrl.get("props", [])}
        params = dict(inherited_params)
        params.update({p["id"]: p for p in ctrl.get("params", [])})
        cid = norm_control(ctrl["id"])
        if cid and props.get("status") != "withdrawn":
            controls[cid] = {
                "id": cid,
                "title": ctrl.get("title", ""),
                "family": fam_id.upper(),
                "statement": "\n".join(statement(ctrl.get("parts"), params)),
            }
        for sub in ctrl.get("controls", []):
            walk(sub, fam_id, params)

    for g in cat.get("groups", []):
        families[g["id"].upper()] = g["title"]
        for c in g.get("controls", []):
            walk(c, g["id"], {})
    return families, controls, version


# --------------------------------------------------------------------------- Checkov
def _literal(node, env: dict):
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        vals = [_literal(e, env) for e in node.elts]
        flat = []
        for v in vals:
            if isinstance(v, list):
                flat.extend(v)
            elif v is not None:
                flat.append(v)
        return flat
    if isinstance(node, ast.Attribute):
        return node.attr  # CheckCategories.ENCRYPTION -> "ENCRYPTION"
    if isinstance(node, ast.JoinedStr):
        out = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                out.append(str(part.value))
            elif isinstance(part, ast.FormattedValue):
                v = _literal(part.value, env)
                if v is None or isinstance(v, (list, dict)):
                    return None
                out.append(str(v))
        return "".join(out)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = _literal(node.left, env), _literal(node.right, env)
        if isinstance(a, str) and isinstance(b, str):
            return a + b
        if isinstance(a, list) and isinstance(b, list):
            return a + b
    if isinstance(node, ast.Call) and getattr(node.func, "id", "") in ("tuple", "list", "set") and node.args:
        return _literal(node.args[0], env)
    return None


_KEYS = ("name", "id", "categories", "supported_resources", "supported_entities", "supported_kind",
         "supported_kinds", "supported_entity", "block_type", "guideline")
_RESOURCE_KEYS = ("supported_resources", "supported_entities", "supported_kind", "supported_kinds", "supported_entity")
_ID_RE = re.compile(r"^CKV2?_[A-Z0-9]+_\d+$")


class ClassIndex:
    """Indexes every class in Checkov's checks folders so values that are
    inherited from base classes (categories, resources, f-string names built
    from constructor params) can be resolved statically - no import needed."""

    def __init__(self):
        self.entries: list[tuple] = []
        self.by_dir: dict[tuple[Path, str], tuple] = {}
        self.classes: dict[tuple[str, str], tuple] = {}
        self.by_name: dict[str, tuple] = {}

    def add_file(self, path: Path, framework: str) -> None:
        src = path.read_text(errors="ignore")
        try:
            tree = ast.parse(src)
        except SyntaxError:
            return
        module_env: dict = {}
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                module_env[stmt.targets[0].id] = _literal(stmt.value, module_env)
        for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            bases = [b.id if isinstance(b, ast.Name) else getattr(b, "attr", None) for b in cls.bases]
            entry = (cls, module_env, [b for b in bases if b], framework, path)
            self.entries.append(entry)
            self.by_dir.setdefault((path.parent, cls.name), entry)
            self.classes.setdefault((framework, cls.name), entry)
            self.by_name.setdefault(cls.name, entry)

    def lookup(self, name: str, framework: str, directory: Path | None = None):
        return ((self.by_dir.get((directory, name)) if directory else None)
                or self.classes.get((framework, name)) or self.by_name.get(name))

    def resolve(self, entry, injected: dict, depth: int = 0) -> dict:
        if entry is None or depth > 8:
            return {}
        cls, module_env, bases, framework, path = entry
        env = dict(module_env)
        for stmt in cls.body:
            if isinstance(stmt, ast.Assign):
                for t in stmt.targets:
                    if isinstance(t, ast.Name):
                        env[t.id] = _literal(stmt.value, env)
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
                env[stmt.target.id] = _literal(stmt.value, env)
        init = next((f for f in cls.body if isinstance(f, ast.FunctionDef) and f.name == "__init__"), None)
        passed: dict = {}
        positional: list = []
        if init:
            params = [a.arg for a in init.args.args[1:]] + [a.arg for a in init.args.kwonlyargs]
            defaults = init.args.defaults
            pos_params = [a.arg for a in init.args.args[1:]]
            for p, d in zip(pos_params[len(pos_params) - len(defaults):], defaults):
                env[p] = _literal(d, env)
            for p, d in zip([a.arg for a in init.args.kwonlyargs], init.args.kw_defaults):
                if d is not None:
                    env[p] = _literal(d, env)
            for i, v in enumerate(injected.get("__args__", [])):
                if i < len(pos_params):
                    env[pos_params[i]] = v
            for k, v in injected.items():
                if k in params:
                    env[k] = v
            for stmt in init.body:
                for n in ast.walk(stmt):
                    if isinstance(n, ast.Assign):
                        for t in n.targets:
                            if isinstance(t, ast.Name):
                                env[t.id] = _literal(n.value, env)
                    elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is not None:
                        env[n.target.id] = _literal(n.value, env)
            for call in (n for n in ast.walk(init) if isinstance(n, ast.Call)):
                if getattr(call.func, "attr", "") == "__init__":
                    positional = [_literal(a, env) for a in call.args]
                    for kw in call.keywords:
                        if kw.arg:
                            passed[kw.arg] = _literal(kw.value, env)
        fields = {k: env[k] for k in _KEYS if env.get(k) is not None and (k != "id" or isinstance(env[k], str))}
        for k, v in passed.items():
            key = "id" if k == "check_id" else k
            if key in _KEYS and v is not None:
                fields[key] = v
        passed["__args__"] = positional
        for b in bases:
            parent = self.resolve(self.lookup(b, framework, path.parent), passed, depth + 1)
            for k, v in parent.items():
                fields.setdefault(k, v)
        return fields

    def checks(self):
        for entry in self.entries:
            framework = entry[3]
            fields = self.resolve(entry, {})
            cid = fields.get("id")
            if not (isinstance(cid, str) and _ID_RE.match(cid)):
                continue
            resources = []
            for k in _RESOURCE_KEYS:
                v = fields.get(k)
                if isinstance(v, str):
                    v = [v]
                if isinstance(v, list):
                    resources.extend(str(x) for x in v if isinstance(x, str))
            cats = fields.get("categories") or []
            if isinstance(cats, str):
                cats = [cats]
            name = fields.get("name")
            yield framework, {
                "id": cid,
                "name": name if isinstance(name, str) else "",
                "categories": [str(c).upper() for c in cats if isinstance(c, str)],
                "resources": resources,
                "guideline": fields.get("guideline") if isinstance(fields.get("guideline"), str) else None,
                "_file": entry[4],
            }


def _collect_resource_types(node, out: set):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "resource_types":
                if isinstance(v, list):
                    out.update(str(x) for x in v if x and str(x).lower() != "all")
                elif isinstance(v, str) and v.lower() != "all":
                    out.add(v)
            else:
                _collect_resource_types(v, out)
    elif isinstance(node, list):
        for v in node:
            _collect_resource_types(v, out)


def extract_yaml_check(path: Path) -> list[dict]:
    try:
        doc = yaml.safe_load(path.read_text(errors="ignore"))
    except yaml.YAMLError:
        return []
    if not isinstance(doc, dict):
        return []
    meta = doc.get("metadata") or {}
    cid = meta.get("id")
    if not (isinstance(cid, str) and cid.startswith("CKV")):
        return []
    res: set[str] = set()
    _collect_resource_types(doc.get("definition"), res)
    cat = meta.get("category")
    return [{
        "id": cid, "name": meta.get("name", ""),
        "categories": [str(cat).upper()] if cat else [],
        "resources": sorted(res), "guideline": meta.get("guideline"),
    }]


_SECRET_ID_RE = re.compile(r"CKV_SECRET_\d+")
_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=[^=]")


def _humanise(var: str) -> str:
    words = re.sub(r"_?(check_ids?|ids?)$", "", var, flags=re.I).replace("_", " ").strip().lower()
    return re.sub(r"\b(aws|uuid|gcp|azure)\b", lambda m: m.group(1).upper(), words) or "generic"


def extract_secrets(checkov_pkg: Path) -> list[dict]:
    """Every CKV_SECRET_* id referenced by the secrets scanner. Names come from the
    SECRET_TYPE_TO_ID table; ids that are only referenced through constants
    (e.g. RANDOM_HIGH_ENTROPY_CHECK_ID, secrets_in_uuid_form) are labelled from that constant."""
    named: dict[str, str] = {}
    runner = checkov_pkg / "secrets" / "runner.py"
    if runner.exists():
        for name, cid in re.findall(r"'([^']+)':\s*'(CKV_SECRET_\d+)'", runner.read_text()):
            named.setdefault(cid, name)
    derived: dict[str, str] = {}
    for f in sorted(checkov_pkg.rglob("*.py")):
        text = f.read_text(errors="ignore")
        if "CKV_SECRET_" not in text:
            continue
        for line in text.splitlines():
            ids = _SECRET_ID_RE.findall(line)
            if not ids:
                continue
            m = _ASSIGN_RE.match(line)
            for cid in ids:
                if cid not in named and not derived.get(cid):
                    derived[cid] = _humanise(m.group(1)) if m else ""
    out = []
    for cid in sorted({**named, **derived}, key=lambda x: int(x.rsplit("_", 1)[1])):
        label = named.get(cid) or derived.get(cid) or ""
        out.append({"id": cid, "name": f"Ensure no hard-coded secret: {label}" if label else "Ensure no hard-coded secret",
                    "categories": ["SECRETS"], "resources": [], "guideline": None, "_framework": "secrets"})
    return out


def parse_checkov(checkov_root: Path) -> tuple[list[dict], str, dict]:
    pkg = checkov_root / "checkov" if (checkov_root / "checkov").is_dir() else checkov_root
    version = "unknown"
    vfile = pkg / "version.py"
    if vfile.exists():
        m = re.search(r"version\s*=\s*['\"]([^'\"]+)", vfile.read_text())
        version = m.group(1) if m else version

    merged: dict[str, dict] = {}
    files: dict[str, set] = {"python": set(), "yaml": set()}

    def add(rec: dict, framework: str):
        cid = rec["id"]
        cur = merged.get(cid)
        if cur is None:
            prefix = re.match(r"^CKV2?_([A-Z0-9]+)_\d+$", cid).group(1)
            cur = merged[cid] = {
                "id": cid, "name": rec["name"], "categories": [], "resources": [], "frameworks": [],
                "provider": PROVIDERS.get(prefix, prefix.title()), "guideline": rec.get("guideline"),
            }
        if not cur["name"] or (framework == "terraform" and rec["name"]):
            cur["name"] = rec["name"] or cur["name"]
        for c in rec["categories"]:
            if c not in cur["categories"]:
                cur["categories"].append(c)
        for r in rec["resources"]:
            if r not in cur["resources"]:
                cur["resources"].append(r)
        fw = FRAMEWORK_LABELS.get(framework, framework.replace("_", " ").title())
        if fw not in cur["frameworks"]:
            cur["frameworks"].append(fw)
        cur["guideline"] = cur["guideline"] or rec.get("guideline")

    index = ClassIndex()
    for checks_dir in sorted(p for p in pkg.rglob("checks") if p.is_dir()):
        framework = checks_dir.relative_to(pkg).parts[0]
        if framework in ("common", "example_runner"):
            continue
        for f in checks_dir.rglob("*"):
            if f.suffix == ".py" and f.name != "__init__.py":
                index.add_file(f, framework)
            elif f.suffix in (".yaml", ".yml"):
                for rec in extract_yaml_check(f):
                    files["yaml"].add(f)
                    add(rec, framework)
    for framework, rec in index.checks():
        files["python"].add(rec.pop("_file"))
        add(rec, framework)
    for rec in extract_secrets(pkg):
        add(rec, rec.pop("_framework"))

    supply_chain_fw = {"GitHub", "GitHub Actions", "GitLab", "GitLab CI", "Bitbucket", "Bitbucket Pipelines",
                       "Azure Pipelines", "CircleCI", "Argo Workflows"}
    for c in merged.values():
        if not c["categories"]:
            if supply_chain_fw.intersection(c["frameworks"]):
                c["categories"] = ["SUPPLY_CHAIN"]
            elif c["provider"] == "Kubernetes":
                c["categories"] = ["KUBERNETES"]
            else:
                c["categories"] = ["GENERAL_SECURITY"]

    checks = sorted(merged.values(), key=lambda c: (c["provider"], _ckv_sort(c["id"])))
    for c in checks:
        c["resources"] = c["resources"][:40]
    stats = {
        "implementations": sum(len(c["frameworks"]) for c in checks),
        "python_files": len(files["python"]),
        "yaml_files": len(files["yaml"]),
    }
    return checks, version, stats


def _ckv_sort(cid: str):
    m = re.match(r"^CKV(2?)_([A-Z0-9]+)_(\d+)$", cid)
    return (m.group(1), m.group(2), int(m.group(3))) if m else (cid, "", 0)


def map_checks(checks: list[dict], rules: dict, known_controls: dict) -> dict:
    """Assign 800-53 controls to every check and record where each one came from:
    ``via: rule`` (keyword rule on the check name, high confidence) or
    ``via: category`` (Checkov category default, low confidence - never used for CSF links)."""
    compiled = []
    for r in rules.get("keyword_rules", []):
        compiled.append((
            r.get("label") or r["pattern"],
            r["pattern"],
            re.compile(r["pattern"], re.I),
            re.compile(r["exclude"], re.I) if r.get("exclude") else None,
            set(r.get("categories") or []),
            [norm_control(x) or x for x in r["controls"]],
        ))
    cat_map = {k: [norm_control(x) or x for x in v] for k, v in (rules.get("category_controls") or {}).items()}
    unknown: set[str] = set()
    for c in checks:
        mapping: dict[str, dict] = {}
        name = c["name"] or ""
        for label, pattern, rx, ex, cats, ctrls in compiled:
            if cats and not cats.intersection(c["categories"]):
                continue
            m = rx.search(name)
            if m and not (ex and ex.search(name)):
                for x in ctrls:
                    mapping.setdefault(x, {"control": x, "via": "rule", "confidence": "high", "rule": label,
                                           "pattern": pattern, "match": m.group(0).strip()})
        for cat in c["categories"]:
            for x in cat_map.get(cat, []):
                mapping.setdefault(x, {"control": x, "via": "category", "confidence": "low", "category": cat})
        unknown.update(x for x in mapping if x not in known_controls)
        c["mapping"] = sorted((v for x, v in mapping.items() if x in known_controls),
                              key=lambda v: control_sort_key(v["control"]))
        c["controls"] = [v["control"] for v in c["mapping"]]
    return {"unknown_controls": sorted(unknown),
            "rule_mapped": sum(1 for c in checks if any(v["via"] == "rule" for v in c["mapping"]))}


def validate_links(path: Path, functions: list[dict], controls: dict) -> None:
    """Sanity-check catalog/csf_check_links.yaml (it is read by the app at runtime)."""
    if not path.exists():
        log(f"! {path.relative_to(ROOT)} not found - no automatic requirement -> check links")
        return
    spec = yaml.safe_load(path.read_text()) or {}
    sids = [s["id"] for f in functions for c in f["categories"] for s in c["subcategories"]]
    none = [k for k, v in spec.items() if isinstance(v, dict) and v.get("checks") == "none"]
    missing = [s for s in sids if s not in spec]
    log(f"link specs: {len(spec) - len(none)} curated, {len(none)} organisational (checks: none), "
        f"{len(missing)} subcategories without a spec")
    if missing:
        log(f"! no link spec for: {', '.join(missing)}")
    bad = sorted({x for v in spec.values() if isinstance(v, dict) for x in v.get("controls") or []
                  if (norm_control(x) or x) not in controls})
    if bad:
        log(f"! unknown controls in link specs: {', '.join(bad)}")
    for k, v in spec.items():
        for key in ("include", "exclude"):
            if isinstance(v, dict) and v.get(key):
                try:
                    re.compile(v[key])
                except re.error as e:
                    log(f"! {k}.{key} is not a valid regex: {e}")


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--refresh", action="store_true", help="re-download NIST sources")
    ap.add_argument("--checkov-path", default=str(ROOT / "references" / "checkov-main"))
    ap.add_argument("--out", default=str(DATA / "catalog.json"))
    args = ap.parse_args()

    print("NIST CSF 2.0")
    csf_xlsx = download(CSF_XLSX_URL, RAW / "csf2_reference_tool.xlsx", args.refresh)
    functions = parse_csf(csf_xlsx)

    print("NIST SP 800-53 Rev 5")
    sp = download(SP80053_URL, RAW / "sp800-53r5_catalog.json", args.refresh)
    families, controls, sp_version = parse_80053(sp)
    log(f"{len(controls)} controls/enhancements across {len(families)} families (v{sp_version})")

    print("Review questions")
    questions = yaml.safe_load((CATALOG_SRC / "csf_questions.yaml").read_text()) or {}
    n_sub = missing = 0
    for f in functions:
        for c in f["categories"]:
            for s in c["subcategories"]:
                n_sub += 1
                q = questions.get(s["id"]) or {}
                if not q:
                    missing += 1
                s["question"] = q.get("question") or f"How does the solution ensure that: {s['text'][0].lower() + s['text'][1:]}?"
                s["scope"] = q.get("scope", "project")
                s["baseline"] = bool(q.get("baseline", False))
                s["triggers"] = q.get("triggers", [])
                s["controls"] = [x for x in s["controls"] if x in controls]
    log(f"{n_sub} subcategories, {n_sub - missing} with curated questions")

    print("Checkov")
    ck_path = Path(args.checkov_path).expanduser()
    if not ck_path.exists():
        print(f"  ! Checkov source not found at {ck_path}", file=sys.stderr)
        return 1
    checks, ck_version, ck_stats = parse_checkov(ck_path)
    rules = yaml.safe_load((CATALOG_SRC / "checkov_nist_rules.yaml").read_text()) or {}
    report = map_checks(checks, rules, controls)
    log(f"{len(checks)} unique checks, {ck_stats['implementations']} per-framework implementations "
        f"from {ck_stats['python_files']} python + {ck_stats['yaml_files']} yaml check files (checkov {ck_version})")
    log(f"{sum(1 for c in checks if c['provider'] == 'Secrets')} secret checks")
    if report["unknown_controls"]:
        log(f"ignored unknown/withdrawn controls in rules: {', '.join(report['unknown_controls'])}")
    log(f"{report['rule_mapped']}/{len(checks)} checks mapped to 800-53 by at least one keyword rule")
    validate_links(CATALOG_SRC / "csf_check_links.yaml", functions, controls)

    catalog = {
        "meta": {
            "built_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "csf_version": "2.0",
            "sp80053_version": sp_version,
            "checkov_version": ck_version,
            "counts": {
                "functions": len(functions),
                "categories": sum(len(f["categories"]) for f in functions),
                "subcategories": n_sub,
                "controls": len(controls),
                "checks": len(checks),
                "check_implementations": ck_stats["implementations"],
            },
        },
        "families": families,
        "functions": functions,
        "controls": controls,
        "checks": checks,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(catalog, ensure_ascii=False, separators=(",", ":")))
    print(f"\nWrote {out.relative_to(ROOT)} ({out.stat().st_size / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
