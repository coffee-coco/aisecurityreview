"""In-memory knowledge base: CSF 2.0 -> SP 800-53 Rev 5 -> Checkov checks."""
from __future__ import annotations

import json
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

import yaml

from .config import CATALOG_PATH, CHECK_LINKS_PATH
from .frameworks import register_frameworks

# Review "platforms" -> catalog providers (lower-case keys; exact provider names also match).
PROVIDER_ALIASES: dict[str, tuple[str, ...]] = {
    "amazon web services": ("AWS",), "amazon": ("AWS",), "aws cloud": ("AWS",), "cloudformation": ("AWS",),
    "cdk": ("AWS",), "sam": ("AWS",), "serverless": ("AWS",),
    "microsoft azure": ("Azure",), "azure cloud": ("Azure",), "azurerm": ("Azure",), "arm": ("Azure",),
    "bicep": ("Azure",),
    "google cloud": ("GCP",), "google cloud platform": ("GCP",), "google": ("GCP",), "gcloud": ("GCP",),
    "k8s": ("Kubernetes",), "kube": ("Kubernetes",), "helm": ("Kubernetes",), "kustomize": ("Kubernetes",),
    "openshift": ("Kubernetes",), "eks": ("AWS", "Kubernetes"), "aks": ("Azure", "Kubernetes"),
    "gke": ("GCP", "Kubernetes"),
    "dockerfile": ("Docker",), "containers": ("Docker",), "container": ("Docker",),
    "github actions": ("GitHub Actions",), "gha": ("GitHub Actions",), "gitlab ci": ("GitLab CI",),
    "oci": ("Oracle Cloud",), "oracle": ("Oracle Cloud",), "alicloud": ("Alibaba Cloud",),
    "alibaba": ("Alibaba Cloud",), "digital ocean": ("DigitalOcean",), "ibm": ("IBM Cloud",),
    "openapi": ("OpenAPI",), "swagger": ("OpenAPI",), "secrets": ("Secrets",),
}
IAC_ALIASES = {"terraform", "opentofu", "tofu", "iac", "infrastructure as code", "hcl"}
GENERIC_PROVIDERS = {"Secrets"}


def base_control(cid: str) -> str:
    return cid.split("(")[0]


def _control_match(control: str, wanted: list[str]) -> bool:
    """'SC-28' in a link spec matches SC-28 and its enhancements; 'CM-7(5)' matches exactly."""
    return any(control == w if "(" in w else base_control(control) == w for w in wanted)


def load_link_specs(path: Path) -> dict[str, dict]:
    """Curated requirement -> check link specs (catalog/csf_check_links.yaml)."""
    if not path.exists():
        return {}
    out: dict[str, dict] = {}
    for rid, spec in (yaml.safe_load(path.read_text()) or {}).items():
        if not isinstance(spec, dict):
            continue
        none = spec.get("checks") == "none"
        out[str(rid)] = {
            "why": str(spec.get("why") or ""),
            "none": none,
            "controls": [str(x).upper() for x in spec.get("controls") or []],
            "categories": {str(x).upper() for x in spec.get("categories") or []},
            "include": re.compile(spec["include"], re.I) if spec.get("include") else None,
            "exclude": re.compile(spec["exclude"], re.I) if spec.get("exclude") else None,
            "checks": [] if none else [str(x) for x in spec.get("checks") or []],
        }
    return out


class Catalog:
    def __init__(self, path: Path):
        if not path.exists():
            raise FileNotFoundError(
                f"{path} not found - run `python scripts/build_catalog.py` to build the NIST/Checkov catalog."
            )
        data = json.loads(path.read_text())
        self.meta: dict = data["meta"]
        self.families: dict[str, str] = data["families"]
        self.functions: list[dict] = data["functions"]
        self.controls: dict[str, dict] = data["controls"]
        self.checks: list[dict] = data["checks"]
        self.checks_by_id = {c["id"]: c for c in self.checks}

        self.subcategories: dict[str, dict] = {}
        self.order: dict[str, int] = {}
        for f in self.functions:
            for c in f["categories"]:
                for s in c["subcategories"]:
                    s["function_id"], s["function_title"] = f["id"], f["title"]
                    s["category_id"], s["category_title"] = c["id"], c["title"]
                    self.order[s["id"]] = len(self.order)
                    self.subcategories[s["id"]] = s
        register_frameworks(self)

        for chk in self.checks:
            chk["_bases"] = sorted({base_control(x) for x in chk["controls"]})
            chk["_haystack"] = " ".join(
                [chk["name"].lower()] + [r.lower().replace("_", " ").replace("::", " ") for r in chk["resources"]]
            )
            # Catalogs built before provenance was recorded: treat every control as rule-derived.
            mapping = chk["mapping"] if "mapping" in chk else [
                {"control": x, "via": "rule", "rule": "legacy mapping"} for x in chk["controls"]]
            chk["_rules"] = [m for m in mapping if m.get("via") == "rule"]
            chk["_resources"] = " ".join(r.lower() for r in chk["resources"])
        self.providers = Counter(c["provider"] for c in self.checks)
        self.iac_providers = sorted({c["provider"] for c in self.checks if "Terraform" in c["frameworks"]})
        self.link_specs = load_link_specs(CHECK_LINKS_PATH)
        self._auto: dict[str, dict[str, dict]] = {}

    # ------------------------------------------------------------------ helpers
    def control_brief(self, cid: str) -> dict:
        c = self.controls.get(cid, {})
        return {"id": cid, "title": c.get("title", ""), "family": c.get("family", cid[:2]),
                "family_title": self.families.get(c.get("family", cid[:2]), "")}

    def public_check(self, chk: dict) -> dict:
        out = {k: v for k, v in chk.items() if not k.startswith("_")}
        if "mapping" in out:
            out["mapping"] = [{k: v for k, v in m.items() if k != "pattern"} for m in out["mapping"]]
        return out

    def subcategory_brief(self, sid: str) -> dict:
        s = self.subcategories[sid]
        policy = self.link_policy(sid)
        return {
            "id": s["id"], "text": s["text"], "question": s["question"], "scope": s["scope"],
            "function_id": s["function_id"], "function_title": s["function_title"],
            "category_id": s["category_id"], "category_title": s["category_title"],
            "controls": [self.control_brief(x) for x in s["controls"]],
            "examples": s["examples"],
            "link_policy": policy["policy"], "link_why": policy["why"],
        }

    def tree(self) -> list[dict]:
        out = []
        for f in self.functions:
            cats = []
            for c in f["categories"]:
                subs = []
                for s in c["subcategories"]:
                    subs.append({
                        "id": s["id"], "text": s["text"], "question": s["question"], "scope": s["scope"],
                        "baseline": s["baseline"], "examples": s["examples"],
                        "controls": [self.control_brief(x) for x in s["controls"]],
                        "check_count": len(self.auto_links(s["id"])),
                        "link_policy": self.link_policy(s["id"])["policy"],
                    })
                cats.append({"id": c["id"], "title": c["title"], "text": c["text"], "subcategories": subs})
            out.append({"id": f["id"], "title": f["title"], "text": f["text"], "categories": cats})
        return out

    # ------------------------------------------------------------------ requirement -> check links
    def link_policy(self, rid: str) -> dict:
        """'none' = organisational (no IaC checks expected), 'curated' = link spec, 'unmapped' = user links only."""
        spec = self.link_specs.get(rid)
        if spec is None:
            return {"policy": "unmapped", "why": ""}
        return {"policy": "none" if spec["none"] else "curated", "why": spec["why"]}

    def auto_links(self, rid: str) -> dict[str, dict]:
        """Automatic links for a requirement: {check_id: {strength, reason, controls}}."""
        if rid not in self._auto:
            self._auto[rid] = self._compute_links(rid)
        return self._auto[rid]

    def _compute_links(self, rid: str) -> dict[str, dict]:
        spec = self.link_specs.get(rid)
        if not spec or spec["none"] or rid not in self.subcategories:
            return {}
        links: dict[str, dict] = {}
        for cid in spec["checks"]:
            if cid in self.checks_by_id:
                links[cid] = {"strength": "strong", "controls": [], "reason": "Curated for this requirement"}
        inc, exc, wanted, cats = spec["include"], spec["exclude"], spec["controls"], spec["categories"]
        for chk in self.checks:
            if chk["id"] in links or (exc and exc.search(chk["name"])):
                continue
            m = inc.search(chk["name"]) if inc else None
            if inc and not m:
                continue
            hits = [x for x in chk["_rules"] if _control_match(x["control"], wanted)]
            if hits:
                links[chk["id"]] = {"strength": "strong", "controls": [x["control"] for x in hits],
                                    "reason": self._rule_reason(hits)}
            elif cats & set(chk["categories"]):
                cat = sorted(cats & set(chk["categories"]))[0]
                links[chk["id"]] = {"strength": "strong" if m else "related", "controls": [],
                                    "reason": f"Checkov category {cat}" + (f", name matches “{m.group(0)}”" if m else "")}
            elif m and not wanted and not cats:
                links[chk["id"]] = {"strength": "related", "controls": [], "reason": f"Name matches “{m.group(0)}”"}
        return links

    def _rule_reason(self, hits: list[dict]) -> str:
        by_rule: dict[str, list[dict]] = {}
        for x in hits:
            by_rule.setdefault(x.get("rule") or "keyword rule", []).append(x)
        parts = []
        for rule, xs in by_rule.items():
            title = self.controls.get(xs[0]["control"], {}).get("title", "")
            match = next((x["match"] for x in xs if x.get("match")), "")
            parts.append(f"{', '.join(x['control'] for x in xs)}{f' ({title})' if title else ''} via rule “{rule}”"
                         + (f" - matched “{match}”" if match else ""))
        return "; ".join(parts)

    # ------------------------------------------------------------------ check ranking
    def subcategory_checks(
        self,
        sid: str,
        providers: list[str] | None = None,
        services: list[str] | None = None,
        query: str | None = None,
        overrides: list[dict] | None = None,
        keep_excluded: bool = False,
    ) -> list[dict]:
        """Checkov checks linked to a requirement.

        Merge order: curated automatic links (catalog/csf_check_links.yaml) -> global
        reviewer include/exclude -> review-scoped include/exclude. ``overrides`` rows have
        check_id, action ('include'|'exclude'), review_id (None = global) and note.
        The provider filter never hides checks a reviewer pinned to the review itself.
        """
        if sid not in self.subcategories:
            return []
        auto = self.auto_links(sid)
        links = {cid: {**link, "source": "auto", "auto": True} for cid, link in auto.items()}
        for o in sorted(overrides or [], key=lambda o: o.get("review_id") is not None):
            cid = o["check_id"]
            if cid not in self.checks_by_id:
                continue
            scope = "global" if o.get("review_id") is None else "review"
            note = o.get("note") or ""
            if o["action"] == "include":
                links[cid] = {"strength": "strong", "controls": links.get(cid, {}).get("controls", []),
                              "reason": "Added by reviewer " + ("for this review" if scope == "review" else "for all reviews"),
                              "source": scope, "note": note, "auto": cid in auto}
            elif cid in links:
                links[cid] = {**links[cid], "excluded": scope, "note": note}
            else:
                links[cid] = {"strength": "related", "controls": [], "reason": "Not linked automatically",
                              "source": scope, "note": note, "auto": False, "excluded": scope}
        prov = {p.lower() for p in providers or []}
        svc = [x.lower().strip() for x in services or [] if x.strip()]
        q = (query or "").lower().strip()
        out = []
        for cid, link in links.items():
            chk = self.checks_by_id[cid]
            if link.get("excluded") and not keep_excluded:
                continue
            if prov and link["source"] != "review" and chk["provider"].lower() not in prov:
                continue
            if q and q not in chk["_haystack"] and q not in cid.lower():
                continue
            stack = [x for x in svc if x in chk["_haystack"]]
            score = (1.0 if link["strength"] == "strong" else 0.5) + 0.1 * len(link["controls"]) + (1.0 if stack else 0)
            out.append({
                **self.public_check(chk),
                "score": round(score, 3), "strength": link["strength"], "reason": link["reason"],
                "source": link["source"], "auto": link["auto"], "excluded": link.get("excluded"),
                "note": link.get("note", ""), "shared_controls": link["controls"], "stack_match": stack,
            })
        out.sort(key=lambda c: (bool(c["excluded"]), c["strength"] != "strong", -c["score"], c["provider"], c["id"]))
        return out

    def find_checks(self, query: str = "", provider: str = "", control: str = "", resource: str = "") -> list[dict]:
        q, res, ctl = query.lower().strip(), resource.lower().strip(), control.upper().strip()
        out = []
        for chk in self.checks:
            if provider and chk["provider"] != provider:
                continue
            if ctl and not (ctl in chk["controls"] or base_control(ctl) in chk["_bases"]):
                continue
            if res and res not in chk["_resources"]:
                continue
            if q and q not in chk["_haystack"] and q not in chk["id"].lower():
                continue
            out.append(chk)
        return out

    def search_checks(self, query: str = "", provider: str = "", control: str = "", limit: int = 200,
                      resource: str = "", offset: int = 0) -> list[dict]:
        hits = self.find_checks(query, provider, control, resource)
        return [self.public_check(c) for c in hits[max(offset, 0):max(offset, 0) + limit]]

    def normalise_providers(self, technologies: list[str] | None) -> tuple[list[str], bool]:
        """Map review platforms to catalog providers. Returns (providers, fallback) - fallback=True
        (and no providers = all platforms) when nothing but generic providers such as Secrets matched."""
        names = {p.lower(): p for p in self.providers}
        out: list[str] = []
        for t in technologies or []:
            key = re.sub(r"\s+", " ", str(t).strip().lower())
            if key in IAC_ALIASES:
                hits: tuple[str, ...] | list[str] = self.iac_providers
            elif key in names:
                hits = (names[key],)
            else:
                hits = PROVIDER_ALIASES.get(key, ())
            out.extend(h for h in hits if h in self.providers and h not in out)
        if not any(p not in GENERIC_PROVIDERS for p in out):
            return [], True
        return out, False


@lru_cache(maxsize=1)
def get_catalog() -> Catalog:
    return Catalog(CATALOG_PATH)
