"""Threat-model generators: one LLM call per artifact, validated and normalised in code.

Every generator has the signature (llm, ctx, prior, instructions, refine) -> data, where ``ctx`` comes from
``context.build_context`` and ``prior`` maps each artifact kind to its stored artifact (or None). Refine mode
sends the current artifact back with the reviewer's instructions so the model improves it and keeps ids stable.
The attack tree, mitigations, DREAD and test cases are derived from the threat model and require one.
"""
from __future__ import annotations

import json

from ..ai.providers import LLM, Attachment, ProviderError
from ..catalog import get_catalog
from ..library import mitigation_library
from .context import render_context
from .normalize import (
    normalize_attack_tree, normalize_dfd, normalize_dread, normalize_mitigations, normalize_test_cases,
    normalize_threat_model,
)
from .prompts import (
    AI_GUIDANCE, ATTACK_TREE_SYSTEM, DFD_IMAGE_SYSTEM, DFD_SYSTEM, DREAD_SYSTEM, MITIGATIONS_SYSTEM,
    TEST_CASES_SYSTEM, THREAT_SYSTEM,
)
from .references import cards, prompt_section, select_cards

FIELD_SCHEMA = {
    "owasp_top10": '"owasp_top10": "A01:2025" or null, ',
    "owasp_llm": '"owasp_llm": "LLM01" or null, ',
    "owasp_asi": '"owasp_asi": "ASI01" or null, ',
    "mitre_attack": '"mitre_attack": ["T1190"], ',
    "mitre_atlas": '"mitre_atlas": ["AML.T0051"], ',
}
THREAT_KEYS = ("id", "category", "title", "component", "scenario", "impact", "likelihood_hint", "owasp_top10",
               "owasp_llm", "owasp_asi", "evidence")


class MissingThreatModel(ValueError):
    pass


def _data(prior: dict, kind: str) -> dict | None:
    art = prior.get(kind)
    return art["data"] if art and isinstance(art.get("data"), dict) else None


def require_threats(prior: dict) -> list[dict]:
    threats = (_data(prior, "threat_model") or {}).get("threats") or []
    if not threats:
        raise MissingThreatModel("Generate the threat model first.")
    return threats


def _threat_section(threats: list[dict]) -> str:
    return "\n\n## Threat model\n" + json.dumps(
        [{k: t[k] for k in THREAT_KEYS if t.get(k)} for t in threats], indent=1)


def _extras(instructions: str, previous: dict | None, what: str) -> str:
    out = ""
    if previous:
        shown = {k: v for k, v in previous.items() if k != "mermaid"}
        out += (f"\n\n## Current {what} (refine it)\n{json.dumps(shown, indent=1)}\n\n"
                f"Improve this {what} rather than starting again: keep the ids of entries you retain, give new "
                f"entries new ids continuing the sequence, and remove entries only when the context or the "
                f"reviewer's instructions show they do not apply.")
    if instructions.strip():
        out += "\n\n## Reviewer instructions (follow these)\n" + instructions.strip()[:4000]
    return out


def _guidance(kind: str, app_type: str) -> str:
    g = AI_GUIDANCE.get(kind, {})
    if app_type == "agentic":
        return g.get("genai", "") + g.get("agentic", "")
    return g.get(app_type, "")


def _require(data: dict, key: str, what: str) -> dict:
    if not data.get(key):
        raise ProviderError(f"The model returned no usable {what}; try again or add reviewer instructions.")
    return data


# --------------------------------------------------------------------------- generators
async def generate_threat_model(llm: LLM, ctx: dict, prior: dict, instructions: str = "",
                                refine: bool = False) -> dict:
    names = select_cards(ctx["app_type"])
    fields = dict.fromkeys(f for n in names for f in cards()[n]["adds_fields"])
    system = THREAT_SYSTEM.replace("{fields}", "".join(FIELD_SCHEMA[f] for f in fields if f in FIELD_SCHEMA))
    system += prompt_section(names)
    current = _data(prior, "threat_model")
    previous = None
    if refine and current:
        previous = {**current, "threats": [{k: v for k, v in t.items() if k != "item_id"}
                                           for t in current.get("threats") or []]}
    raw = await llm.complete_json(system, render_context(ctx) + _extras(instructions, previous, "threat model"))
    data = normalize_threat_model(raw, app_type=ctx["app_type"], cards=names,
                                  csf_ids=set(get_catalog().subcategories), prior=current, by_id=bool(previous),
                                  known_files=set(ctx.get("known_files") or ()))
    data = _require(data, "threats", "threats")
    if ctx.get("inputs"):  # what this run was based on, shown with the result
        data["inputs"] = {**ctx["inputs"], "source": (ctx.get("source") or {}).get("stats")}
    return data


async def generate_attack_tree(llm: LLM, ctx: dict, prior: dict, instructions: str = "",
                               refine: bool = False) -> dict:
    threats = require_threats(prior)
    previous = _data(prior, "attack_tree") if refine else None
    user = render_context(ctx, source=False) + _threat_section(threats) + _extras(instructions, previous,
                                                                                   "attack tree")
    raw = await llm.complete_json(ATTACK_TREE_SYSTEM + _guidance("attack_tree", ctx["app_type"]), user)
    return _require(normalize_attack_tree(raw, {t["id"] for t in threats}), "nodes", "attack tree")


async def generate_dfd(llm: LLM, ctx: dict, prior: dict, instructions: str = "", refine: bool = False) -> dict:
    previous = _data(prior, "dfd") if refine else None
    raw = await llm.complete_json(DFD_SYSTEM, render_context(ctx) + _extras(instructions, previous,
                                                                             "data flow diagram"))
    return _require(normalize_dfd(raw), "nodes", "data flow diagram")


async def dfd_from_image(llm: LLM, image: Attachment) -> dict:
    user = f"Extract the data flow diagram from the attached image ({image.name})."
    raw = await llm.complete_json(DFD_IMAGE_SYSTEM, user, [image])
    return _require(normalize_dfd(raw), "nodes", "diagram elements")


async def generate_mitigations(llm: LLM, ctx: dict, prior: dict, instructions: str = "",
                               refine: bool = False) -> dict:
    threats = require_threats(prior)
    lib = mitigation_library()
    current = _data(prior, "mitigations")
    previous = None
    if refine and current:
        previous = {"mitigations": [{k: v for k, v in m.items() if k != "mitigation_id"}
                                    for m in current.get("mitigations") or []]}
    library = "\n".join(f"{k}: {v['title']} [{', '.join(v['nist'])}]" for k, v in lib.items())
    user = (render_context(ctx, documents=False) + _threat_section(threats)
            + "\n\n## Mitigating-control library (id: title [SP 800-53 Rev 5])\n" + library
            + _extras(instructions, previous, "mitigations"))
    raw = await llm.complete_json(MITIGATIONS_SYSTEM + _guidance("mitigations", ctx["app_type"]), user)
    data = normalize_mitigations(raw, threat_ids={t["id"] for t in threats}, cat=get_catalog(), lib=lib,
                                 register=ctx["mitigations"], prior=current, by_id=bool(previous))
    return _require(data, "mitigations", "mitigations")


async def generate_dread(llm: LLM, ctx: dict, prior: dict, instructions: str = "", refine: bool = False) -> dict:
    threats = require_threats(prior)
    previous = _data(prior, "dread") if refine else None
    user = render_context(ctx, documents=False) + _threat_section(threats) + _extras(instructions, previous,
                                                                                      "DREAD assessment")
    raw = await llm.complete_json(DREAD_SYSTEM + _guidance("dread", ctx["app_type"]), user)
    return _require(normalize_dread(raw, {t["id"] for t in threats}), "assessments", "DREAD scores")


async def generate_test_cases(llm: LLM, ctx: dict, prior: dict, instructions: str = "",
                              refine: bool = False) -> dict:
    threats = require_threats(prior)
    previous = _data(prior, "test_cases") if refine else None
    user = render_context(ctx, documents=False) + _threat_section(threats) + _extras(instructions, previous,
                                                                                      "test cases")
    raw = await llm.complete_json(TEST_CASES_SYSTEM + _guidance("test_cases", ctx["app_type"]), user)
    return _require(normalize_test_cases(raw, {t["id"] for t in threats}), "test_cases", "test cases")


GENERATORS = {
    "threat_model": generate_threat_model, "attack_tree": generate_attack_tree, "dfd": generate_dfd,
    "mitigations": generate_mitigations, "dread": generate_dread, "test_cases": generate_test_cases,
}
