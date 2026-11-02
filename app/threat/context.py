"""Review context for threat-model prompts and application-type detection.

Pulls together everything the review already knows: intake, profile, the AI design analysis, uploaded
document text (bounded by the provider's context budget), the code review inventory and top findings,
scoped NIST CSF requirements, the risk and control registers, and any existing data flow diagram.
"""
from __future__ import annotations

import json

from .. import db
from ..ai.providers import LLM
from ..api import _get_review
from ..api_files import _code_roots, _docs, _load_doc_inputs
from ..catalog import get_catalog
from ..code.workspace import build_inventory, iter_sources
from ..items import load_items, load_mitigations
from ..profile import profile_summary
from . import store
from .source import assess_inputs, gather_source

AGENT_DEPS = ("langchain", "@langchain", "langgraph", "@langchain/langgraph", "crewai", "autogen", "pyautogen", "ag2",
              "semantic-kernel", "llama-index", "llama_index", "llamaindex", "smolagents", "pydantic-ai", "mcp",
              "fastmcp", "@modelcontextprotocol", "openai-agents", "@openai/agents", "haystack-ai", "dspy")
LLM_DEPS = ("openai", "anthropic", "@anthropic-ai", "google-generativeai", "google-genai", "@google/generative-ai",
            "@google/genai", "mistralai", "@mistralai", "cohere", "litellm", "ollama", "groq", "transformers",
            "sentence-transformers", "huggingface-hub", "chromadb", "pinecone", "weaviate-client", "faiss-cpu")
AGENT_FRAMEWORKS = {"LangChain", "CrewAI", "AutoGen", "Model Context Protocol", "Semantic Kernel", "LlamaIndex"}


def _dep_hit(deps: list[str], names: tuple[str, ...]) -> bool:
    return any(d == n or d.startswith((n + "-", n + "/", n + "_", n + "[")) for d in deps for n in names)


def detect_app_type(review: dict) -> str:
    """web | genai | agentic, from the profile, design analysis and code inventory."""
    code = review.get("code_review") or {}
    inv = code.get("inventory") or {}
    systems = set(review.get("system_types") or []) | set(code.get("system_types") or []) \
        | set((review.get("design") or {}).get("system_types") or [])
    deps = [str(d).lower() for d in inv.get("dependencies") or []]
    fws = set(inv.get("ai_frameworks") or [])
    if "ai_agent" in systems or fws & AGENT_FRAMEWORKS or _dep_hit(deps, AGENT_DEPS):
        return "agentic"
    if review.get("uses_ai") or "ai_ml" in systems or fws or _dep_hit(deps, LLM_DEPS):
        return "genai"
    return "web"


def _code_brief(code: dict) -> dict:
    inv = code.get("inventory") or {}
    out = {
        "summary": code.get("summary") or "",
        "architecture": code.get("architecture") or {},
        "languages": [l["name"] for l in inv.get("languages") or []][:8],
        "frameworks": inv.get("frameworks") or [],
        "ai_frameworks": inv.get("ai_frameworks") or [],
        "dependencies": (inv.get("dependencies") or [])[:150],
        "http_routes": [f"{r['method']} {r['route']}" for r in (inv.get("routes") or [])[:60]],
        "top_findings": [f"[{f['severity']}] {f['title']}" + (f" ({f['evidence'][0]['file']})" if f.get("evidence")
                                                               else "") for f in (code.get("findings") or [])[:25]],
        "open_questions": code.get("open_questions") or [],
    }
    return {k: v for k, v in out.items() if v}


def _code_inventory(review: dict, roots: list) -> tuple[dict, bool]:
    """The stored code-review inventory when it matches the linked sources, else a fresh one (cheap, no AI)."""
    code = review.get("code_review") or {}
    inv = code.get("inventory") or {}
    if inv.get("file_list") and set(code.get("sources") or []) == {label for label, _ in roots}:
        return inv, False
    return build_inventory(roots), True


def build_context(review_id: int, llm: LLM | None) -> dict:
    """Blocking (reads the linked source files); call it with ``asyncio.to_thread`` from async code."""
    cat = get_catalog()
    with db.tx() as conn:
        review = _get_review(conn, review_id)
        items = load_items(conn, review_id, cat)
        mits = load_mitigations(conn, review_id)
        dfd = store.get_artifact(conn, review_id, "dfd")
        code_docs = _docs(conn, review_id, ("code",))
        docs_count = len(_docs(conn, review_id, ("document", "image")))
    ctx_chars = llm.context_chars if llm else 60_000
    roots = _code_roots(review_id)
    source = None
    if roots:
        inv, fresh = _code_inventory(review, roots)
        if fresh:  # code was linked after (or without) a code review: use the new inventory everywhere
            review = {**review, "code_review": {**(review.get("code_review") or {}), "inventory": inv}}
        hit = {e["file"] for f in (review.get("code_review") or {}).get("findings") or []
               for e in f.get("evidence") or []}
        source = gather_source(inv, dict(iter_sources(roots)), int(ctx_chars * 0.4), hit)
    app_type = detect_app_type(review)
    design = review.get("design") or {}
    code = review.get("code_review") or {}
    brief: dict = {
        "title": review.get("title"),
        "type": "New initiative" if review.get("change_type") == "new" else "Change to existing system",
        "description": review.get("description"),
        "tech_stack": review.get("tech_stack"),
        "business_unit": review.get("business_unit"),
        "profile": profile_summary(review),
        "application_type": app_type,
    }
    if design.get("summary"):
        brief["design_analysis"] = {k: design[k] for k in (
            "summary", "components", "data_flows", "trust_boundaries", "integrations", "notable_concerns",
            "open_questions") if design.get(k)}
    if code.get("inventory") or code.get("summary"):
        brief["code_review"] = _code_brief(code)
    csf_scope = [i["subcategory_id"] for i in items if i["subcategory_id"]]
    if csf_scope:
        brief["scoped_csf_requirements"] = [
            {"id": i["subcategory_id"], "outcome": (i.get("subcategory") or {}).get("text", ""), "status": i["status"]}
            for i in items if i["subcategory_id"]][:80]
    risks = [{"title": i["display_title"], "risk": (i["risk"] or "")[:300], "rating": i["risk_rating"]}
             for i in items if i["is_risk"]]
    if risks:
        brief["existing_risks"] = risks[:40]
    if mits:
        brief["control_register"] = [{"title": m["title"], "state": m["state"], "status": m["status"],
                                      "nist": m["nist"][:6]} for m in mits][:60]
    if dfd and (dfd["data"].get("nodes") or []):
        brief["data_flow_diagram"] = {k: dfd["data"].get(k) for k in ("nodes", "edges", "trust_boundaries")}
    head = json.dumps(brief, indent=1, default=str)
    code_used = source["stats"]["chars"] if source else 0
    budget = max(int(ctx_chars * 0.15), int(ctx_chars * 0.6) - len(head) - code_used)
    parts, used = [], 0
    for d in _load_doc_inputs(review_id):
        text = d.get("text") or ""
        if not text or used >= budget:
            continue
        chunk = f"\n\n### Document: {d['filename']}\n{text}"
        if used + len(chunk) > budget:
            chunk = chunk[:max(0, budget - used)] + "\n[... truncated ...]"
        parts.append(chunk)
        used += len(chunk)
    inputs = assess_inputs(review, code_docs, docs_count, bool(brief.get("data_flow_diagram")), source)
    return {"review": review, "app_type": app_type, "brief": brief, "documents": "".join(parts),
            "csf_scope": csf_scope, "items": items, "mitigations": mits, "source": source, "inputs": inputs,
            "known_files": [f["path"] for f in (code.get("inventory") or {}).get("file_list") or []] if source else []}


def render_context(ctx: dict, documents: bool = True, source: bool | None = None) -> str:
    """``source`` (the real code) defaults to following ``documents``."""
    out = "## Review context\n" + json.dumps(ctx["brief"], indent=1, default=str)
    if documents and ctx["documents"]:
        out += "\n\n## Architecture and design documents" + ctx["documents"]
    src = ctx.get("source")
    if (documents if source is None else source) and src and src["text"]:
        st = src["stats"]
        out += (f"\n\n## Source code ({st['files_included']} of {st['files_total']} files shown, highest-value "
                f"first; line numbers precede each line)\n### File tree\n" + "\n".join(src["tree"])
                + "\n\n### Files" + src["text"])
    return out
