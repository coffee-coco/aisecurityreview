---
name: agentic
title: OWASP Top 10 for Agentic Applications
when_to_load: |
  Load in addition to the genai card when the system uses an agent framework
  (langchain, langgraph, crewai, autogen, pydantic-ai, smolagents, llama-index
  agents, MCP), implements a tool-use or function-calling loop, coordinates
  multiple agents, or persists agent memory across sessions.
app_types: [agentic]
adds_fields: [owasp_asi]
source: https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
version: 2025
---

# OWASP Top 10 for Agentic Applications — Reference Card

The system uses agent patterns. In addition to traditional threats and the LLM threats from the genai card, you MUST consider the agentic threats below and place each under one of the six threat categories. A single threat may carry both an `owasp_llm` and an `owasp_asi` code.

## Architectural pattern detection

Before generating threats, determine which of these patterns are present. For each pattern detected, include threats specific to it:

1. RAG / RETRIEVAL (RAG, vector databases, embeddings, knowledge bases, document ingestion, Pinecone, Weaviate, ChromaDB, FAISS):
   - vector store poisoning (malicious documents injected into the knowledge base)
   - embedding manipulation (adversarial content designed to surface in retrieval)
   - cross-tenant data leakage if multi-tenant RAG is implied
   - stale or poisoned index threats if incremental updates are mentioned
2. MULTI-AGENT (orchestration, agent-to-agent communication, CrewAI, AutoGen, LangGraph, swarms, hierarchical agents):
   - agent impersonation, inter-agent message tampering, malicious agent injection
   - goal conflicts and unintended emergent behaviour, cascading failures across agent chains
3. CODE EXECUTION / SANDBOXING (code generation or execution, REPL, interpreter, containers):
   - sandbox escape and container breakout, resource exhaustion via generated code
   - filesystem/network access beyond intended scope, malicious dependency installation
4. TOOL / PLUGIN ECOSYSTEMS (MCP servers, plugins, function calling, external APIs):
   - malicious tool providers returning poisoned data, tool impersonation
   - supply-chain attacks via compromised tool packages, confused-deputy misuse of legitimate tools
5. PERSISTENT MEMORY / STATE (conversation history, long-term memory, cross-session context):
   - memory poisoning, cross-session leakage, extraction of other users' context
   - gradual state manipulation altering agent goals
6. FINE-TUNED / CUSTOM MODELS (fine-tuning, LoRA, adapters, proprietary models):
   - training data poisoning, backdoor triggers, compromised base model or pipeline, model IP extraction

## Agentic threats by category

SPOOFING:
- ASI07 (Insecure Inter-Agent Communication): spoofed agent identities, fake agents joining multi-agent systems
- ASI04 (Agentic Supply Chain Vulnerabilities): malicious MCP servers or tool providers impersonating legitimate ones
- fake tool responses injected into agent context

TAMPERING:
- ASI06 (Memory and Context Poisoning): RAG poisoning, manipulated memory/state, cross-session contamination
- ASI01 (Agent Goal Hijack): injection via poisoned documents, emails or user input that alters agent objectives
- ASI07: message tampering in inter-agent channels

REPUDIATION:
- ASI09 (Human-Agent Trust Exploitation): actions that circumvent audit by exploiting user over-trust
- untraceable autonomous decisions and gaps in decision audit logs

INFORMATION DISCLOSURE:
- ASI06: context window leakage from previous sessions, cross-tenant exposure
- ASI01: injection leading to data exfiltration via crafted outputs
- credentials or data exposed through tool-call logs or persistent memory

DENIAL OF SERVICE:
- ASI08 (Cascading Failures): error propagation across agent chains causing system-wide outages
- agent loop attacks causing unbounded reasoning cycles; runaway tool invocations or code execution

ELEVATION OF PRIVILEGE:
- ASI02 (Tool Misuse and Exploitation): over-privileged tools executing destructive commands, unvalidated tool inputs
- ASI03 (Identity and Privilege Abuse): cached credential misuse, confused deputy, cross-agent delegation abuse
- ASI05 (Unexpected Code Execution): unsafe eval/exec of generated code, shell injection, sandbox escape
- ASI10 (Rogue Agents): agents persisting beyond their lifecycle, impersonating users or resisting shutdown

## Cross-layer analysis

Consider how each threat cascades across components: poisoned retrieval affecting tool use, a compromised tool provider corrupting memory, multi-agent manipulation leading to infrastructure compromise, observability gaps hiding attack progression. Include at least 2-3 threats that describe explicit cross-component attack chains where applicable.

## Critical agentic risks to evaluate

1. ASI01 - Agent Goal Hijack  2. ASI02 - Tool Misuse  3. ASI03 - Identity and Privilege Abuse
4. ASI04 - Agentic Supply Chain  5. ASI05 - Unexpected Code Execution  6. ASI06 - Memory and Context Poisoning
7. ASI07 - Insecure Inter-Agent Communication  8. ASI08 - Cascading Failures
9. ASI09 - Human-Agent Trust Exploitation  10. ASI10 - Rogue Agents

## Schema additions

Each threat additionally carries:
- `"owasp_asi"`: the applicable code as a string (e.g. `"ASI01"`), or `null` if none applies.
