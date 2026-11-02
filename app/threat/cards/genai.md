---
name: genai
title: OWASP Top 10 for LLM Applications
when_to_load: |
  Load when the system uses LLM SDKs (openai, anthropic, mistralai,
  google-generativeai, etc.), exposes LLM-driven endpoints, performs RAG or
  embedding operations, or otherwise has language-model behaviour in scope.
app_types: [genai, agentic]
adds_fields: [owasp_llm]
source: https://owasp.org/www-project-top-10-for-large-language-model-applications/
version: 2025
---

# OWASP Top 10 for LLM Applications — Reference Card

The system has language-model behaviour in scope. In addition to traditional threats, you MUST consider the LLM-specific threats below and place each under one of the six threat categories.

## LLM-specific threats by category (OWASP Top 10 for LLM Applications 2025)

SPOOFING (traditional + LLM):
- Traditional: identity spoofing, credential theft
- LLM01 (Prompt Injection): crafted inputs override system instructions, making the model impersonate other entities or bypass intended behaviour
- LLM07 (System Prompt Leakage): extracted system prompts reveal intended identity/behaviour, enabling more targeted spoofing

TAMPERING (traditional + LLM):
- Traditional: data modification, code injection
- LLM01 (Prompt Injection): direct or indirect injection that manipulates model behaviour or outputs
- LLM04 (Data and Model Poisoning): malicious modification of training data, fine-tuning data or embeddings
- LLM08 (Vector and Embedding Weaknesses): manipulation of RAG data or embeddings to alter retrieval results

REPUDIATION (traditional + LLM):
- Traditional: denial of actions, log manipulation
- LLM09 (Misinformation): the model generates false information that users act upon; accountability is hard to attribute
- Missing audit trails for model decisions and generated content

INFORMATION DISCLOSURE (traditional + LLM):
- Traditional: data leaks, unauthorised access
- LLM02 (Sensitive Information Disclosure): the model reveals training data, PII, credentials or proprietary information
- LLM07 (System Prompt Leakage): exposure of confidential instructions, business logic or secrets embedded in prompts
- LLM08 (Vector and Embedding Weaknesses): leakage through embeddings or cross-tenant RAG data

DENIAL OF SERVICE (traditional + LLM):
- Traditional: resource exhaustion, service disruption
- LLM10 (Unbounded Consumption): resource and cost exhaustion through expensive queries, long contexts or repeated requests
- LLM04 (Data and Model Poisoning): model performance degradation through poisoned data

ELEVATION OF PRIVILEGE (traditional + LLM):
- Traditional: privilege escalation, unauthorised access
- LLM05 (Improper Output Handling): model output passed downstream without validation enables command injection, XSS, SSRF
- LLM06 (Excessive Agency): the model is granted excessive permissions or autonomy to perform actions
- LLM03 (Supply Chain): compromised models, plugins or dependencies introduce backdoors or malicious capabilities

## Critical LLM risks to evaluate

1. LLM01 - Prompt Injection: can users or external content manipulate the model through crafted inputs?
2. LLM02 - Sensitive Information Disclosure: could the model leak training data, PII or secrets in responses?
3. LLM03 - Supply Chain: are models, plugins and dependencies from trusted sources with integrity verification?
4. LLM04 - Data and Model Poisoning: could training, fine-tuning or RAG content be poisoned?
5. LLM05 - Improper Output Handling: is model output validated and sanitised before downstream use?
6. LLM06 - Excessive Agency: are the model's actions and permissions appropriately limited?
7. LLM07 - System Prompt Leakage: could prompts containing secrets or logic be extracted?
8. LLM08 - Vector and Embedding Weaknesses: are embeddings and RAG stores protected from manipulation and leakage?
9. LLM09 - Misinformation: could hallucinated or false outputs cause harm if trusted?
10. LLM10 - Unbounded Consumption: are there limits on consumption to prevent denial of service and cost overruns?

## Hosted inference providers

When the model is served by a hosted or shared provider, treat the inference endpoint as an external service outside the trust boundary. Prompt and KV caches, request batching and multi-tenant scheduling can expose one customer's prompt or completion content to another, independently of the system's own controls. This is not one of LLM01–LLM10, so set `owasp_llm` to `null` for such a threat unless one of them also applies.

## Schema additions

Each threat additionally carries:
- `"owasp_llm"`: the applicable code as a string (e.g. `"LLM01"`), or `null` if none applies.
