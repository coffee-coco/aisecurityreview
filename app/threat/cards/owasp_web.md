---
name: owasp_web
title: OWASP Top 10 (web applications)
when_to_load: |
  Load for any system with a web, API or service surface. Annotates each threat
  with the most relevant OWASP Top 10:2025 category.
app_types: [web, genai, agentic]
adds_fields: [owasp_top10]
source: https://owasp.org/Top10/2025/
version: 2025
---

# OWASP Top 10:2025 — Reference Card

Attach the single most relevant OWASP Top 10:2025 category to each threat where one clearly applies.

- A01:2025 Broken Access Control (includes SSRF)
- A02:2025 Security Misconfiguration
- A03:2025 Software Supply Chain Failures
- A04:2025 Cryptographic Failures
- A05:2025 Injection
- A06:2025 Insecure Design
- A07:2025 Authentication Failures
- A08:2025 Software or Data Integrity Failures
- A09:2025 Security Logging and Alerting Failures
- A10:2025 Mishandling of Exceptional Conditions

## Schema additions

Each threat additionally carries:
- `"owasp_top10"`: the category code as a string (e.g. `"A01:2025"`), or `null` if none clearly applies.
