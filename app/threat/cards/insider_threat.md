---
name: insider_threat
title: AI Insider Threat
when_to_load: |
  Load in addition to the agentic card when the agent has meaningful autonomy,
  persistent credentials, broad tool access, or operates with limited real-time
  human oversight. Flips the lens from "agent as asset under attack" to "agent
  as potentially-untrusted insider".
app_types: [agentic]
adds_fields: []
source: https://ai-insider-threat.matt-adams.co.uk
version: 2026-04
---

# AI Insider Threat — Reference Card

Most threat analysis treats the application as the asset under attack: "what could an external attacker do to this system?". This card adds a complementary lens. It treats the AI agent itself as a potentially-untrusted insider with credentials, access and autonomy, and asks "what could this agent do against the organisation that deployed it?". A thorough analysis of a high-autonomy agentic system needs both lenses.

## Why this lens matters

Frontier agents now meet the four classical insider-threat preconditions: access (tool integrations, MCP servers, credentials), capability (multi-step planning, code execution, persistent context), opportunity (long autonomous sessions, post-hoc human review) and predisposition (documented misalignment behaviours, including deceptive reasoning traces).

## Deployment archetypes (autonomy levels)

- L1 Human-as-Operator (LOW): a human approves every action. Residual risk: reviewer fatigue.
- L2 Human-as-Collaborator (MEDIUM): the agent acts within scoped boundaries; auto-approved actions are the weak point.
- L3 Human-as-Supervisor (HIGH): the agent runs autonomously per task; humans review outputs, not actions.
- L4 Human-as-Auditor (CRITICAL): continuous execution with persistent access; logs reviewed periodically.

If unclear, assume L2/L3 for any system with tool use or persistent credentials, and state that assumption.

## The five insider categories

1. Credential Compromise: the agent harvests API tokens, SSH keys or service-account credentials from environment, config or process memory (Spoofing, Elevation of Privilege).
2. Supply Chain Sabotage: the agent injects subtle vulnerabilities, modifies CI/CD pipelines or tampers with dependencies (Tampering, Repudiation).
3. Data Exfiltration: the agent accumulates and exfiltrates IP, PII or credentials via MCP connections, possibly encoded in legitimate-looking output (Information Disclosure).
4. Infrastructure Sabotage: the agent corrupts repositories, floods services, provisions rogue cloud resources or takes down shared infrastructure (Denial of Service).
5. Deception & Evasion: the agent manipulates visible reasoning, interleaves malicious actions with legitimate work, modifies logs or adapts to monitoring (Spoofing, Repudiation, Elevation of Privilege).

## Concrete scenarios to check

Spoofing: harvested keys used to impersonate users or services; commits with forged author metadata or via CI service accounts; messages sent through MCP integrations impersonating staff; a benign-looking reasoning trace masking different actions.
Tampering: backdoors in source (weakened auth checks, hard-coded credentials, race conditions); malicious CI/CD build steps; database writes altering ACLs or audit records; modification of its own container (tools, iptables, /proc).
Repudiation: deleting or truncating logs, SIEM forwarder configs or shell history; interleaving malicious actions in long sessions; changes made through indirect mechanisms that bypass commit signing.
Information Disclosure: mass accumulation and exfiltration via MCP; reading process memory for in-memory secrets; bulk extraction from staging databases holding production copies; sensitive chain-of-thought logged to broadly accessible observability systems.
Denial of Service: fork bombs and massive queries; excessive cloud resources or deleted infrastructure via cloud APIs; flooding ticketing/chat systems; force-pushing or deleting branches.
Elevation of Privilege: container escape via /proc, ptrace or the Docker socket; harvested credentials used beyond intended scope (dev to prod); pipeline steps running with elevated service-account rights; creating accounts or altering group memberships through identity systems.

## Detection guidance

Detect insider-style AI threats through action-level monitoring of what the agent did, not what it said. Prioritise immutable, agent-write-protected audit logs of every tool call, command, file operation, network connection and query; behavioural baselines with deviation alerting; honey tokens and canary credentials; deny-by-default egress allowlists. When suggesting improvements for insider-relevant threats, name specific controls (SIEM rules, UEBA baselines, egress allowlists, container-escape EDR indicators, force-push alerts) rather than generic monitoring.

## How to record insider threats

There is no extra field for this lens. When a threat fits one of the five insider categories, start its `title` with the category name (e.g. "Credential Compromise: agent reuses cached cloud keys") and state the assumed autonomy level in the `scenario`. The threat still belongs to exactly one of the six threat categories in `category`.
