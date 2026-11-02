# Sentinel: AI Security Review

A queue-based workspace for running security design reviews of **new initiatives and changes**.
You describe the change, AI picks the relevant NIST requirements, and the reviewer works through them.
Each requirement links down to SP 800-53 controls and then to Checkov technical checks.

```
NIST CSF 2.0 subcategory  (the review question, e.g. PR.DS-01)
  └─ SP 800-53 Rev 5 controls  (NIST's official CSF → 800-53 mapping, e.g. SC-28, SC-12)
       └─ Checkov checks  (IaC policies that implement those controls, e.g. CKV_AWS_19)
```

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Build data/catalog.json (downloads NIST sources once into data/raw/, parses Checkov statically)
python scripts/build_catalog.py            # --refresh to re-download, --checkov-path to point elsewhere

python main.py                             # http://127.0.0.1:8000  (--port, --host, --reload)
```

The SQLite database (`data/reviews.db`) is created the first time you run the app.

Optional demo data: `python scripts/seed_demo.py` adds 10 realistic reviews covering every status.
Use `--reset` to recreate them, `--remove` to delete them, and `--use-ai` to scope them with your configured provider.
Only the demo reviews are touched.

## Workflow

1. **New review**: the requester gives a description, tech stack and risk flags (internet facing, personal data, third party, AI…).
2. **AI scoping** selects in-scope CSF subcategories, says why each one applies, and detects technologies, services and key risks.
   You can edit, add or remove any of it, and re-running scoping keeps your manual changes.
3. **Assess**: for each requirement, record the team's response, reviewer notes and a status (Met / Partial / Not met / N/A).
   Under each requirement you'll see its 800-53 controls and the ranked Checkov checks, filtered to your platforms.
   Mark each check Pass / Fail / Exception / N/A.
4. **Decide**: the review moves `new → in_progress → awaiting_info → approved / rejected` (you can drag cards on the board).
   **Export** a Markdown report.

## AI providers

Set these in **Settings** (stored in SQLite) or with environment variables / `.env` (see `.env.example`):

| Provider | Notes |
|---|---|
| `heuristic` | Default. Works offline using the keyword and flag triggers in `catalog/csf_questions.yaml` |
| `openai` | Any OpenAI-compatible endpoint (Azure OpenAI, LM Studio, vLLM…) via `OPENAI_BASE_URL` |
| `anthropic` | Claude models |
| `gemini` | Google Gemini |
| `ollama` | Local models |

The AI only chooses requirements from the catalog. Its output is checked against the catalog, and if the AI fails the app falls back to the heuristic.

## Data sources & customisation

| File | Purpose |
|---|---|
| `catalog/csf_questions.yaml` | Reviewer-style question, scope (project/org), baseline flag and triggers for each of the 106 CSF 2.0 subcategories |
| `catalog/checkov_nist_rules.yaml` | **Checkov → 800-53 mapping**: labelled regex keyword rules (high confidence) plus Checkov category defaults (low confidence, informational only). Each check's controls are stored with their provenance in `catalog.json` (`check.mapping`) |
| `catalog/csf_check_links.yaml` | **Requirement → check links**: for every CSF 2.0 subcategory either `checks: none` (organisational) or a link spec (`controls`, `categories`, `include` / `exclude` name regexes, explicit `checks`) with a one-line `why`. Read at startup - restart the app after editing |
| `catalog/frameworks/*.yaml` | Additional requirement frameworks used alongside CSF (NIST AI RMF 1.0, NIST AI 600-1, OWASP Top 10:2025, LLM 2025, API 2023, Agentic 2026): official text plus question, scope, baseline, triggers and an `applies_when` profile condition. Loaded at startup - no catalog rebuild needed |
| `scripts/build_catalog.py` | Merges the NIST CSF 2.0 reference tool (CPRT), the OSCAL SP 800-53 r5 catalog and Checkov into `data/catalog.json` |

> **Note:** open-source Checkov does not ship a NIST mapping, so `checkov_nist_rules.yaml` is this project's own mapping and you can edit it.
> The CSF → 800-53 links are NIST's official informative references.
> After editing `csf_questions.yaml` or `checkov_nist_rules.yaml`, re-run `python scripts/build_catalog.py` (it also validates `csf_check_links.yaml`).

Checks are linked to a requirement only through its spec in `csf_check_links.yaml`, never through NIST's broad CSF → 800-53 references.
A check matches when one of its rule-derived controls is in the spec's `controls` (or its category is in `categories`) and its name passes the `include` / `exclude` filters.
Explicit ids and rule-derived matches are *strong*; category-only matches without an `include` filter are *related*. Every link carries a human-readable reason.
Requirements without a spec (e.g. other frameworks) get no automatic checks.

Reviewers can correct links on the **Mappings** page (`#/mappings`, applies to all reviews, with YAML export / import) or inline under a requirement in a review (this review only, or all reviews).
These overrides are stored in the `check_links` table and merged in order: automatic → all-reviews include/exclude → review include/exclude.
A review's platforms filter the checks shown; if none of them match a Checkov platform, all platforms are shown instead.

## Layout

```
app/            FastAPI backend (api, catalog, db, report, ai/providers, ai/scoping)
static/         Vanilla JS SPA (hash router, views/) + CSS design system
catalog/        Hand-maintained YAML (questions, Checkov→NIST rules, requirement→check links)
scripts/        Catalog builder
data/           catalog.json (generated), raw/ (downloaded sources), reviews.db
references/     Checkov source tree used for parsing
```
