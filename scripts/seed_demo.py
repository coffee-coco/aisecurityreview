"""Seed realistic demo security reviews into the review queue.

Reviews are created through the real API (in-process, no server needed), so they get
scoped exactly like user-submitted ones. Then a reviewer's progress is layered on top:
requirement answers and statuses, Checkov results, status transitions, and back-dated
timestamps so the queue looks lived-in.

    python scripts/seed_demo.py              # seed into DB_PATH (default data/reviews.db)
    python scripts/seed_demo.py --reset      # remove previously seeded demo reviews first
    python scripts/seed_demo.py --remove     # only remove the demo reviews
    python scripts/seed_demo.py --use-ai     # scope with the AI provider configured in Settings

Only reviews whose titles match the demo set are touched; your own reviews are left alone.
"""
from __future__ import annotations

import argparse
import random
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

import app.api as api  # noqa: E402
from app import db  # noqa: E402
from app.config import DB_PATH  # noqa: E402
from app.main import app  # noqa: E402

TODAY = date.today()


def due(days: int) -> str:
    return (TODAY + timedelta(days=days)).isoformat()


# Generic reviewer-style answers used to fill the remaining requirements on mature reviews.
FILL_ANSWERS = [
    ("met", "Covered by the enterprise cloud baseline; confirmed in design walkthrough.", ""),
    ("met", "Inherited from the platform team's landing zone controls (see LZ-STD-004).", ""),
    ("met", "Evidence provided: architecture diagram v3 and Terraform plan output.", ""),
    ("met", "Handled by existing ISMS process - no change introduced by this initiative.", ""),
    ("na", "Not applicable to this scope.", "Agreed N/A - no new assets of this type."),
]

DEMO = [
    # ------------------------------------------------------------------ in progress
    {
        "body": {
            "title": "Customer self-service portal",
            "change_type": "new",
            "description": (
                "New public portal on AWS using CloudFront, API Gateway, Lambda and RDS Postgres. Customers "
                "log in via Okta to view statements and update personal details. Payments are handled by "
                "Stripe (SaaS). Infrastructure is deployed with Terraform from GitHub Actions."),
            "requester": "Jane Doe", "business_owner": "Head of Digital", "reviewer": "Daniel Sanders",
            "business_unit": "Digital", "data_classification": "confidential",
            "tech_stack": "AWS, Terraform, GitHub Actions, Okta",
            "internet_facing": True, "personal_data": True, "third_party": True, "priority": "critical",
            "due_date": due(18),
        },
        "status": ["in_progress"], "risk": "critical", "created": 9, "updated": 0.2, "fill": 0.25,
        "reqs": {
            "PR.DS-01": ("partial", "RDS encrypted with the AWS-managed KMS key; S3 uses SSE-S3.",
                         "Require a customer-managed KMS key for RDS before go-live."),
            "PR.DS-02": ("met", "TLS 1.2+ enforced on CloudFront and API Gateway; HSTS enabled.", ""),
            "PR.AA-03": ("met", "Customers authenticate via Okta CIAM with MFA on profile changes.", ""),
            "PR.AA-05": ("partial", "Lambda roles scoped per function, but the deploy role has iam:*.",
                         "Remove iam:* from deploy role - use permission boundaries."),
            "DE.CM-01": ("not_met", "No WAF/CloudFront logs shipped to the SIEM yet.",
                         "Blocking: forward CloudFront, WAF and API GW logs to Sentinel."),
            "GV.SC-05": ("met", "Stripe is PCI DSS Level 1; DPA signed and on file.", ""),
        },
        "checks": {
            "CKV_AWS_16": ("pass", ""), "CKV_AWS_17": ("pass", ""),
            "CKV_AWS_157": ("fail", "Single-AZ RDS in the current Terraform."),
            "CKV_AWS_68": ("pass", ""), "CKV_AWS_174": ("pass", ""),
            "CKV_AWS_86": ("fail", "Access logging not configured on the distribution."),
            "CKV_AWS_45": ("pass", ""),
            "CKV_AWS_117": ("exception", "Public Lambdas don't need VPC access; approved by the CISO."),
            "CKV_AWS_76": ("pass", ""),
            "CKV_AWS_161": ("fail", "App uses a static DB password from Secrets Manager; IAM auth planned."),
        },
    },
    {
        "body": {
            "title": "Internal RAG chatbot on Azure OpenAI",
            "change_type": "new",
            "description": (
                "Internal assistant that answers staff questions from SharePoint policies and Confluence. "
                "Uses Azure OpenAI (GPT-4o) with Azure AI Search as the vector store, hosted on Azure App "
                "Service. Staff sign in with Entra ID SSO; secrets live in Key Vault. Prompts and responses "
                "are logged for quality review."),
            "requester": "Priya N", "business_owner": "COO", "reviewer": "Daniel Sanders",
            "business_unit": "Technology", "data_classification": "confidential",
            "tech_stack": "Azure, Azure OpenAI, App Service, Key Vault, Entra ID, Azure Pipelines",
            "uses_ai": True, "personal_data": True, "priority": "high", "due_date": due(25),
        },
        "status": ["in_progress"], "risk": "high", "created": 6, "updated": 1, "fill": 0.35,
        "reqs": {
            "PR.AA-05": ("partial", "Search index isn't security-trimmed yet; every user can retrieve every doc.",
                         "Implement document-level ACL filtering in AI Search before pilot."),
            "PR.DS-01": ("met", "AI Search and Storage encrypted with CMK in Key Vault.", ""),
            "ID.RA-01": ("partial", "Threat model covers prompt injection, not data exfiltration via citations.",
                         "Extend threat model (OWASP LLM Top 10: LLM01, LLM06)."),
            "GV.SC-05": ("met", "Microsoft DPA and Azure OpenAI abuse-monitoring opt-out approved.", ""),
        },
        "checks": {
            "CKV_AZURE_134": ("pass", ""),
            "CKV_AZURE_236": ("fail", "Local (key) auth still enabled for the OpenAI account."),
            "CKV_AZURE_238": ("pass", ""),
            "CKV_AZURE_247": ("fail", "Outbound network restrictions / DLP not configured."),
            "CKV_AZURE_110": ("pass", ""), "CKV_AZURE_42": ("pass", ""), "CKV_AZURE_14": ("pass", ""),
        },
    },
    {
        "body": {
            "title": "Claims analytics data lake on S3",
            "change_type": "new",
            "description": (
                "Central data lake for claims analytics. Raw claims extracts land in S3, are catalogued with "
                "Glue and queried with Athena. Lake Formation governs table access for actuarial analysts. "
                "Contains policyholder PII and health information."),
            "requester": "Marcus Lee", "business_owner": "Chief Data Officer", "reviewer": "Alex Kim",
            "business_unit": "Data & Analytics", "data_classification": "restricted",
            "tech_stack": "AWS, S3, Glue, Athena, Lake Formation, Terraform",
            "personal_data": True, "priority": "high", "due_date": due(9),
        },
        "status": ["in_progress"], "risk": "high", "created": 14, "updated": 2, "fill": 0.6,
        "reqs": {
            "PR.DS-01": ("met", "SSE-KMS with per-zone CMKs (raw/curated) and annual rotation.", ""),
            "PR.AA-05": ("met", "Lake Formation column-level grants; PII columns masked for analysts.", ""),
            "DE.CM-03": ("partial", "CloudTrail data events on for raw zone only.",
                         "Enable S3 data events for curated zone."),
            "PR.DS-11": ("met", "Versioning plus AWS Backup vault lock for raw zone.", ""),
        },
        "checks": {
            "CKV_AWS_19": ("pass", ""), "CKV_AWS_145": ("pass", ""), "CKV2_AWS_6": ("pass", ""),
            "CKV_AWS_18": ("fail", "Server access logging missing on 2 of 5 buckets."),
            "CKV_AWS_21": ("pass", ""), "CKV_AWS_7": ("pass", ""), "CKV_AWS_20": ("pass", ""),
        },
    },
    # ------------------------------------------------------------------ awaiting info
    {
        "body": {
            "title": "Migrate HR payroll to Workday SaaS",
            "change_type": "change",
            "description": (
                "Replace the on-prem payroll system with Workday. Employee master data and bank details "
                "sync nightly over SFTP from an Azure-hosted integration server. Staff use Entra ID SSO. "
                "Workday support staff (offshore) have delegated access."),
            "requester": "Sam Lee", "business_owner": "Chief People Officer", "reviewer": "Daniel Sanders",
            "business_unit": "People & Culture", "data_classification": "restricted",
            "tech_stack": "Workday (SaaS), Azure, SFTP, Entra ID",
            "personal_data": True, "third_party": True, "priority": "high", "due_date": due(-4),
        },
        "status": ["in_progress", "awaiting_info"], "risk": "high", "created": 21, "updated": 3, "fill": 0.5,
        "reqs": {
            "GV.SC-05": ("partial", "MSA signed; security schedule lacks a 24h breach-notification clause.",
                         "Awaiting legal: add breach notification + right-to-audit."),
            "GV.SC-07": ("open", "", "Requested Workday SOC 2 Type II bridge letter."),
            "PR.AA-01": ("met", "Joiner/mover/leaver driven from Entra ID via SCIM.", ""),
            "PR.DS-02": ("partial", "SFTP uses key auth but files aren't PGP-encrypted.",
                         "Require PGP encryption of payroll files at rest on the integration server."),
            "PR.AA-05": ("not_met", "Offshore support has standing access to production tenant.",
                         "Need JIT / approval-based support access."),
        },
        "checks": {
            "CKV_AZURE_3": ("pass", ""), "CKV_AZURE_44": ("pass", ""),
            "CKV_AZURE_35": ("fail", "Integration storage account allows all networks."),
            "CKV2_AZURE_1": ("exception", "Microsoft-managed keys accepted for transient files (<24h)."),
            "CKV_AZURE_59": ("pass", ""),
        },
    },
    {
        "body": {
            "title": "Containerise legacy claims portal on AKS",
            "change_type": "change",
            "description": (
                "Lift the .NET claims portal from IIS VMs into Docker containers on Azure Kubernetes Service. "
                "Internet facing via Application Gateway WAF. Images built in Azure Pipelines and pushed to "
                "ACR. Helm charts manage deployment."),
            "requester": "Olivia Chen", "business_owner": "GM Claims", "reviewer": "Alex Kim",
            "business_unit": "Claims", "data_classification": "confidential",
            "tech_stack": "Azure, AKS, Docker, Helm, Azure Pipelines",
            "internet_facing": True, "personal_data": True, "priority": "medium", "due_date": due(12),
        },
        "status": ["in_progress", "awaiting_info"], "risk": "medium", "created": 11, "updated": 1.5, "fill": 0.45,
        "reqs": {
            "PR.PS-01": ("partial", "Pod Security Admission 'baseline' only.",
                         "Move app namespaces to 'restricted'; provide exceptions list."),
            "PR.IR-01": ("met", "AKS in dedicated spoke VNet; App Gateway WAF in prevention mode.", ""),
            "ID.RA-01": ("open", "", "Awaiting container image scan results from Defender for Containers."),
        },
        "checks": {
            "CKV_AZURE_115": ("fail", "Public API server; team requested 1 sprint to move to private cluster."),
            "CKV_AZURE_7": ("pass", ""), "CKV_AZURE_116": ("pass", ""), "CKV_AZURE_4": ("pass", ""),
            "CKV_K8S_16": ("pass", ""),
            "CKV_K8S_20": ("fail", "allowPrivilegeEscalation not set in the Helm chart."),
            "CKV_K8S_43": ("fail", "Images referenced by tag, not digest."),
            "CKV_K8S_8": ("pass", ""), "CKV_K8S_9": ("pass", ""),
            "CKV_DOCKER_3": ("pass", ""), "CKV_DOCKER_7": ("pass", ""),
        },
    },
    # ------------------------------------------------------------------ approved
    {
        "body": {
            "title": "Payments microservice on GKE",
            "change_type": "new",
            "description": (
                "New card-payments orchestration service on Google Kubernetes Engine with Cloud SQL "
                "(Postgres) and Pub/Sub for settlement events. In PCI DSS scope; card data is tokenised by "
                "the acquirer before reaching our systems."),
            "requester": "Ravi Patel", "business_owner": "Head of Payments", "reviewer": "Daniel Sanders",
            "business_unit": "Payments", "data_classification": "restricted",
            "tech_stack": "GCP, GKE, Cloud SQL, Pub/Sub, Terraform, GitHub Actions",
            "third_party": True, "priority": "high", "due_date": due(-10),
        },
        "status": ["in_progress", "awaiting_info", "in_progress", "approved"], "risk": "medium",
        "created": 40, "updated": 12, "fill": 1.0,
        "decision": ("Approved with conditions: (1) rotate Cloud SQL CMK annually, "
                     "(2) re-review before adding direct PAN handling."),
        "reqs": {
            "PR.DS-01": ("met", "Cloud SQL and Pub/Sub encrypted with CMEK in Cloud KMS.", ""),
            "PR.DS-02": ("met", "mTLS between services via Anthos Service Mesh; SQL requires SSL.", ""),
            "PR.IR-01": ("met", "Private GKE cluster, master authorised networks, no public IPs.", ""),
        },
        "checks": {
            "CKV_GCP_6": ("pass", ""), "CKV_GCP_60": ("pass", ""), "CKV_GCP_11": ("pass", ""),
            "CKV_GCP_14": ("pass", ""), "CKV_GCP_20": ("pass", ""), "CKV_GCP_25": ("pass", ""),
            "CKV_GCP_13": ("pass", ""),
            "CKV_GCP_83": ("exception", "CMEK used instead of CSEK - accepted by security architecture."),
            "CKV_K8S_16": ("pass", ""), "CKV_K8S_22": ("pass", ""), "CKV_K8S_40": ("pass", ""),
        },
    },
    {
        "body": {
            "title": "GitHub Actions OIDC deployment pipeline",
            "change_type": "change",
            "description": (
                "Replace long-lived AWS access keys in GitHub secrets with GitHub Actions OIDC federation "
                "to per-environment IAM roles. Terraform plans run on PRs; applies require environment "
                "approval."),
            "requester": "Platform team", "business_owner": "Head of Platform", "reviewer": "Alex Kim",
            "business_unit": "Platform", "data_classification": "internal",
            "tech_stack": "GitHub Actions, AWS IAM, Terraform", "priority": "medium", "due_date": due(-20),
        },
        "status": ["in_progress", "approved"], "risk": "low", "created": 30, "updated": 22, "fill": 1.0,
        "decision": "Approved. Reduces credential exposure; trust policy restricted to repo:org/infra:environment:*.",
        "reqs": {
            "PR.AA-01": ("met", "No static AWS credentials remain; OIDC roles per environment.", ""),
            "PR.PS-06": ("met", "Branch protection, CODEOWNERS and required reviews on infra repo.", ""),
        },
        "checks": {
            "CKV2_GHA_1": ("pass", ""), "CKV_GHA_2": ("pass", ""), "CKV_GHA_7": ("pass", ""),
            "CKV_AWS_289": ("pass", ""),
            "CKV_AWS_290": ("exception", "Terraform apply role needs broad write; bounded by SCPs."),
            "CKV_SECRET_2": ("pass", ""),
        },
    },
    # ------------------------------------------------------------------ rejected
    {
        "body": {
            "title": "Share claims data with marketing agency via Snowflake",
            "change_type": "new",
            "description": (
                "Marketing wants to share customer and claims history with an external agency through a "
                "Snowflake reader account for campaign targeting. Data would include names, emails, "
                "postcodes and claim types."),
            "requester": "Emma Wilson", "business_owner": "CMO", "reviewer": "Daniel Sanders",
            "business_unit": "Marketing", "data_classification": "restricted",
            "tech_stack": "Snowflake (SaaS), AWS S3",
            "personal_data": True, "third_party": True, "priority": "high", "due_date": due(-15),
        },
        "status": ["in_progress", "awaiting_info", "rejected"], "risk": "critical",
        "created": 35, "updated": 18, "fill": 0.3,
        "decision": ("Rejected: sharing identifiable claims data for marketing isn't covered by our privacy "
                     "notice and the agency has no SOC 2 / ISO 27001. Resubmit with aggregated, "
                     "de-identified data."),
        "reqs": {
            "GV.SC-06": ("not_met", "Agency has no independent security assurance.", "No SOC 2 / ISO 27001."),
            "PR.DS-01": ("partial", "Snowflake encrypted, but reader account allows export.", ""),
            "GV.OC-03": ("not_met", "Use is outside the purpose stated in the privacy notice.",
                         "Privacy officer advises not permitted."),
        },
        "checks": {"CKV_AWS_20": ("pass", ""), "CKV2_AWS_6": ("pass", "")},
    },
    # ------------------------------------------------------------------ new (just submitted, unscoped)
    {
        "body": {
            "title": "Upgrade EKS clusters to 1.31",
            "change_type": "change",
            "description": (
                "In-place upgrade of production EKS clusters from 1.29 to 1.31, including managed node "
                "groups, CoreDNS and the AWS Load Balancer Controller. ArgoCD-managed workloads."),
            "requester": "Ops team", "business_owner": "Head of Platform",
            "business_unit": "Platform", "data_classification": "internal",
            "tech_stack": "AWS, EKS, Kubernetes, Helm, ArgoCD", "priority": "low", "due_date": due(30),
            "auto_scope": False,
        },
        "status": [], "risk": "", "created": 0.8, "updated": 0.8,
    },
    {
        "body": {
            "title": "Mobile app push notifications via Firebase",
            "change_type": "new",
            "description": (
                "Add push notifications to the iOS/Android app using Firebase Cloud Messaging. Device "
                "tokens stored in Firestore and linked to customer IDs; campaign triggers from Braze."),
            "requester": "Tom Baker", "business_owner": "Head of Mobile",
            "business_unit": "Digital", "data_classification": "confidential",
            "tech_stack": "GCP, Firebase, Firestore, Braze (SaaS)",
            "internet_facing": True, "personal_data": True, "third_party": True,
            "priority": "medium", "due_date": due(21), "auto_scope": False,
        },
        "status": [], "risk": "", "created": 0.1, "updated": 0.1,
    },
]

DEMO_TITLES = [d["body"]["title"] for d in DEMO]


def remove_demo() -> int:
    with db.tx() as conn:
        n = conn.execute(f"DELETE FROM reviews WHERE title IN ({','.join('?' * len(DEMO_TITLES))})",
                         DEMO_TITLES).rowcount
    return n


def backdate(review_id: int, created_days: float, updated_days: float) -> None:
    now = datetime.now(timezone.utc)
    created = now - timedelta(days=created_days)
    updated = now - timedelta(days=updated_days)
    iso = lambda d: d.isoformat(timespec="seconds")  # noqa: E731
    with db.tx() as conn:
        conn.execute("UPDATE reviews SET created_at = ?, updated_at = ? WHERE id = ?",
                     (iso(created), iso(updated), review_id))
        conn.execute("UPDATE review_requirements SET updated_at = ? WHERE review_id = ?", (iso(updated), review_id))
        conn.execute("UPDATE review_checks SET updated_at = ? WHERE review_id = ?", (iso(updated), review_id))
        ids = [r[0] for r in conn.execute("SELECT id FROM activity WHERE review_id = ? ORDER BY id", (review_id,))]
        span = updated - created
        for i, aid in enumerate(ids):
            frac = i / (len(ids) - 1) if len(ids) > 1 else 0
            conn.execute("UPDATE activity SET ts = ? WHERE id = ?", (iso(created + span * frac), aid))


def seed(client: TestClient, spec: dict, rng: random.Random) -> dict:
    body = {"auto_scope": True, **spec["body"]}
    r = client.post("/api/reviews", json=body)
    r.raise_for_status()
    review = r.json()
    rid = review["id"]
    in_scope = {x["subcategory_id"] for x in review["requirements"]}

    for sid, (status, answer, notes) in spec.get("reqs", {}).items():
        if sid not in in_scope:
            client.post(f"/api/reviews/{rid}/requirements", json={"subcategory_id": sid, "priority": "high"})
        client.patch(f"/api/reviews/{rid}/requirements/{sid}",
                     json={"status": status, "answer": answer, "notes": notes}).raise_for_status()

    # Fill a share of the remaining open requirements with plausible outcomes.
    fill = spec.get("fill", 0)
    if fill:
        remaining = [x["subcategory_id"] for x in client.get(f"/api/reviews/{rid}").json()["requirements"]
                     if x["status"] == "open" and x["subcategory_id"] not in spec.get("reqs", {})]
        for sid in remaining[: round(len(remaining) * fill)]:
            status, answer, notes = rng.choice(FILL_ANSWERS)
            client.patch(f"/api/reviews/{rid}/requirements/{sid}",
                         json={"status": status, "answer": answer, "notes": notes})

    for cid, (status, note) in spec.get("checks", {}).items():
        client.put(f"/api/reviews/{rid}/checks/{cid}", json={"status": status, "note": note}).raise_for_status()

    for st in spec.get("status", []):
        client.patch(f"/api/reviews/{rid}", json={"status": st})
    patch = {}
    if spec.get("risk"):
        patch["risk_rating"] = spec["risk"]
    if spec.get("decision"):
        patch["decision_notes"] = spec["decision"]
    if patch:
        client.patch(f"/api/reviews/{rid}", json=patch).raise_for_status()

    backdate(rid, spec["created"], spec["updated"])
    return client.get(f"/api/reviews/{rid}").json()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reset", action="store_true", help="delete existing demo reviews before seeding")
    ap.add_argument("--remove", action="store_true", help="only delete the demo reviews")
    ap.add_argument("--use-ai", action="store_true", help="scope with the configured AI provider")
    args = ap.parse_args()

    db.init_db()
    if args.remove or args.reset:
        print(f"Removed {remove_demo()} demo review(s) from {DB_PATH}")
        if args.remove:
            return
    if not args.use_ai:
        api.build_llm = lambda _settings: None  # offline heuristic scoping: fast, free, deterministic

    with db.tx() as conn:
        existing = {r[0] for r in conn.execute("SELECT title FROM reviews")}
    rng = random.Random(42)
    with TestClient(app) as client:
        for spec in DEMO:
            title = spec["body"]["title"]
            if title in existing:
                print(f"  skip  {title} (already exists - use --reset to recreate)")
                continue
            r = seed(client, spec, rng)
            done = sum(1 for x in r["requirements"] if x["status"] != "open")
            print(f"  {r['ref']}  {r['status']:<13} {done:>3}/{len(r['requirements']):<3} reqs  "
                  f"{sum(r['check_counts'].values()):>2} checks  {title}")
    print(f"Done -> {DB_PATH}")


if __name__ == "__main__":
    main()
