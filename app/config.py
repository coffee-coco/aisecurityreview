"""Application configuration (paths + environment)."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Tiny .env loader (KEY=VALUE per line) so no extra dependency is needed."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(ROOT / ".env")

DATA_DIR = ROOT / "data"
STATIC_DIR = ROOT / "static"
CATALOG_PATH = Path(os.getenv("CATALOG_PATH", DATA_DIR / "catalog.json"))
CHECK_LINKS_PATH = Path(os.getenv("CHECK_LINKS_PATH", ROOT / "catalog" / "csf_check_links.yaml"))
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", DATA_DIR / "uploads"))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "100"))          # per file / archive
MAX_CODE_FILES = int(os.getenv("MAX_CODE_FILES", "20000"))      # files extracted from an archive
MAX_CODE_UNPACKED_MB = int(os.getenv("MAX_CODE_UNPACKED_MB", "500"))
FIX_CONCURRENCY = max(1, int(os.getenv("FIX_CONCURRENCY", "10")))  # parallel AI calls for "Generate all" fixes
AI_BATCH_CONCURRENCY = max(1, int(os.getenv("AI_BATCH_CONCURRENCY", "5")))  # parallel AI calls per batch review
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()                 # sentinel.* loggers (AI call details, jobs)
AI_READ_TIMEOUT = float(os.getenv("AI_READ_TIMEOUT", "300"))        # seconds to wait for data from an AI provider

# Postgres + Celery
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://sentinel:sentinel@localhost:5432/sentinel")
DB_POOL_MIN = int(os.getenv("DB_POOL_MIN", "1"))
DB_POOL_MAX = int(os.getenv("DB_POOL_MAX", "10"))
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", os.getenv("REDIS_URL", "redis://localhost:6379/0"))
CELERY_QUEUE = os.getenv("CELERY_QUEUE", "sentinel")
JOB_TIME_LIMIT = int(os.getenv("JOB_TIME_LIMIT", "7200"))           # hard limit per background job (seconds)
JOB_MAX_AI_CALLS = int(os.getenv("JOB_MAX_AI_CALLS", "300"))      # AI calls one job may make (0 = unlimited)

# Auth
APP_SECRET_KEY = os.getenv("APP_SECRET_KEY", "")                  # encrypts stored workspace secrets (required)
SESSION_COOKIE = os.getenv("SESSION_COOKIE", "sentinel_session")
SESSION_TTL_HOURS = float(os.getenv("SESSION_TTL_HOURS", "12"))     # idle timeout (sliding)
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() in ("1", "true", "yes")
ALLOW_REGISTRATION = os.getenv("ALLOW_REGISTRATION", "true").lower() in ("1", "true", "yes")
DEMO_USER_ENABLED = os.getenv("DEMO_USER_ENABLED", "false").lower() in ("1", "true", "yes")
VERIFY_CODE_TTL_MINUTES = int(os.getenv("VERIFY_CODE_TTL_MINUTES", "15"))
MAX_LOGIN_FAILURES = int(os.getenv("MAX_LOGIN_FAILURES", "5"))
LOCKOUT_MINUTES = int(os.getenv("LOCKOUT_MINUTES", "15"))
ENABLE_DOCS = os.getenv("ENABLE_DOCS", "true").lower() in ("1", "true", "yes")

# Workspace AI defaults (non-secret) - each workspace sets its own provider, model and API keys in Settings.
AI_DEFAULTS = {
    "ai_provider": os.getenv("AI_PROVIDER", "heuristic"),
    "ai_model": os.getenv("AI_MODEL", ""),
    "openai_api_key": "",
    "openai_base_url": os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
    "anthropic_api_key": "",
    "gemini_api_key": "",
    "ollama_base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
    "gitlab_base_url": os.getenv("GITLAB_BASE_URL", "https://gitlab.com"),
    "gitlab_username": "oauth2",
    "gitlab_token": "",
}
SECRET_SETTINGS = ("openai_api_key", "anthropic_api_key", "gemini_api_key", "gitlab_token")

DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-sonnet-4-5",
    "gemini": "gemini-2.5-flash",
    "ollama": "llama3.1",
    "heuristic": "",
}
