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
DB_PATH = Path(os.getenv("DB_PATH", DATA_DIR / "reviews.db"))
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", DATA_DIR / "uploads"))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "100"))          # per file / archive
MAX_CODE_FILES = int(os.getenv("MAX_CODE_FILES", "20000"))      # files extracted from an archive
MAX_CODE_UNPACKED_MB = int(os.getenv("MAX_CODE_UNPACKED_MB", "500"))

# AI defaults - every value can be overridden from the Settings page (stored in SQLite).
AI_DEFAULTS = {
    "ai_provider": os.getenv("AI_PROVIDER", "heuristic"),
    "ai_model": os.getenv("AI_MODEL", ""),
    "openai_api_key": os.getenv("OPENAI_API_KEY", ""),
    "openai_base_url": os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
    "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY", ""),
    "gemini_api_key": os.getenv("GEMINI_API_KEY", os.getenv("GOOGLE_API_KEY", "")),
    "ollama_base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
}

DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-sonnet-4-5",
    "gemini": "gemini-2.5-flash",
    "ollama": "llama3.1",
    "heuristic": "",
}
