"""FastAPI application entrypoint."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import db
from .api import router
from .api_auth import router as auth_router
from .api_devil import router as devil_router
from .api_files import router as files_router
from .api_fixes import router as fixes_router
from .api_frameworks import router as frameworks_router
from .api_items import router as items_router
from .api_jobs import router as jobs_router
from .api_mappings import router as mappings_router
from .api_threat_models import router as threat_models_router
from .api_threats import router as threats_router
from .auth import authorize
from .catalog import get_catalog
from .config import COOKIE_SECURE, ENABLE_DOCS, LOG_LEVEL, STATIC_DIR

_sentinel_log = logging.getLogger("sentinel")
if not _sentinel_log.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S"))
    _sentinel_log.addHandler(_handler)
    _sentinel_log.setLevel(LOG_LEVEL)
    _sentinel_log.propagate = False


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.pool()
    get_catalog()  # fail fast if the catalog hasn't been built
    yield
    db.close_pool()


app = FastAPI(title="AI Security Review", version="0.3.0", lifespan=lifespan,
              docs_url="/docs" if ENABLE_DOCS else None, redoc_url=None,
              openapi_url="/openapi.json" if ENABLE_DOCS else None)
app.include_router(auth_router)
for r in (router, items_router, files_router, mappings_router, threats_router, threat_models_router,
          frameworks_router, fixes_router, devil_router, jobs_router):
    app.include_router(r, dependencies=[Depends(authorize)])


# The SPA loads scripts only from itself and the Mermaid CDN; inline styles are used throughout the views.
APP_CSP = ("default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
           "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; "
           "img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; "
           "frame-ancestors 'none'")
# Swagger UI is served from the CDN with an inline bootstrap script.
DOCS_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
            "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
# API responses are data, never pages: nothing in them may run or load (PDFs are exempt so the viewer works).
API_CSP = "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    path, h = request.url.path, response.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Referrer-Policy", "same-origin")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
    h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if COOKIE_SECURE:
        h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if path.startswith("/api/"):
        h.setdefault("Cache-Control", "no-store")
        if not h.get("content-type", "").startswith("application/pdf"):
            h.setdefault("Content-Security-Policy", API_CSP)
    else:
        h.setdefault("Content-Security-Policy", DOCS_CSP if path.startswith("/docs") else APP_CSP)
    if path == "/" or path.startswith("/static/"):
        h["Cache-Control"] = "no-cache"  # revalidate SPA assets so UI updates are picked up immediately
    return response


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")
