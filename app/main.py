"""FastAPI application entrypoint."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import db, jobs
from .api import router
from .api_files import router as files_router
from .api_frameworks import router as frameworks_router
from .api_items import router as items_router
from .api_mappings import router as mappings_router
from .api_threat_models import router as threat_models_router
from .api_threats import router as threats_router
from .catalog import get_catalog
from .config import STATIC_DIR


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    jobs.reset_stale()
    get_catalog()  # fail fast if the catalog hasn't been built
    yield


app = FastAPI(title="AI Security Review", version="0.2.0", lifespan=lifespan)
app.include_router(router)
app.include_router(items_router)
app.include_router(files_router)
app.include_router(mappings_router)
app.include_router(threats_router)
app.include_router(threat_models_router)
app.include_router(frameworks_router)


@app.middleware("http")
async def no_stale_assets(request: Request, call_next):
    """Make browsers revalidate the SPA assets so UI updates are picked up immediately."""
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache"
    return response


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")
