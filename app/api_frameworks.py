"""REST API for requirement frameworks (NIST CSF 2.0 plus catalog/frameworks/*.yaml)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from .catalog import get_catalog
from .frameworks import framework_meta, framework_tree

router = APIRouter(prefix="/api")


@router.get("/frameworks")
def list_frameworks():
    return get_catalog().frameworks


@router.get("/frameworks/{fid}/tree")
def framework_tree_view(fid: str):
    cat = get_catalog()
    if not framework_meta(cat, fid):
        raise HTTPException(404, "Unknown framework")
    return framework_tree(cat, fid)
