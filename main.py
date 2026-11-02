"""Run the AI Security Review tool.

    python main.py            # http://127.0.0.1:8000
    python main.py --reload   # auto-reload while developing
"""
import argparse
import sys
from pathlib import Path

import uvicorn

ROOT = Path(__file__).resolve().parent

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--reload", action="store_true")
    args = ap.parse_args()

    if not (ROOT / "data" / "catalog.json").exists():
        print("Catalog not built yet - run:  python scripts/build_catalog.py", file=sys.stderr)
        sys.exit(1)
    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload)
