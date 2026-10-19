"""FastAPI web application for Security Scanner v0.1.

Wraps the exact same passive engine used by the CLI. Endpoints:

    GET  /                 -> single-page frontend
    POST /api/scan         -> run a scan, return JSON (result + remediation plan)
    GET  /api/report.pdf   -> download the PDF report for a target
    GET  /api/health       -> liveness probe

Run:  uvicorn web.app:app --reload   (or: python run_web.py)

This keeps zero scanning logic of its own — it just calls scanner.engine.scan,
so the CLI, this web app and a future SaaS all share one engine.
"""
from __future__ import annotations

import datetime
import time
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from scanner.engine import scan
from scanner.utils import normalize_target
from scanner import remediation
from scanner.email_headers import analyzer as header_analyzer
from scanner.urlcheck import analyze as analyze_url
from scanner.urlcheck import shot as url_shot
from scanner.reputation import check as reputation_check
from reports import pdf as pdf_report

app = FastAPI(
    title="CyberScore",
    version="0.1",
    description="Passive, non-invasive website security scanner (cyberscore.cc).",
)

_STATIC = Path(__file__).parent / "static"

# --- very light in-memory rate limit (per client, best-effort) --------------
_RECENT: Dict[str, float] = {}
_MIN_INTERVAL = 3.0  # seconds between scans from the same client


class ScanRequest(BaseModel):
    target: str


class HeadersRequest(BaseModel):
    headers: str


class UrlRequest(BaseModel):
    url: str
    screenshot: bool = True


def _stamp() -> str:
    return "Generated " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M")


def _rate_ok(client: str) -> bool:
    now = time.time()
    last = _RECENT.get(client, 0.0)
    if now - last < _MIN_INTERVAL:
        return False
    _RECENT[client] = now
    return True


@app.get("/api/health")
def health() -> Dict[str, Any]:
    return {"status": "ok"}


@app.post("/api/scan")
def api_scan(req: ScanRequest, request_host: str = "") -> JSONResponse:
    """Run a passive scan and return the structured result + remediation plan."""
    try:
        host = normalize_target(req.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    result = scan(host)
    payload = result.to_dict()
    payload["remediation"] = remediation.build_plan(result.all_findings)
    payload["scanned_at"] = _stamp()
    return JSONResponse(payload)


@app.post("/api/analyze-headers")
def api_headers(req: HeadersRequest) -> JSONResponse:
    """Analyze pasted raw email headers for auth results + spoofing signals."""
    if not (req.headers or "").strip():
        raise HTTPException(status_code=400, detail="No headers provided.")
    mod = header_analyzer.analyze(req.headers)
    payload = mod.to_dict()
    payload["remediation"] = remediation.build_plan(mod.findings)
    payload["scanned_at"] = _stamp()
    return JSONResponse(payload)


@app.post("/api/analyze-url")
def api_url(req: UrlRequest) -> JSONResponse:
    """Passively analyse a URL for phishing/malicious signals + reputation."""
    if not (req.url or "").strip():
        raise HTTPException(status_code=400, detail="No URL provided.")
    mod = analyze_url(req.url)
    payload = mod.to_dict()
    payload["remediation"] = remediation.build_plan(mod.findings)
    # Multi-engine reputation (falls back to heuristics, never fails).
    payload["reputation"] = reputation_check(mod.data.get("normalized", req.url))
    # Optional page screenshot (None if Playwright absent / non-public host).
    if req.screenshot:
        payload["screenshot"] = url_shot.capture(
            mod.data.get("final_url") or mod.data.get("normalized", "")
        )
    payload["scanned_at"] = _stamp()
    return JSONResponse(payload)


@app.get("/api/report.pdf")
def api_report(target: str = Query(..., description="Domain to report on")):
    try:
        host = normalize_target(target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    result = scan(host)
    data = pdf_report.render_bytes(result, generated_at=_stamp())
    filename = pdf_report.default_filename(host)
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_STATIC / "index.html")


@app.get("/privacy")
def privacy() -> FileResponse:
    return FileResponse(_STATIC / "privacy.html")


@app.get("/ads.txt")
def ads_txt() -> FileResponse:
    return FileResponse(_STATIC / "ads.txt", media_type="text/plain")


# Serve any other static assets (currently just index.html lives here).
app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")
