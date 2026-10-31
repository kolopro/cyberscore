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
import re
import time
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from scanner import netguard
from scanner.engine import scan
from scanner.utils import normalize_target
from scanner import remediation
from scanner.tls import checker as tls_checker
from scanner.email_headers import analyzer as header_analyzer
from scanner.urlcheck import analyze as analyze_url
from scanner.urlcheck import shot as url_shot
from scanner.reputation import check as reputation_check
from reports import pdf as pdf_report

# Block outbound requests to private / internal / metadata addresses for the
# whole web process. The public API is untrusted input, so this closes SSRF
# across the http checker, the url live-fetch and the reputation providers.
netguard.install()

app = FastAPI(
    title="CyberScore",
    version="0.1",
    description="Passive, non-invasive website security scanner (cyberscore.cc).",
)

_STATIC = Path(__file__).parent / "static"

# Request body ceilings (reject obvious abuse before doing any work).
_MAX_HEADERS_LEN = 100_000   # pasted email headers
_MAX_URL_LEN = 4_000         # URL to analyse

# --- very light in-memory rate limit (per client, best-effort) --------------
_RECENT: Dict[str, float] = {}
_MIN_INTERVAL = 3.0  # seconds between requests from the same client
_MAX_TRACKED = 10_000  # cap the dict so it cannot grow without bound


class ScanRequest(BaseModel):
    target: str


class HeadersRequest(BaseModel):
    headers: str


class UrlRequest(BaseModel):
    url: str
    screenshot: bool = True


def _stamp() -> str:
    return "Generated " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M")


def _client_ip(request: Request) -> str:
    """Real client IP, honouring the X-Forwarded-For set by the Caddy proxy."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "?"


def _rate_ok(client: str) -> bool:
    now = time.time()
    last = _RECENT.get(client, 0.0)
    if now - last < _MIN_INTERVAL:
        return False
    _RECENT[client] = now
    if len(_RECENT) > _MAX_TRACKED:
        cutoff = now - 3600
        for k in [k for k, v in _RECENT.items() if v < cutoff]:
            _RECENT.pop(k, None)
    return True


def _enforce_rate(request: Request) -> None:
    if not _rate_ok(_client_ip(request)):
        raise HTTPException(status_code=429,
                            detail="Too many requests — slow down a little.")


def _require_public(host: str) -> None:
    """Refuse to point the scanner at private / internal / metadata hosts.

    Covers TLS and DNS probing too, which connect at the socket level and are
    not caught by the urllib3 connect guard.
    """
    if not netguard.host_is_public(host):
        raise HTTPException(
            status_code=400,
            detail="This scanner only accepts public hosts.")


@app.get("/api/health")
def health() -> Dict[str, Any]:
    return {"status": "ok"}


@app.post("/api/scan")
def api_scan(req: ScanRequest, request: Request) -> JSONResponse:
    """Run a passive scan and return the structured result + remediation plan."""
    _enforce_rate(request)
    try:
        host = normalize_target(req.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    _require_public(host)

    result = scan(host)
    payload = result.to_dict()
    payload["remediation"] = remediation.build_plan(result.all_findings)
    payload["scanned_at"] = _stamp()
    return JSONResponse(payload)


@app.post("/api/analyze-headers")
def api_headers(req: HeadersRequest, request: Request) -> JSONResponse:
    """Analyze pasted raw email headers for auth results + spoofing signals."""
    _enforce_rate(request)
    if not (req.headers or "").strip():
        raise HTTPException(status_code=400, detail="No headers provided.")
    if len(req.headers) > _MAX_HEADERS_LEN:
        raise HTTPException(status_code=413, detail="Headers too large.")
    mod = header_analyzer.analyze(req.headers)
    payload = mod.to_dict()
    payload["remediation"] = remediation.build_plan(mod.findings)
    payload["scanned_at"] = _stamp()
    return JSONResponse(payload)


@app.post("/api/analyze-url")
def api_url(req: UrlRequest, request: Request) -> JSONResponse:
    """Passively analyse a URL for phishing/malicious signals + reputation."""
    _enforce_rate(request)
    if not (req.url or "").strip():
        raise HTTPException(status_code=400, detail="No URL provided.")
    if len(req.url) > _MAX_URL_LEN:
        raise HTTPException(status_code=413, detail="URL too long.")
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


@app.post("/api/tls-deep")
def api_tls_deep(req: ScanRequest, request: Request) -> JSONResponse:
    """Run the slower, SSL-Labs-style deep TLS assessment on demand."""
    _enforce_rate(request)
    try:
        host = normalize_target(req.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    _require_public(host)

    mod = tls_checker.run_deep(host)
    payload = mod.to_dict()
    payload["target"] = host
    payload["remediation"] = remediation.build_plan(mod.findings)
    payload["scanned_at"] = _stamp()
    return JSONResponse(payload)


@app.get("/api/report.pdf")
def api_report(request: Request, target: str = Query(..., description="Domain to report on")):
    _enforce_rate(request)
    try:
        host = normalize_target(target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    _require_public(host)

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


@app.get("/el")
def index_el() -> FileResponse:
    return FileResponse(_STATIC / "el.html")


@app.get("/contact")
def contact() -> FileResponse:
    return FileResponse(_STATIC / "contact.html")


@app.get("/guides")
def guides() -> FileResponse:
    return FileResponse(_STATIC / "guides.html")


@app.get("/guides/{slug}")
def guide(slug: str) -> FileResponse:
    # slug is restricted to a safe charset, so no path traversal is possible.
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", slug):
        raise HTTPException(status_code=404, detail="Guide not found")
    path = _STATIC / f"guide-{slug}.html"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Guide not found")
    return FileResponse(path)


@app.get("/ads.txt")
def ads_txt() -> FileResponse:
    return FileResponse(_STATIC / "ads.txt", media_type="text/plain")


@app.get("/robots.txt")
def robots_txt() -> FileResponse:
    return FileResponse(_STATIC / "robots.txt", media_type="text/plain")


@app.get("/sitemap.xml")
def sitemap_xml() -> FileResponse:
    return FileResponse(_STATIC / "sitemap.xml", media_type="application/xml")


# Serve any other static assets (currently just index.html lives here).
app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")
