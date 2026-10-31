"""Optional page screenshot for the URL check.

Uses Playwright/Chromium if it is installed; otherwise returns None so the web
app degrades gracefully (the URL analysis still works, just without a preview).
The target host is SSRF-guarded here too: we never screenshot a private or
internal address.
"""
from __future__ import annotations

import base64
import os
import threading
from typing import Optional
from urllib.parse import urlsplit

from scanner import netguard

# Chromium is heavy: cap how many screenshots render at once so a burst of
# requests cannot exhaust the host's CPU/RAM. Tunable via env.
_MAX_CONCURRENT = max(1, int(os.environ.get("CYBERSCORE_MAX_SHOTS", "2")))
_SEMAPHORE = threading.BoundedSemaphore(_MAX_CONCURRENT)


def _public_host(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return netguard.host_is_public(host)


def capture(url: str, width: int = 1024, height: int = 720,
            timeout_ms: int = 12000) -> Optional[str]:
    """Return a data: URL (PNG, base64) of the page, or None if unavailable.

    Never raises; any problem (Playwright missing, timeout, nav error, non-public
    host) just yields None.
    """
    if not url.lower().startswith(("http://", "https://")):
        return None
    if not _public_host(url):
        return None
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return None

    # Back off instead of queueing when all render slots are busy.
    if not _SEMAPHORE.acquire(blocking=False):
        return None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox"])
            try:
                page = browser.new_page(
                    viewport={"width": width, "height": height},
                    user_agent=("Mozilla/5.0 (compatible; CyberScore/1.0; "
                                "+https://cyberscore.cc)"),
                )
                # SSRF guard for the browser process: abort any navigation or
                # sub-request (including redirects) to a non-public host, since
                # the urllib3 connect guard cannot reach Chromium's own sockets.
                def _guard(route):
                    h = (urlsplit(route.request.url).hostname or "").lower()
                    if netguard.host_is_public(h):
                        route.continue_()
                    else:
                        route.abort()

                page.route("**/*", _guard)
                page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                page.wait_for_timeout(1200)
                png = page.screenshot(type="png")
            finally:
                browser.close()
        return "data:image/png;base64," + base64.b64encode(png).decode("ascii")
    except Exception:
        return None
    finally:
        _SEMAPHORE.release()
