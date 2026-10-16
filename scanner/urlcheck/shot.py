"""Optional page screenshot for the URL check.

Uses Playwright/Chromium if it is installed; otherwise returns None so the web
app degrades gracefully (the URL analysis still works, just without a preview).
The target host is SSRF-guarded here too: we never screenshot a private or
internal address.
"""
from __future__ import annotations

import base64
import ipaddress
import socket
from typing import Optional
from urllib.parse import urlsplit


def _public_host(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        return False
    try:
        try:
            ip = host.strip("[]")
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = ipaddress.ip_address(socket.gethostbyname(host))
        return not (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_reserved or addr.is_multicast or addr.is_unspecified)
    except (OSError, ValueError):
        return False


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
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox"])
            try:
                page = browser.new_page(
                    viewport={"width": width, "height": height},
                    user_agent=("Mozilla/5.0 (compatible; CyberScore/1.0; "
                                "+https://cyberscore.cc)"),
                )
                page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                page.wait_for_timeout(1200)
                png = page.screenshot(type="png")
            finally:
                browser.close()
        return "data:image/png;base64," + base64.b64encode(png).decode("ascii")
    except Exception:
        return None
