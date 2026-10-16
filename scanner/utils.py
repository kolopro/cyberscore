"""Small shared helpers."""
from __future__ import annotations

from urllib.parse import urlparse


def normalize_target(raw: str) -> str:
    """Return a bare hostname from user input like 'https://example.com/path'."""
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty target")
    if "://" not in raw:
        raw = "http://" + raw
    host = urlparse(raw).hostname or ""
    host = host.strip().lower()
    if host.startswith("www.") and host.count(".") > 1:
        # keep www variant available but scanning the apex is usually intended;
        # we still scan whatever the user gave via HTTP module following redirects.
        pass
    if not host:
        raise ValueError(f"Could not parse a hostname from: {raw!r}")
    return host


def registrable_domain(host: str) -> str:
    """Best-effort apex domain (no public-suffix list dependency in v0.1).

    For 'www.shop.example.co.uk' this returns 'example.co.uk' when a known
    two-level TLD is detected, else the last two labels.
    """
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    two_level_tlds = {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.au", "net.au",
        "org.au", "co.nz", "com.br", "com.tr", "gr.com", "co.in", "co.za",
    }
    last_two = ".".join(labels[-2:])
    last_three = ".".join(labels[-3:])
    if last_two in two_level_tlds:
        return last_three
    return last_two
