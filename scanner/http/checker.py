"""HTTP/HTTPS passive checks: redirects, security headers, cookies, server info."""
from __future__ import annotations

from typing import Optional

import requests

from config import settings
from scanner.models import ModuleResult, Severity, Status


def _get(url: str, allow_redirects: bool = True) -> Optional[requests.Response]:
    try:
        return requests.get(
            url,
            timeout=settings.HTTP_TIMEOUT,
            allow_redirects=allow_redirects,
            headers={"User-Agent": settings.USER_AGENT},
        )
    except requests.RequestException:
        return None


def run(host: str) -> ModuleResult:
    result = ModuleResult(name="http")

    http_resp = _get(f"http://{host}/", allow_redirects=False)
    https_resp = _get(f"https://{host}/", allow_redirects=True)

    # --- HTTPS availability -------------------------------------------------
    if https_resp is not None:
        result.add_check("https", "HTTPS reachable", Status.OK,
                         f"HTTP {https_resp.status_code}")
        result.data["https_available"] = True
        result.data["final_url"] = https_resp.url
    else:
        result.add_check("https", "HTTPS reachable", Status.FAIL,
                         "no successful HTTPS response")
        result.data["https_available"] = False
        result.add_finding(
            Severity.HIGH, "Site is not reachable over HTTPS",
            "Enable TLS and serve the site over HTTPS.",
            code="http.no_https",
        )

    # --- HTTP -> HTTPS redirect --------------------------------------------
    if http_resp is not None:
        loc = http_resp.headers.get("location", "")
        redirects_to_https = (
            http_resp.is_redirect and loc.lower().startswith("https://")
        )
        result.data["http_status"] = http_resp.status_code
        result.data["http_redirect_location"] = loc
        if redirects_to_https:
            result.add_check("redirect", "HTTP redirects to HTTPS", Status.OK, loc)
        elif https_resp is not None:
            result.add_check("redirect", "HTTP redirects to HTTPS", Status.FAIL,
                             f"HTTP {http_resp.status_code} -> {loc or 'no redirect'}")
            result.add_finding(
                Severity.MEDIUM, "Plain HTTP does not redirect to HTTPS",
                "Return a 301 redirect from http:// to https:// for all paths.",
                evidence=f"http status {http_resp.status_code}",
                code="http.no_redirect",
            )
    else:
        result.add_check("redirect", "HTTP redirects to HTTPS", Status.INFO,
                         "port 80 not answering")

    # From here on, work against the HTTPS response if we have one.
    resp = https_resp or http_resp
    if resp is None:
        result.error = "No HTTP or HTTPS response from host."
        return result

    headers = {k.lower(): v for k, v in resp.headers.items()}

    # --- Server / technology-relevant headers ------------------------------
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    result.data["server"] = server
    result.data["x_powered_by"] = powered
    result.data["headers"] = headers
    if server:
        result.add_check("server", "Server header", Status.INFO, server)
    if powered:
        # Exposing framework/version is minor information disclosure.
        result.add_check("powered_by", "X-Powered-By exposed", Status.WARN, powered)
        result.add_finding(
            Severity.LOW, "X-Powered-By header discloses stack details",
            "Remove or obfuscate the X-Powered-By header.",
            evidence=powered,
            code="http.powered_by",
        )

    # --- Security headers ---------------------------------------------------
    for hkey, (label, sev) in settings.SECURITY_HEADERS.items():
        if hkey in headers:
            result.add_check(hkey, label, Status.OK)
        else:
            result.add_check(hkey, label, Status.FAIL, "missing")
            result.add_finding(
                Severity[sev], f"Missing security header: {label}",
                f"Add the {label} response header.",
                code=f"http.header.{hkey}",
            )

    # --- Cookies ------------------------------------------------------------
    _audit_cookies(resp, result)

    return result


def _audit_cookies(resp: "requests.Response", result: ModuleResult) -> None:
    raw_cookies = resp.raw.headers.getlist("Set-Cookie") if resp.raw else []
    if not raw_cookies:
        # Fall back to the parsed jar.
        raw_cookies = [
            f"{c.name}={c.value}; " +
            ("secure; " if c.secure else "") +
            ("httponly; " if c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly") else "")
            for c in resp.cookies
        ]
    if not raw_cookies:
        result.add_check("cookies", "Cookies set", Status.INFO, "none observed")
        return

    insecure = []
    for raw in raw_cookies:
        low = raw.lower()
        name = raw.split("=", 1)[0].strip()
        missing = [f for f in settings.COOKIE_FLAGS if f not in low]
        if missing:
            insecure.append((name, missing))

    result.data["cookies_count"] = len(raw_cookies)
    if not insecure:
        result.add_check("cookies", "Cookie security flags", Status.OK,
                         f"{len(raw_cookies)} cookie(s), all flagged")
    else:
        sample = ", ".join(f"{n} (missing {'/'.join(m)})" for n, m in insecure[:3])
        result.add_check("cookies", "Cookie security flags", Status.WARN, sample)
        result.add_finding(
            Severity.LOW, "Cookies missing security flags",
            "Set Secure, HttpOnly and SameSite on session cookies.",
            evidence=sample,
            code="http.cookie_flags",
        )
