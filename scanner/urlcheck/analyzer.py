"""Passive URL safety analysis.

Given a URL, this inspects its structure for the signals phishing and malicious
links commonly exhibit — no page is treated as trusted, nothing is executed —
then does ONE safe HEAD/GET to observe the redirect chain and final location.
A deterministic verdict (Safe / Caution / Suspicious) is produced from the
findings, mirroring the scanner's existing ModuleResult shape so the same
remediation + rendering pipeline works unchanged.

Only passive, non-invasive behaviour: a single GET with redirects followed,
short timeout, no crawling, no active probing of the target.
"""
from __future__ import annotations

import ipaddress
import re
from typing import List, Optional, Tuple
from urllib.parse import urlsplit, unquote

import requests

from scanner import netguard
from scanner.models import ModuleResult, Severity, Status

# URL shorteners: they hide the real destination until you follow them.
_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly", "t.ly", "bl.ink",
    "tiny.cc", "lnkd.in", "trib.al", "soo.gd", "clck.ru", "v.gd", "qr.ae",
}

# TLDs disproportionately abused for phishing / malware (heuristic, not a block).
_RISKY_TLDS = {
    "zip", "mov", "xyz", "top", "gq", "cf", "ml", "ga", "tk", "work",
    "click", "link", "country", "kim", "loan", "men", "download", "stream",
    "racing", "review", "date", "faith", "science", "party", "rest", "cam",
}

# Words that in a hostname/path often front credential-harvesting pages.
_PHISH_WORDS = (
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "webscr", "wallet", "recover", "unlock", "billing", "invoice", "suspend",
)

_KNOWN_SCHEMES = {"http", "https", "ftp", "mailto", "javascript", "data", "file"}
_UA = "Mozilla/5.0 (compatible; CyberScore/1.0; +https://cyberscore.cc)"


def _normalize(raw: str) -> str:
    """Add a scheme only when the input clearly lacks one (keep known schemes)."""
    raw = (raw or "").strip()
    if not raw:
        return raw
    # Already has a scheme like "http:", "javascript:", "mailto:"?
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):", raw)
    if m and m.group(1).lower() in _KNOWN_SCHEMES:
        return raw
    if "://" in raw:
        return raw
    # Bare input (no scheme typed) — assume HTTPS; don't penalise for a scheme
    # the user never chose. An explicit http:// is still honoured and flagged.
    return "https://" + raw


def _registrable(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _resolve_public(host: str) -> Tuple[Optional[str], bool]:
    """Resolve host → (ip, is_public). is_public False for private/loopback/etc.

    Delegates to the shared netguard so the "is this internal?" reporting here
    uses exactly the same ranges the connect-time SSRF guard enforces.
    """
    ips = netguard.resolve_host(host)
    if not ips:
        return None, False
    return ips[0], netguard.host_is_public(host)


def analyze(raw_url: str, fetch: bool = True) -> ModuleResult:
    result = ModuleResult(name="url")
    url = _normalize(raw_url)
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()

    result.data["input"] = raw_url
    result.data["normalized"] = url
    result.data["scheme"] = scheme

    # --- dangerous / non-web schemes ---------------------------------------
    if scheme in ("javascript", "data"):
        result.add_check("scheme", "URL scheme", Status.FAIL, f"{scheme}: URI")
        result.add_finding(
            Severity.HIGH,
            f"Dangerous '{scheme}:' URL",
            evidence=url[:120],
            code="url.dangerous_scheme",
        )
        result.data["host"] = ""
        _attach_verdict(result)
        return result

    host = (parts.hostname or "").lower()
    result.data["host"] = host
    result.data["port"] = parts.port
    result.data["path"] = parts.path or "/"

    if not host:
        result.add_check("host", "Hostname", Status.FAIL, "no host in URL")
        result.add_finding(Severity.MEDIUM, "URL has no hostname",
                           evidence=url[:120], code="url.no_host")
        _attach_verdict(result)
        return result

    # --- HTTPS -------------------------------------------------------------
    if scheme == "https":
        result.add_check("https", "Uses HTTPS", Status.OK, "encrypted")
    else:
        result.add_check("https", "Uses HTTPS", Status.WARN, f"{scheme}://")
        result.add_finding(Severity.MEDIUM, "Link does not use HTTPS",
                           evidence=f"{scheme}://{host}", code="url.no_https")

    # --- userinfo (user@host) ----------------------------------------------
    if parts.username is not None:
        result.add_check("userinfo", "Embedded credentials", Status.FAIL,
                         f"{parts.username}@…")
        result.add_finding(
            Severity.HIGH,
            "URL contains an '@' before the host",
            evidence=url[:120], code="url.userinfo",
        )
    else:
        result.add_check("userinfo", "Embedded credentials", Status.OK, "none")

    # --- IP literal host ----------------------------------------------------
    if _is_ip_host(host):
        result.add_check("ip_host", "Host is a raw IP", Status.WARN, host)
        result.add_finding(
            Severity.MEDIUM, "Link points at a raw IP address, not a domain",
            evidence=host, code="url.ip_host",
        )
    else:
        result.add_check("ip_host", "Host is a domain name", Status.OK, host)

    # --- punycode / IDN homograph ------------------------------------------
    if "xn--" in host:
        result.add_check("punycode", "Internationalised (punycode) host",
                         Status.WARN, host)
        result.add_finding(
            Severity.MEDIUM,
            "Host uses punycode (possible look-alike domain)",
            evidence=host, code="url.punycode",
        )
    else:
        result.add_check("punycode", "Internationalised (punycode) host",
                         Status.OK, "no")

    # --- subdomain depth ----------------------------------------------------
    labels = host.split(".")
    depth = max(0, len(labels) - 2)
    result.data["subdomain_depth"] = depth
    if depth >= 4:
        result.add_check("subdomains", "Subdomain depth", Status.WARN,
                         f"{depth} levels")
        result.add_finding(
            Severity.LOW,
            "Unusually deep subdomain chain",
            evidence=host, code="url.many_subdomains",
        )
    else:
        result.add_check("subdomains", "Subdomain depth", Status.OK,
                         f"{depth} level{'s' if depth != 1 else ''}")

    # --- shortener ----------------------------------------------------------
    reg = _registrable(host)
    if reg in _SHORTENERS:
        result.add_check("shortener", "URL shortener", Status.WARN, reg)
        result.add_finding(
            Severity.LOW,
            "Link uses a URL shortener (destination hidden)",
            evidence=reg, code="url.shortener",
        )
    else:
        result.add_check("shortener", "URL shortener", Status.OK, "no")

    # --- risky TLD ----------------------------------------------------------
    tld = labels[-1] if labels else ""
    if tld in _RISKY_TLDS:
        result.add_check("tld", "Top-level domain", Status.WARN, f".{tld}")
        result.add_finding(
            Severity.LOW,
            f"Domain uses a frequently-abused TLD (.{tld})",
            evidence=host, code="url.risky_tld",
        )
    else:
        result.add_check("tld", "Top-level domain", Status.OK, f".{tld}" if tld else "—")

    # --- non-standard port --------------------------------------------------
    if parts.port and parts.port not in (80, 443):
        result.add_check("port", "Network port", Status.WARN, str(parts.port))
        result.add_finding(
            Severity.LOW, f"Link uses a non-standard port ({parts.port})",
            evidence=url[:120], code="url.odd_port",
        )

    # --- phishing-style keywords -------------------------------------------
    hay = (host + " " + unquote(parts.path or "")).lower()
    hits = sorted({w for w in _PHISH_WORDS if w in hay})
    if hits:
        result.add_check("keywords", "Sensitive keywords in URL", Status.WARN,
                         ", ".join(hits))
        result.add_finding(
            Severity.LOW,
            "URL contains credential/payment keywords often used in phishing",
            evidence=", ".join(hits), code="url.phish_words",
        )
    else:
        result.add_check("keywords", "Sensitive keywords in URL", Status.OK, "none")

    # --- excessive length ---------------------------------------------------
    if len(url) > 120:
        result.add_check("length", "URL length", Status.WARN, f"{len(url)} chars")
        result.add_finding(Severity.LOW, "Very long URL (can hide the real target)",
                           evidence=f"{len(url)} characters", code="url.long")

    # --- live redirect check (single, safe, SSRF-guarded) ------------------
    if fetch and scheme in ("http", "https"):
        _live_check(result, url, host)

    _attach_verdict(result)
    return result


def _live_check(result: ModuleResult, url: str, host: str) -> None:
    ip, public = _resolve_public(host)
    result.data["resolved_ip"] = ip
    if ip is None:
        result.add_check("resolve", "Domain resolves", Status.FAIL,
                         "could not resolve")
        result.add_finding(Severity.LOW, "Host does not resolve in DNS",
                           evidence=host, code="url.no_resolve")
        return
    if not public:
        # SSRF guard: never fetch internal / private targets.
        result.add_check("resolve", "Domain resolves", Status.WARN,
                         f"{ip} (private/internal)")
        result.data["fetch_skipped"] = "non-public address"
        return
    result.add_check("resolve", "Domain resolves", Status.OK, ip)

    try:
        r = requests.get(url, timeout=8, allow_redirects=True,
                         headers={"User-Agent": _UA}, stream=True)
        chain = [resp.headers.get("Location", resp.url) for resp in r.history]
        final = r.url
        r.close()
    except requests.RequestException as exc:
        result.add_check("reachable", "Page reachable", Status.WARN,
                         type(exc).__name__)
        result.data["fetch_error"] = str(exc)[:160]
        return

    result.add_check("reachable", "Page reachable", Status.OK,
                     f"HTTP {r.status_code}")
    result.data["final_url"] = final
    result.data["redirects"] = chain

    final_host = (urlsplit(final).hostname or "").lower()
    result.data["final_host"] = final_host
    if final_host and _registrable(final_host) != _registrable(host):
        result.add_check("redirect", "Redirects off-site", Status.WARN,
                         f"→ {final_host}")
        result.add_finding(
            Severity.MEDIUM,
            "Link redirects to a different domain",
            evidence=f"{host} → {final_host}", code="url.cross_redirect",
        )
    elif chain:
        result.add_check("redirect", "Redirects", Status.INFO,
                         f"{len(chain)} hop(s), same site")
    else:
        result.add_check("redirect", "Redirects off-site", Status.OK, "no")

    # downgrade https -> http on the way
    if url.lower().startswith("https://") and final.lower().startswith("http://"):
        result.add_finding(
            Severity.MEDIUM, "Redirect downgrades HTTPS to HTTP",
            evidence=f"{url} → {final}", code="url.downgrade",
        )


def _attach_verdict(result: ModuleResult) -> None:
    """Deterministic Safe / Caution / Suspicious verdict from the findings."""
    sev = [f.severity for f in result.findings]
    highs = sum(1 for s in sev if s == Severity.HIGH)
    meds = sum(1 for s in sev if s == Severity.MEDIUM)
    lows = sum(1 for s in sev if s == Severity.LOW)

    if highs or meds >= 2 or (meds >= 1 and lows >= 2):
        level, title = "suspicious", "Suspicious — do not trust this link"
        summary = ("This link shows strong signs of a phishing or malicious URL. "
                   "Do not enter credentials or download anything from it.")
    elif meds == 1 or lows >= 1:
        level, title = "caution", "Caution — verify before trusting"
        summary = ("Some warning signs are present. Make sure you know and trust "
                   "the sender before opening or acting on this link.")
    else:
        level, title = "safe", "No major red flags found"
        summary = ("The structure looks normal. This is not a guarantee of safety — "
                   "still confirm the sender and the destination domain.")

    reasons = [f.title for f in result.findings][:6]
    next_steps = _next_steps(level, result)
    result.data["verdict"] = {
        "level": level, "title": title, "summary": summary,
        "reasons": reasons, "next_steps": next_steps,
        "counts": {"HIGH": highs, "MEDIUM": meds, "LOW": lows},
    }


def _next_steps(level: str, result: ModuleResult) -> List[str]:
    steps: List[str] = []
    if level == "suspicious":
        steps.append("Do not click, log in, or download — treat the link as hostile.")
        steps.append("Report it to your IT/security team or the impersonated brand.")
    elif level == "caution":
        steps.append("Confirm with the sender through a separate, trusted channel.")
        steps.append("Hover to check the real destination; don't enter credentials.")
    else:
        steps.append("Still verify the sender and that the domain is the official one.")
    final = result.data.get("final_url")
    if final and final != result.data.get("normalized"):
        steps.append(f"Note the real destination: {final}")
    return steps
