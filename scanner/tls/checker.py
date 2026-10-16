"""TLS / certificate passive checks using the standard library only.

We open a single TLS connection to read the negotiated protocol, cipher and
certificate. To enumerate supported protocol versions we make short,
non-invasive handshake attempts pinned to specific versions.
"""
from __future__ import annotations

import datetime as _dt
import socket
import ssl
from typing import Optional, Tuple

from config import settings
from scanner.models import ModuleResult, Severity, Status


def _connect(host: str, ssl_ctx: ssl.SSLContext) -> Optional[ssl.SSLSocket]:
    try:
        raw = socket.create_connection((host, 443), timeout=settings.TLS_TIMEOUT)
        return ssl_ctx.wrap_socket(raw, server_hostname=host)
    except (ssl.SSLError, socket.error, OSError):
        return None


def _try_version(host: str, minimum, maximum) -> bool:
    """Return True if a handshake succeeds pinned to the given version window."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = minimum
        ctx.maximum_version = maximum
    except ValueError:
        return False
    sock = _connect(host, ctx)
    if sock is None:
        return False
    try:
        return sock.version() is not None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _parse_cert_time(value: str) -> Optional[_dt.datetime]:
    try:
        return _dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=_dt.timezone.utc
        )
    except (ValueError, TypeError):
        return None


def run(host: str) -> ModuleResult:
    result = ModuleResult(name="tls")

    # --- Verified connection for cert + negotiated params -------------------
    verify_ctx = ssl.create_default_context()
    verify_ctx.set_ciphers("DEFAULT")
    sock = _connect(host, verify_ctx)
    cert_valid = sock is not None

    if not cert_valid:
        # Retry without verification so we can still read the cert details and
        # report *why* validation failed rather than nothing at all.
        insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        sock = _connect(host, insecure)

    if sock is None:
        result.add_check("tls", "TLS handshake", Status.FAIL, "no TLS on port 443")
        result.error = "Could not establish a TLS connection on port 443."
        result.add_finding(
            Severity.HIGH, "No usable TLS on port 443",
            "Install a valid TLS certificate and enable HTTPS.",
            code="tls.no_tls",
        )
        return result

    negotiated = sock.version()
    cipher = sock.cipher()
    try:
        cert = sock.getpeercert()
    except ssl.SSLError:
        cert = None
    finally:
        try:
            sock.close()
        except OSError:
            pass

    result.data["negotiated_version"] = negotiated
    result.data["cipher"] = cipher[0] if cipher else None

    # --- Certificate validity ----------------------------------------------
    if cert_valid:
        result.add_check("cert_valid", "Certificate valid & trusted", Status.OK)
    else:
        result.add_check("cert_valid", "Certificate valid & trusted", Status.FAIL,
                         "chain/hostname verification failed")
        result.add_finding(
            Severity.HIGH, "TLS certificate is not trusted for this host",
            "Use a certificate from a trusted CA that matches the hostname "
            "(and includes the full chain).",
            code="tls.untrusted",
        )

    # --- Expiry -------------------------------------------------------------
    if cert:
        subject = dict(x[0] for x in cert.get("subject", []))
        result.data["subject_cn"] = subject.get("commonName")
        issuer = dict(x[0] for x in cert.get("issuer", []))
        result.data["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
        not_after = _parse_cert_time(cert.get("notAfter", ""))
        if not_after:
            days = (not_after - _dt.datetime.now(_dt.timezone.utc)).days
            result.data["days_to_expiry"] = days
            result.data["not_after"] = cert.get("notAfter")
            if days < 0:
                result.add_check("cert_expiry", "Certificate not expired",
                                 Status.FAIL, f"expired {abs(days)}d ago")
                result.add_finding(
                    Severity.HIGH, "TLS certificate has expired",
                    "Renew the certificate immediately.",
                    evidence=cert.get("notAfter", ""),
                    code="tls.expired",
                )
            elif days <= settings.CERT_EXPIRY_CRITICAL:
                result.add_check("cert_expiry", "Certificate not expired",
                                 Status.WARN, f"expires in {days}d")
                result.add_finding(
                    Severity.MEDIUM, f"TLS certificate expires very soon ({days}d)",
                    "Renew / verify auto-renewal now.",
                    code="tls.expiring_soon",
                )
            elif days <= settings.CERT_EXPIRY_WARNING:
                result.add_check("cert_expiry", "Certificate not expired",
                                 Status.WARN, f"expires in {days}d")
                result.add_finding(
                    Severity.LOW, f"TLS certificate expires in {days} days",
                    "Confirm renewal is scheduled.",
                    code="tls.expiring",
                )
            else:
                result.add_check("cert_expiry", "Certificate not expired",
                                 Status.OK, f"{days}d remaining")

    # --- Protocol versions --------------------------------------------------
    T = ssl.TLSVersion
    has_tls12 = _try_version(host, T.TLSv1_2, T.TLSv1_2)
    has_tls13 = _try_version(host, T.TLSv1_3, T.TLSv1_3)
    # Legacy: try to negotiate <= TLS 1.1. Success here is a weakness.
    legacy = False
    try:
        legacy = _try_version(host, T.MINIMUM_SUPPORTED, T.TLSv1_1)
    except Exception:
        legacy = False

    result.data["tls1_2"] = has_tls12
    result.data["tls1_3"] = has_tls13
    result.data["legacy_tls"] = legacy

    if has_tls12 or has_tls13:
        result.add_check("tls12plus", "TLS 1.2+ supported", Status.OK)
    else:
        result.add_check("tls12plus", "TLS 1.2+ supported", Status.WARN,
                         f"negotiated {negotiated}")

    result.add_check("tls13", "TLS 1.3 supported",
                     Status.OK if has_tls13 else Status.WARN,
                     "" if has_tls13 else "not offered")
    if not has_tls13:
        result.add_finding(
            Severity.LOW, "TLS 1.3 is not offered",
            "Enable TLS 1.3 for better performance and security.",
            code="tls.no_tls13",
        )

    if legacy:
        result.add_check("legacy_tls", "Legacy TLS (<=1.1) disabled", Status.FAIL,
                         "TLS 1.0/1.1 negotiable")
        result.add_finding(
            Severity.MEDIUM, "Deprecated TLS 1.0/1.1 is still enabled",
            "Disable TLS 1.0 and 1.1; require TLS 1.2 or higher.",
            code="tls.legacy",
        )
    else:
        result.add_check("legacy_tls", "Legacy TLS (<=1.1) disabled", Status.OK)

    return result
