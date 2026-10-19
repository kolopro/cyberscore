"""Deep TLS analysis via SSLyze — an SSL-Labs-style assessment.

Enumerates supported protocol versions and cipher suites, forward secrecy,
certificate key/signature/chain details and a set of well-known vulnerabilities
(Heartbleed, ROBOT, CCS injection, insecure renegotiation, CRIME), then derives
an overall A+ → F grade.

This runs a number of short TLS handshakes against port 443, so it is slower
than the basic checks. It is fully optional: if SSLyze is unavailable or the
host cannot be reached, `deep_scan()` returns None and the caller falls back to
the standard-library checks.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from sslyze import (
        Scanner, ServerScanRequest, ServerNetworkLocation, ScanCommand,
        ServerScanStatusEnum, ScanCommandAttemptStatusEnum, RobotScanResultEnum,
    )
    _HAVE_SSLYZE = True
except Exception:  # pragma: no cover - import guard
    _HAVE_SSLYZE = False

# cipher-suite tokens we consider weak (case-insensitive substring match)
_WEAK_TOKENS = ("RC4", "3DES", "_DES_", "DES_CBC", "NULL", "EXPORT", "MD5", "ANON", "_PSK")

# protocol scan-result attribute -> human label (worst → best)
_PROTO_ATTRS = [
    ("ssl_2_0_cipher_suites", "SSL 2.0", True),
    ("ssl_3_0_cipher_suites", "SSL 3.0", True),
    ("tls_1_0_cipher_suites", "TLS 1.0", True),
    ("tls_1_1_cipher_suites", "TLS 1.1", True),
    ("tls_1_2_cipher_suites", "TLS 1.2", False),
    ("tls_1_3_cipher_suites", "TLS 1.3", False),
]

_GRADES = ["A+", "A", "B", "C", "D", "F"]


def _cap(current: str, maximum: str) -> str:
    """Lower `current` to `maximum` if `maximum` is worse."""
    return current if _GRADES.index(current) >= _GRADES.index(maximum) else maximum


def _is_weak_cipher(name: str) -> bool:
    n = (name or "").upper()
    return any(tok in n for tok in _WEAK_TOKENS)


def _ok(attempt) -> bool:
    return attempt is not None and attempt.status == ScanCommandAttemptStatusEnum.COMPLETED


def deep_scan(host: str, port: int = 443) -> Optional[Dict[str, Any]]:
    """Run a deep TLS assessment. Returns a structured dict, or None on failure."""
    if not _HAVE_SSLYZE:
        return None
    try:
        request = ServerScanRequest(
            server_location=ServerNetworkLocation(hostname=host, port=port),
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
                ScanCommand.OPENSSL_CCS_INJECTION,
                ScanCommand.SESSION_RENEGOTIATION,
                ScanCommand.TLS_COMPRESSION,
            },
        )
    except Exception:
        return None

    try:
        scanner = Scanner()
        scanner.queue_scans([request])
        server_result = next(iter(scanner.get_results()), None)
    except Exception:
        return None

    if server_result is None or server_result.scan_status != ServerScanStatusEnum.COMPLETED:
        return None

    sr = server_result.scan_result
    out: Dict[str, Any] = {"protocols": [], "weak_protocols": [], "weak_ciphers": [],
                           "cipher_count": {}, "vulns": {}, "cert": {}, "notes": []}

    # --- Protocols + cipher suites -----------------------------------------
    enabled_weak_proto = False
    enabled_legacy_proto = False
    has_tls13 = False
    all_accepted = []  # (proto_label, cipher_name, is_fs)
    for attr, label, is_legacy in _PROTO_ATTRS:
        attempt = getattr(sr, attr, None)
        if not _ok(attempt):
            continue
        accepted = attempt.result.accepted_cipher_suites or []
        enabled = len(accepted) > 0
        out["protocols"].append({"name": label, "enabled": enabled,
                                 "ciphers": len(accepted)})
        out["cipher_count"][label] = len(accepted)
        if enabled:
            if label in ("SSL 2.0", "SSL 3.0"):
                enabled_weak_proto = True
                out["weak_protocols"].append(label)
            if label in ("TLS 1.0", "TLS 1.1"):
                enabled_legacy_proto = True
                out["weak_protocols"].append(label)
            if label == "TLS 1.3":
                has_tls13 = True
            for cs in accepted:
                name = cs.cipher_suite.name
                fs = (cs.ephemeral_key is not None) or ("ECDHE" in name) or ("DHE" in name)
                all_accepted.append((label, name, fs))
                if _is_weak_cipher(name) or cs.cipher_suite.is_anonymous:
                    if name not in out["weak_ciphers"]:
                        out["weak_ciphers"].append(name)

    # Forward secrecy across modern protocols
    modern = [fs for (lbl, nm, fs) in all_accepted if lbl in ("TLS 1.2", "TLS 1.3")]
    if not modern:
        out["forward_secrecy"] = "unknown"
    elif all(modern):
        out["forward_secrecy"] = "all"
    elif any(modern):
        out["forward_secrecy"] = "partial"
    else:
        out["forward_secrecy"] = "none"

    # --- Certificate details ------------------------------------------------
    trusted = None
    try:
        ci = sr.certificate_info
        if _ok(ci):
            dep = ci.result.certificate_deployments[0]
            leaf = dep.received_certificate_chain[0]
            pub = leaf.public_key()
            key_type = type(pub).__name__.replace("PublicKey", "")
            if "RSA" in key_type:
                key_type = "RSA"
            elif "EllipticCurve" in key_type:
                key_type = "EC"
            out["cert"]["key_type"] = key_type
            out["cert"]["key_size"] = getattr(pub, "key_size", None)
            try:
                out["cert"]["sig_alg"] = (leaf.signature_hash_algorithm.name
                                          if leaf.signature_hash_algorithm else None)
            except Exception:
                out["cert"]["sig_alg"] = None
            try:
                from cryptography import x509
                sans = leaf.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
                out["cert"]["sans"] = list(sans)[:20]
            except Exception:
                out["cert"]["sans"] = []
            out["cert"]["chain_in_order"] = bool(dep.received_chain_has_valid_order)
            out["cert"]["has_anchor_in_chain"] = bool(dep.received_chain_contains_anchor_certificate)
            out["cert"]["sha1_in_chain"] = bool(dep.verified_chain_has_sha1_signature)
            out["cert"]["ocsp_stapling"] = dep.ocsp_response is not None
            trusted = any(p.validation_error is None for p in dep.path_validation_results)
            out["cert"]["trusted"] = trusted
    except Exception:
        pass

    # --- Vulnerabilities ----------------------------------------------------
    v = out["vulns"]
    try:
        if _ok(sr.heartbleed):
            v["heartbleed"] = bool(sr.heartbleed.result.is_vulnerable_to_heartbleed)
    except Exception:
        pass
    robot_vuln = False
    try:
        if _ok(sr.robot):
            rr = sr.robot.result.robot_result
            robot_vuln = rr in (RobotScanResultEnum.VULNERABLE_STRONG_ORACLE,
                                RobotScanResultEnum.VULNERABLE_WEAK_ORACLE)
            v["robot"] = rr.name
    except Exception:
        pass
    try:
        if _ok(sr.openssl_ccs_injection):
            v["ccs_injection"] = bool(sr.openssl_ccs_injection.result.is_vulnerable_to_ccs_injection)
    except Exception:
        pass
    secure_reneg = True
    try:
        if _ok(sr.session_renegotiation):
            secure_reneg = bool(sr.session_renegotiation.result.supports_secure_renegotiation)
            v["secure_renegotiation"] = secure_reneg
    except Exception:
        pass
    try:
        if _ok(sr.tls_compression):
            v["compression"] = bool(sr.tls_compression.result.supports_compression)
    except Exception:
        pass

    # --- Grade --------------------------------------------------------------
    grade = "A+"
    # Hard fails
    if enabled_weak_proto:
        grade = _cap(grade, "F")
    if v.get("heartbleed") or robot_vuln or v.get("ccs_injection"):
        grade = _cap(grade, "F")
    if trusted is False:
        grade = _cap(grade, "F")
    if not secure_reneg:
        grade = _cap(grade, "F")
    # Weak ciphers / no forward secrecy
    if out["weak_ciphers"]:
        grade = _cap(grade, "C")
    if out["forward_secrecy"] == "none":
        grade = _cap(grade, "C")
    elif out["forward_secrecy"] == "partial":
        grade = _cap(grade, "B")
    if v.get("compression"):
        grade = _cap(grade, "C")
    # Legacy protocols
    if enabled_legacy_proto:
        grade = _cap(grade, "C")
    # Weak key / SHA-1
    ks = out["cert"].get("key_size")
    kt = out["cert"].get("key_type")
    if kt == "RSA" and ks and ks < 2048:
        grade = _cap(grade, "F")
    if out["cert"].get("sha1_in_chain"):
        grade = _cap(grade, "C")
    # A+ requires modern TLS 1.3 and no legacy; otherwise cap at A
    if grade == "A+" and not (has_tls13 and not enabled_legacy_proto):
        grade = "A"
    out["grade"] = grade

    return out
