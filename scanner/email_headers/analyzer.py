"""Email header analyzer.

Takes RAW email headers (pasted by the user) and reports:
  - the key identity headers (From, Return-Path, Reply-To, To, Subject, Date)
  - SPF / DKIM / DMARC authentication results (from Authentication-Results)
  - the Received hop chain (delivery path)
  - spoofing / phishing red flags (domain mismatches, auth failures)

This is 100% offline parsing — no network, no email is sent. It reuses the
shared Check/Finding models so the output renders like any other module.
"""
from __future__ import annotations

import ipaddress
import re
from email.header import decode_header, make_header
from email.parser import Parser
from email.utils import parseaddr, getaddresses
from typing import List, Optional

from scanner.models import ModuleResult, Severity, Status


def _decode(value: str) -> str:
    """Decode RFC 2047 encoded-words (=?UTF-8?B?...?=) to readable text."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _domain_of(addr: str) -> str:
    _, email = parseaddr(addr or "")
    if "@" in email:
        return email.rsplit("@", 1)[1].strip().lower().rstrip(".")
    return ""


_IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,}:[0-9a-fA-F:]*)\]?")


def _is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return not (obj.is_private or obj.is_loopback or obj.is_link_local
                    or obj.is_unspecified)
    except ValueError:
        return False


def _sending_origin(received: List[str]) -> dict:
    """From the earliest Received hop, extract the sending host + public IP."""
    if not received:
        return {"ip": "", "host": ""}
    # Received headers are newest-first; the LAST one is the origin.
    origin = " ".join(received[-1].split())
    ip = ""
    for m in _IP_RE.finditer(origin):
        cand = m.group(1)
        if _is_public_ip(cand):
            ip = cand
            break
    host = ""
    hm = re.search(r"from\s+([A-Za-z0-9.\-]+\.[A-Za-z]{2,})", origin)
    if hm:
        host = hm.group(1).lower()
    return {"ip": ip, "host": host, "raw": origin[:200]}


def _parse_auth_results(values: List[str]) -> dict:
    """Extract spf/dkim/dmarc verdicts from Authentication-Results header(s)."""
    joined = " ".join(values).lower()
    out = {}
    for method in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{method}\s*=\s*([a-z]+)", joined)
        if m:
            out[method] = m.group(1)
    return out


def _received_chain(msg) -> List[str]:
    # Received headers are listed newest-first; reverse to show delivery order.
    received = msg.get_all("Received") or []
    hops = []
    for r in reversed(received):
        r = " ".join(r.split())
        hops.append(r[:200])
    return hops


def analyze(raw_headers: str) -> ModuleResult:
    result = ModuleResult(name="email_headers")

    raw = (raw_headers or "").strip()
    if not raw:
        result.error = "No headers provided."
        result.add_check("input", "Headers provided", Status.FAIL, "empty input")
        return result

    msg = Parser().parsestr(raw, headersonly=True)

    frm = _decode(msg.get("From", ""))
    return_path = msg.get("Return-Path", "")
    reply_to = _decode(msg.get("Reply-To", ""))
    to = ", ".join(a for _, a in getaddresses(msg.get_all("To") or []))
    subject = _decode(msg.get("Subject", ""))
    date = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")

    from_name, from_addr = parseaddr(frm)
    from_dom = _domain_of(frm)
    rp_dom = _domain_of(return_path)
    reply_dom = _domain_of(reply_to)

    origin = _sending_origin(msg.get_all("Received") or [])

    result.data.update({
        "from": frm, "from_name": from_name, "from_address": from_addr,
        "from_domain": from_dom,
        "return_path": return_path, "return_path_domain": rp_dom,
        "reply_to": reply_to, "reply_to_domain": reply_dom,
        "to": to, "subject": subject, "date": date, "message_id": message_id,
        "sending_ip": origin.get("ip", ""), "sending_host": origin.get("host", ""),
    })

    # --- identity headers (informational) ----------------------------------
    result.add_check("from", "From", Status.INFO, frm or "(missing)")
    if to:
        result.add_check("to", "To", Status.INFO, to)
    if subject:
        result.add_check("subject", "Subject", Status.INFO, subject)
    if date:
        result.add_check("date", "Date", Status.INFO, date)
    if return_path:
        result.add_check("return_path", "Return-Path", Status.INFO, return_path)

    # --- authentication results --------------------------------------------
    ar = msg.get_all("Authentication-Results") or []
    recv_spf = msg.get("Received-SPF", "")
    verdicts = _parse_auth_results(ar)
    if recv_spf and "spf" not in verdicts:
        m = re.match(r"\s*([a-zA-Z]+)", recv_spf)
        if m:
            verdicts["spf"] = m.group(1).lower()
    result.data["auth"] = verdicts

    if not ar and not recv_spf:
        result.add_check("auth", "Authentication-Results", Status.WARN,
                         "no auth headers found")
        result.add_finding(
            Severity.MEDIUM, "No Authentication-Results header present",
            "Cannot confirm SPF/DKIM/DMARC — get the full headers as received "
            "by the destination mail server.",
            code="hdr.no_auth_results",
        )
    else:
        _verdict_check(result, "spf", "SPF", verdicts.get("spf"), "hdr.spf_fail")
        _verdict_check(result, "dkim", "DKIM", verdicts.get("dkim"), "hdr.dkim_fail")
        _verdict_check(result, "dmarc", "DMARC", verdicts.get("dmarc"), "hdr.dmarc_fail")

    # --- spoofing red flags -------------------------------------------------
    if from_dom and rp_dom and from_dom != rp_dom:
        result.add_check("from_rp", "From vs Return-Path domain", Status.WARN,
                         f"{from_dom} != {rp_dom}")
        result.add_finding(
            Severity.MEDIUM, "From domain differs from Return-Path (envelope) domain",
            "Verify the sender; mismatched envelope/header domains are a common "
            "spoofing pattern (some legitimate bulk senders also do this).",
            evidence=f"From={from_dom}  Return-Path={rp_dom}",
            code="hdr.from_returnpath_mismatch",
        )
    elif from_dom and rp_dom:
        result.add_check("from_rp", "From vs Return-Path domain", Status.OK,
                         "aligned")

    if from_dom and reply_dom and from_dom != reply_dom:
        result.add_check("reply_to", "Reply-To domain", Status.WARN,
                         f"{reply_dom} != From {from_dom}")
        result.add_finding(
            Severity.LOW, "Reply-To domain differs from From domain",
            "Confirm replies are going where you expect; attackers use this to "
            "capture replies.",
            evidence=f"From={from_dom}  Reply-To={reply_dom}",
            code="hdr.reply_to_mismatch",
        )

    # display-name that itself contains a different domain (e.g. "support@bank.com <evil@x.ru>")
    display, _addr = parseaddr(frm)
    dm = re.search(r"[\w.-]+@([\w.-]+\.\w+)", display or "")
    if dm and from_dom and dm.group(1).lower() != from_dom:
        result.add_check("display_spoof", "From display-name", Status.WARN,
                         f"shows {dm.group(1)} but sends from {from_dom}")
        result.add_finding(
            Severity.MEDIUM, "From display-name mimics a different domain",
            "The display name shows one domain while the real sender is another "
            "— a classic phishing trick.",
            evidence=display, code="hdr.from_returnpath_mismatch",
        )

    # --- received chain -----------------------------------------------------
    hops = _received_chain(msg)
    result.data["received"] = hops
    result.add_check("received", "Received hops", Status.INFO, f"{len(hops)} hop(s)")

    # --- overall verdict + next steps --------------------------------------
    result.data["verdict"] = _build_verdict(verdicts, result, from_dom, origin)

    return result


def _build_verdict(auth: dict, result: ModuleResult, from_dom: str,
                   origin: dict) -> dict:
    """Turn the signals into a plain-language legit / caution / suspicious call."""
    spf = auth.get("spf")
    dkim = auth.get("dkim")
    dmarc = auth.get("dmarc")
    fail_vals = {"fail", "softfail", "hardfail"}
    codes = {f.code for f in result.findings}
    has_mismatch = "hdr.from_returnpath_mismatch" in codes
    any_auth_fail = any(v in fail_vals for v in (spf, dkim, dmarc) if v)

    reasons: List[str] = []
    ip = origin.get("ip") or "unknown"
    host = origin.get("host") or ""

    if not auth:
        level = "unverified"
        title = "Cannot verify — no authentication data"
        summary = ("These headers contain no Authentication-Results, so SPF/DKIM/"
                   "DMARC could not be confirmed. Treat with caution until verified.")
        reasons.append("No Authentication-Results header was present.")
    elif dmarc == "pass":
        level = "legit"
        title = "Likely legitimate"
        summary = (f"The message passed DMARC, so it is cryptographically "
                   f"authenticated as coming from {from_dom or 'the From domain'}.")
        reasons.append(f"DMARC = pass (aligned with {from_dom or 'the From domain'}).")
        if spf == "pass":
            reasons.append("SPF = pass (sending server is authorised).")
        if dkim == "pass":
            reasons.append("DKIM = pass (signature verified, content intact).")
        if has_mismatch:
            reasons.append("Note: Return-Path differs from From — normal for "
                           "newsletters/ESPs when DMARC still passes.")
    elif dmarc in fail_vals or (spf in fail_vals and dkim in fail_vals):
        level = "suspicious"
        title = "Suspicious — likely spoofed"
        summary = ("Authentication failed, so this message may be forged. Do not "
                   "trust links, attachments or requests in it until verified.")
        if dmarc:
            reasons.append(f"DMARC = {dmarc}.")
        if spf in fail_vals:
            reasons.append(f"SPF = {spf} (server not authorised for the domain).")
        if dkim in fail_vals:
            reasons.append(f"DKIM = {dkim} (signature did not verify).")
        if has_mismatch:
            reasons.append("From domain does not match the envelope sender.")
    else:
        level = "caution"
        title = "Partially verified — check further"
        summary = ("Some checks passed but not all, or DMARC is absent. Confirm "
                   "the sender before trusting the message.")
        for name, v in (("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc)):
            if v:
                reasons.append(f"{name} = {v}.")

    # next steps by level
    if level == "legit":
        next_steps = [
            f"Confirm the From domain '{from_dom}' really belongs to the brand you "
            f"expect (e.g. a newsletter subdomain of the company's main domain).",
            f"Sending server: {host or 'n/a'} ({ip}) — a mismatch with the brand's "
            "known email provider would be worth a second look.",
            "Still hover over links before clicking; authenticated ≠ automatically safe.",
        ]
    elif level == "suspicious":
        next_steps = [
            "Do NOT click links, open attachments, or reply with any information.",
            f"The message claims to be from '{from_dom or 'unknown'}' but sent from "
            f"{host or 'unknown host'} ({ip}) — verify with the real organisation "
            "using a phone number/website you already trust (not one from this email).",
            "Report it to your provider as phishing, then delete it.",
        ]
    elif level == "unverified":
        next_steps = [
            "Get the FULL headers as received by your mailbox (they must include the "
            "Authentication-Results line added by your provider).",
            f"Independently check whether sending IP {ip} belongs to the sender's "
            "real email provider.",
            "Until confirmed, treat links and attachments as untrusted.",
        ]
    else:  # caution
        next_steps = [
            f"Verify the From domain '{from_dom}' against the sender you expect.",
            f"Check that sending server {host or 'n/a'} ({ip}) matches the brand's "
            "email provider.",
            "If anything looks off, confirm via a known channel before acting.",
        ]

    return {"level": level, "title": title, "summary": summary,
            "reasons": reasons, "next_steps": next_steps,
            "sending_ip": ip, "sending_host": host}


def _verdict_check(result: ModuleResult, key: str, label: str,
                   verdict: Optional[str], fail_code: str) -> None:
    if verdict is None:
        result.add_check(key, f"{label} result", Status.INFO, "not stated")
        return
    v = verdict.lower()
    if v == "pass":
        result.add_check(key, f"{label} result", Status.OK, "pass")
    elif v in ("none", "neutral", "policy", "temperror", "permerror"):
        result.add_check(key, f"{label} result", Status.WARN, v)
    else:  # fail, softfail, hardfail, etc.
        result.add_check(key, f"{label} result", Status.FAIL, v)
        result.add_finding(
            Severity.MEDIUM, f"{label} authentication did not pass ({v})",
            f"{label} = {v} for this message.",
            code=fail_code,
        )
