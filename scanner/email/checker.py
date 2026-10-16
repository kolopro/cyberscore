"""Email security passive checks: SPF, DMARC, DKIM detection, MX config.

All checks are DNS lookups only. No email is ever sent.
"""
from __future__ import annotations

from typing import List, Optional

import dns.resolver
import dns.exception

from config import settings
from scanner.models import ModuleResult, Severity, Status
from scanner.utils import registrable_domain


def _resolver() -> "dns.resolver.Resolver":
    r = dns.resolver.Resolver()
    r.timeout = settings.DNS_TIMEOUT
    r.lifetime = settings.DNS_TIMEOUT
    # Advertise a large EDNS buffer so big apex TXT sets (many SPF/verification
    # records) come back in one UDP response instead of truncating/timing out.
    r.use_edns(0, 0, 4096)
    return r


def _txt(name: str) -> List[str]:
    r = _resolver()

    def _collect(tcp: bool) -> List[str]:
        ans = r.resolve(name, "TXT", raise_on_no_answer=False, tcp=tcp)
        if ans.rrset is None:
            return []
        return ["".join(s.decode() if isinstance(s, bytes) else s
                        for s in rr.strings) for rr in ans]

    try:
        return _collect(tcp=False)
    except dns.exception.Timeout:
        # Large TXT sets can exceed UDP; retry once over TCP.
        try:
            return _collect(tcp=True)
        except dns.exception.DNSException:
            return []
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.DNSException):
        return []


def _mx(name: str) -> List[str]:
    r = _resolver()
    try:
        ans = r.resolve(name, "MX", raise_on_no_answer=False)
        if ans.rrset is None:
            return []
        return [rr.exchange.to_text().rstrip(".") for rr in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.DNSException):
        return []


def run(host: str) -> ModuleResult:
    result = ModuleResult(name="email")
    apex = registrable_domain(host)
    result.data["apex"] = apex

    mx = _mx(apex)
    result.data["MX"] = mx
    has_mail = bool(mx)
    if has_mail:
        result.add_check("mx", "MX configured", Status.OK, ", ".join(mx[:3]))
    else:
        result.add_check("mx", "MX configured", Status.INFO, "no MX (no email)")

    # --- SPF ----------------------------------------------------------------
    spf = _find_spf(apex)
    result.data["spf"] = spf
    if spf:
        soft = "~all" in spf or "-all" in spf
        result.add_check("spf", "SPF record", Status.OK if soft else Status.WARN,
                         spf[:80])
        if not soft:
            result.add_finding(
                Severity.LOW, "SPF record has no strict 'all' qualifier",
                "End the SPF record with '-all' (fail) or '~all' (softfail).",
                evidence=spf,
                code="email.spf_weak",
            )
    else:
        result.add_check("spf", "SPF record", Status.FAIL, "missing")
        result.add_finding(
            Severity.MEDIUM, "No SPF record",
            "Publish an SPF TXT record to declare authorised mail senders.",
            code="email.no_spf",
        )

    # --- DMARC --------------------------------------------------------------
    dmarc = _find_dmarc(apex)
    result.data["dmarc"] = dmarc
    if dmarc:
        policy = _dmarc_policy(dmarc)
        result.data["dmarc_policy"] = policy
        if policy in ("reject", "quarantine"):
            result.add_check("dmarc", "DMARC record", Status.OK, f"p={policy}")
        else:
            result.add_check("dmarc", "DMARC record", Status.WARN, f"p={policy or 'none'}")
            result.add_finding(
                Severity.MEDIUM, f"DMARC policy is weak (p={policy or 'none'})",
                "Move DMARC to p=quarantine, then p=reject once monitoring is clean.",
                evidence=dmarc,
                code="email.dmarc_weak",
            )
    else:
        result.add_check("dmarc", "DMARC record", Status.FAIL, "missing")
        sev = Severity.MEDIUM if has_mail else Severity.LOW
        result.add_finding(
            sev, "No DMARC record",
            "Publish a _dmarc TXT record (start with p=none for monitoring).",
            code="email.no_dmarc",
        )

    # --- DMARC detail: pct + subdomain policy -------------------------------
    if dmarc:
        tags = _dmarc_tags(dmarc)
        result.data["dmarc_tags"] = tags
        pct = tags.get("pct")
        if pct is not None and pct != "100":
            result.add_check("dmarc_pct", "DMARC coverage (pct)", Status.WARN,
                             f"pct={pct}%")
            result.add_finding(
                Severity.LOW, f"DMARC only applied to {pct}% of mail (pct={pct})",
                "Set pct=100 so the policy covers all messages.",
                evidence=dmarc, code="email.dmarc_pct",
            )
        sp = tags.get("sp")
        if sp in ("none", None) and tags.get("p") in ("quarantine", "reject"):
            result.add_check("dmarc_sp", "DMARC subdomain policy", Status.WARN,
                             f"sp={sp or 'inherits p, but check'}")
            result.add_finding(
                Severity.LOW, "DMARC subdomain policy is weak or unset",
                "Add sp=reject (or sp=quarantine) so subdomains are protected too.",
                evidence=dmarc, code="email.dmarc_sp",
            )
        if not tags.get("rua"):
            result.add_check("dmarc_rua", "DMARC aggregate reports (rua)",
                             Status.WARN, "no rua")
            result.add_finding(
                Severity.LOW, "DMARC has no aggregate report address (rua)",
                "Add rua=mailto:you@domain to receive DMARC reports and gain visibility.",
                code="email.dmarc_no_rua",
            )

    # --- DKIM (best-effort selector probing) --------------------------------
    dkim_selectors = _find_dkim(apex)
    result.data["dkim_selectors"] = dkim_selectors
    if dkim_selectors:
        result.add_check("dkim", "DKIM detected", Status.OK,
                         "selectors: " + ", ".join(dkim_selectors))
    else:
        result.add_check("dkim", "DKIM detected", Status.WARN,
                         "not detected (common selectors probed)")
        if has_mail:
            result.add_finding(
                Severity.LOW, "DKIM not detected",
                "Enable DKIM signing and publish the selector's public key. "
                "(Detection probes common selectors only; yours may differ.)",
                code="email.no_dkim",
            )

    # --- SPF lookup count (RFC 7208 caps DNS lookups at 10) -----------------
    if spf:
        lookups = _spf_lookup_count(spf)
        result.data["spf_lookups"] = lookups
        if lookups > 10:
            result.add_check("spf_lookups", "SPF DNS lookups", Status.FAIL,
                             f"{lookups} (limit 10)")
            result.add_finding(
                Severity.MEDIUM, f"SPF exceeds the 10 DNS-lookup limit ({lookups})",
                "Reduce include/a/mx mechanisms or use SPF flattening; over 10 "
                "lookups makes SPF fail (permerror).",
                evidence=spf, code="email.spf_lookups",
            )
        else:
            result.add_check("spf_lookups", "SPF DNS lookups", Status.OK,
                             f"{lookups}/10")

    # --- MTA-STS (enforced TLS for inbound mail) ----------------------------
    if has_mail:
        mtasts = _txt(f"_mta-sts.{apex}")
        has_mtasts = any(t.lower().startswith("v=stsv1") for t in mtasts)
        result.data["mta_sts"] = has_mtasts
        if has_mtasts:
            result.add_check("mta_sts", "MTA-STS", Status.OK, "policy record present")
        else:
            result.add_check("mta_sts", "MTA-STS", Status.WARN, "not configured")
            result.add_finding(
                Severity.LOW, "MTA-STS is not configured",
                "Publish an MTA-STS policy so senders require TLS to your mail "
                "servers (prevents downgrade/interception).",
                code="email.no_mtasts",
            )

        # --- TLS-RPT (TLS reporting) ---------------------------------------
        tlsrpt = _txt(f"_smtp._tls.{apex}")
        has_tlsrpt = any(t.lower().startswith("v=tlsrptv1") for t in tlsrpt)
        result.data["tls_rpt"] = has_tlsrpt
        if has_tlsrpt:
            result.add_check("tls_rpt", "TLS-RPT", Status.OK, "reporting configured")
        else:
            result.add_check("tls_rpt", "TLS-RPT", Status.INFO, "not configured")
            result.add_finding(
                Severity.LOW, "TLS-RPT is not configured",
                "Add a _smtp._tls TXT record (v=TLSRPTv1) to receive reports about "
                "failed inbound TLS connections.",
                code="email.no_tlsrpt",
            )

    # --- BIMI (brand logo; informational) -----------------------------------
    bimi = _txt(f"default._bimi.{apex}")
    has_bimi = any(t.lower().startswith("v=bimi1") for t in bimi)
    result.data["bimi"] = has_bimi
    result.add_check("bimi", "BIMI", Status.OK if has_bimi else Status.INFO,
                     "logo record present" if has_bimi else "not configured")

    return result


def _find_spf(apex: str) -> Optional[str]:
    for txt in _txt(apex):
        if txt.lower().startswith("v=spf1"):
            return txt
    return None


def _find_dmarc(apex: str) -> Optional[str]:
    for txt in _txt(f"_dmarc.{apex}"):
        if txt.lower().startswith("v=dmarc1"):
            return txt
    return None


def _dmarc_policy(dmarc: str) -> Optional[str]:
    for part in dmarc.split(";"):
        part = part.strip()
        if part.lower().startswith("p="):
            return part.split("=", 1)[1].strip().lower()
    return None


def _dkim_has_key(record: str) -> bool:
    """True only if the record carries a non-empty public key (p=<data>).

    A record like 'v=DKIM1; p=' is a *null* / revoked key (example.com uses a
    wildcard one) and must not count as an active DKIM key.
    """
    low = record.lower()
    if "v=dkim1" not in low and "k=rsa" not in low:
        return False
    for part in record.split(";"):
        part = part.strip()
        if part.lower().startswith("p="):
            return len(part[2:].strip()) > 0
    return False


def _dmarc_tags(dmarc: str) -> dict:
    """Parse a DMARC record into a {tag: value} dict (lowercased tags)."""
    tags = {}
    for part in dmarc.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


# SPF mechanisms/modifiers that each cost a DNS lookup (RFC 7208 §4.6.4).
_SPF_LOOKUP_TERMS = ("include:", "a:", "mx:", "ptr", "exists:", "redirect=")


def _spf_lookup_count(spf: str) -> int:
    """Approximate the number of DNS-lookup-causing terms in an SPF record.

    Counts include/a/mx/ptr/exists/redirect. A bare 'a' or 'mx' (no ':') also
    costs a lookup. This is a first-order estimate (does not recurse into
    included records), enough to flag records near/over the limit of 10.
    """
    count = 0
    for tok in spf.split():
        low = tok.lower()
        if low in ("a", "mx", "ptr"):
            count += 1
        elif any(low.startswith(t) for t in _SPF_LOOKUP_TERMS):
            count += 1
    return count


def _find_dkim(apex: str) -> List[str]:
    found = []
    for sel in settings.DKIM_SELECTORS:
        recs = _txt(f"{sel}._domainkey.{apex}")
        if any(_dkim_has_key(r) for r in recs):
            found.append(sel)
    return found
