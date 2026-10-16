"""DNS passive checks: A/AAAA, MX, TXT, CAA, DNSSEC indication."""
from __future__ import annotations

from typing import List

import dns.resolver
import dns.exception
import dns.flags

from config import settings
from scanner.models import ModuleResult, Severity, Status
from scanner.utils import registrable_domain


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = settings.DNS_TIMEOUT
    r.lifetime = settings.DNS_TIMEOUT
    # Large EDNS buffer so big TXT sets return in one response.
    r.use_edns(0, 0, 4096)
    return r


def _query(name: str, rtype: str, want_dnssec: bool = False) -> List[str]:
    r = _resolver()
    try:
        if want_dnssec:
            r.use_edns(0, dns.flags.DO, 4096)
        ans = r.resolve(name, rtype, raise_on_no_answer=False)
        if ans.rrset is None:
            return []
        return [rr.to_text() for rr in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.DNSException):
        return []


def run(host: str) -> ModuleResult:
    result = ModuleResult(name="dns")
    apex = registrable_domain(host)
    result.data["apex"] = apex

    a = _query(host, "A")
    aaaa = _query(host, "AAAA")
    result.data["A"] = a
    result.data["AAAA"] = aaaa

    if a:
        result.add_check("a", "A record", Status.OK, ", ".join(a[:3]))
    else:
        result.add_check("a", "A record", Status.FAIL, "none")
        result.add_finding(Severity.MEDIUM, "No A record for host",
                           "Publish an A record so the host resolves over IPv4.",
                           code="dns.no_a")
    result.add_check("aaaa", "AAAA (IPv6)",
                     Status.OK if aaaa else Status.INFO,
                     ", ".join(aaaa[:2]) if aaaa else "no IPv6")

    mx = _query(apex, "MX")
    result.data["MX"] = mx
    result.add_check("mx", "MX record",
                     Status.OK if mx else Status.INFO,
                     f"{len(mx)} host(s)" if mx else "no mail exchangers")

    txt = _query(apex, "TXT")
    result.data["TXT"] = txt
    result.add_check("txt", "TXT records", Status.INFO, f"{len(txt)} record(s)")

    caa = _query(apex, "CAA")
    result.data["CAA"] = caa
    if caa:
        result.add_check("caa", "CAA record", Status.OK, f"{len(caa)} policy")
    else:
        result.add_check("caa", "CAA record", Status.WARN, "not set")
        result.add_finding(
            Severity.LOW, "No CAA record",
            "Add a CAA record to restrict which CAs may issue certificates.",
            code="dns.no_caa",
        )

    # --- DNSSEC indication (passive) ---------------------------------------
    # We look for an RRSIG / AD flag on the apex. This is an *indication*,
    # not full validation.
    dnssec = _dnssec_indication(apex)
    result.data["dnssec"] = dnssec
    if dnssec == "signed":
        result.add_check("dnssec", "DNSSEC", Status.OK, "signed (RRSIG present)")
    elif dnssec == "ad":
        result.add_check("dnssec", "DNSSEC", Status.OK, "validated (AD flag)")
    else:
        result.add_check("dnssec", "DNSSEC", Status.WARN, "no signature detected")
        result.add_finding(
            Severity.LOW, "DNSSEC does not appear to be enabled",
            "Enable DNSSEC signing at your DNS provider / registrar.",
            code="dns.no_dnssec",
        )

    return result


def _dnssec_indication(apex: str) -> str:
    r = _resolver()
    # Ask a validating-capable path for the AD flag.
    try:
        r.use_edns(0, dns.flags.DO, 4096)
        ans = r.resolve(apex, "A", raise_on_no_answer=False)
        if ans.response.flags & dns.flags.AD:
            return "ad"
    except dns.exception.DNSException:
        pass
    # Look for RRSIG / DNSKEY directly.
    if _query(apex, "DNSKEY") or _query(apex, "RRSIG"):
        return "signed"
    return "unsigned"
