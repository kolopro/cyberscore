"""DNS zone enumeration: AXFR attempt + all standard record types + common subdomains."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import dns.exception
import dns.flags
import dns.query
import dns.resolver
import dns.zone
import dns.rdatatype

from config import settings
from scanner.utils import registrable_domain

RECORD_TYPES = ["SOA", "NS", "A", "AAAA", "MX", "TXT", "CAA", "SRV", "DNSKEY", "DS", "CNAME"]

COMMON_SUBDOMAINS = [
    "www", "mail", "smtp", "imap", "pop", "pop3", "ftp", "api",
    "dev", "staging", "app", "vpn", "remote", "webmail", "m",
    "mobile", "ns1", "ns2", "admin", "portal", "shop", "store",
    "cdn", "static", "media", "img", "images", "blog", "forum",
]


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = settings.DNS_TIMEOUT
    r.lifetime = settings.DNS_TIMEOUT
    r.use_edns(0, 0, 4096)
    return r


def _query(name: str, rtype: str) -> List[str]:
    r = _resolver()
    try:
        ans = r.resolve(name, rtype, raise_on_no_answer=False)
        if ans.rrset is None:
            return []
        return [rr.to_text() for rr in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.DNSException):
        return []


def _try_axfr(ns_name: str, domain: str) -> Optional[List[str]]:
    """Attempt AXFR zone transfer from a nameserver. Returns records list or None."""
    ns_addrs = _query(ns_name, "A")
    if not ns_addrs:
        ns_addrs = _query(ns_name, "AAAA")
    if not ns_addrs:
        return None
    try:
        z = dns.zone.from_xfr(dns.query.xfr(ns_addrs[0], domain, timeout=5))
        records = []
        for name, node in z.nodes.items():
            for rdataset in node.rdatasets:
                rtype_str = dns.rdatatype.to_text(rdataset.rdtype)
                for rdata in rdataset:
                    full_name = f"{name}.{domain}".rstrip(".")
                    records.append(f"{full_name} {rdataset.ttl} IN {rtype_str} {rdata.to_text()}")
        return records
    except Exception:
        return None


def run(host: str) -> Dict[str, Any]:
    apex = registrable_domain(host)
    result: Dict[str, Any] = {
        "domain": apex,
        "axfr": {"allowed": False, "from_ns": None, "records": []},
        "records": {},
        "subdomains": {},
    }

    # Nameservers for the apex
    ns_list = _query(apex, "NS")

    # Try AXFR from each nameserver (security check — open zone transfer is a misconfiguration)
    for ns in ns_list:
        ns_name = ns.rstrip(".")
        records = _try_axfr(ns_name, apex)
        if records is not None:
            result["axfr"]["allowed"] = True
            result["axfr"]["from_ns"] = ns
            result["axfr"]["records"] = records
            break

    # Query all standard record types on the apex
    for rtype in RECORD_TYPES:
        recs = _query(apex, rtype)
        if recs:
            result["records"][rtype] = recs

    # Enumerate common subdomains
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{apex}"
        a = _query(fqdn, "A")
        aaaa = _query(fqdn, "AAAA")
        cname = _query(fqdn, "CNAME")
        if a or aaaa or cname:
            entry: Dict[str, List[str]] = {}
            if a:
                entry["A"] = a
            if aaaa:
                entry["AAAA"] = aaaa
            if cname:
                entry["CNAME"] = cname
            result["subdomains"][sub] = entry

    return result
