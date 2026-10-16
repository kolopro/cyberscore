"""Concrete reputation providers.

Each is independent and degrades to None on any error or spent budget. Keys are
read from the environment so none are hard-coded:

    URLHAUS_AUTH_KEY        - URLhaus (abuse.ch) Auth-Key (free)
    GOOGLE_SAFE_BROWSING_KEY- Google Safe Browsing API key (free tier)
    VIRUSTOTAL_API_KEY      - VirusTotal API key (free tier ~500/day, 4/min)

The coordinator chains them; if all are unavailable it uses local heuristics.
"""
from __future__ import annotations

from typing import Optional

import requests

from scanner.reputation.base import Provider, ProviderResult

_TIMEOUT = 8
_UA = "CyberScore/1.0 (+https://cyberscore.cc)"


class URLhausProvider(Provider):
    """abuse.ch URLhaus — free, no strict daily cap. Checks host + URL."""
    name = "URLhaus"
    key_env = "URLHAUS_AUTH_KEY"  # now required by abuse.ch
    daily_budget = 0

    def _lookup(self, target: str, host: str) -> Optional[ProviderResult]:
        headers = {"User-Agent": _UA, "Auth-Key": self.api_key}
        r = requests.post("https://urlhaus-api.abuse.ch/v1/host/",
                          data={"host": host}, headers=headers, timeout=_TIMEOUT)
        if r.status_code != 200:
            return None
        j = r.json()
        status = j.get("query_status")
        if status == "no_results":
            return ProviderResult(self.name, "clean", "not listed by URLhaus",
                                  0, 1, "https://urlhaus.abuse.ch/")
        if status == "ok":
            urls = j.get("urls") or []
            online = sum(1 for u in urls if u.get("url_status") == "online")
            ref = j.get("urlhaus_reference", "https://urlhaus.abuse.ch/")
            return ProviderResult(
                self.name, "malicious",
                f"listed on URLhaus ({online} active of {len(urls)} URLs)",
                max(1, online), len(urls) or 1, ref,
            )
        return None


class SafeBrowsingProvider(Provider):
    """Google Safe Browsing Lookup API (free tier)."""
    name = "Google Safe Browsing"
    key_env = "GOOGLE_SAFE_BROWSING_KEY"
    daily_budget = 10000

    def _lookup(self, target: str, host: str) -> Optional[ProviderResult]:
        body = {
            "client": {"clientId": "cyberscore", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": target}],
            },
        }
        r = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": self.api_key}, json=body, timeout=_TIMEOUT,
            headers={"User-Agent": _UA},
        )
        if r.status_code != 200:
            return None
        matches = (r.json() or {}).get("matches") or []
        if not matches:
            return ProviderResult(self.name, "clean", "no Safe Browsing match",
                                  0, 1, "https://transparencyreport.google.com/safe-browsing/search")
        kinds = ", ".join(sorted({m.get("threatType", "?") for m in matches}))
        return ProviderResult(self.name, "malicious",
                              f"Google flags: {kinds}", len(matches), len(matches),
                              "https://transparencyreport.google.com/safe-browsing/search")


class VirusTotalProvider(Provider):
    """VirusTotal v3 domain report (free tier)."""
    name = "VirusTotal"
    key_env = "VIRUSTOTAL_API_KEY"
    daily_budget = 450  # stay under the 500/day free cap

    def _lookup(self, target: str, host: str) -> Optional[ProviderResult]:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{host}",
            headers={"x-apikey": self.api_key, "User-Agent": _UA},
            timeout=_TIMEOUT,
        )
        if r.status_code != 200:
            return None
        stats = (((r.json() or {}).get("data") or {}).get("attributes") or {}) \
            .get("last_analysis_stats") or {}
        mal = int(stats.get("malicious", 0))
        susp = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 1
        ref = f"https://www.virustotal.com/gui/domain/{host}"
        if mal:
            return ProviderResult(self.name, "malicious",
                                  f"{mal}/{total} engines flag this domain",
                                  mal, total, ref)
        if susp:
            return ProviderResult(self.name, "suspicious",
                                  f"{susp}/{total} engines mark it suspicious",
                                  susp, total, ref)
        return ProviderResult(self.name, "clean",
                              f"0/{total} engines flag this domain", 0, total, ref)


#: priority order the coordinator walks (first configured + in-budget wins).
CHAIN = [URLhausProvider, SafeBrowsingProvider, VirusTotalProvider]
