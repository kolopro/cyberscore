"""Reputation coordinator: cache + provider chain + heuristic fallback.

check(target) tries each configured, in-budget provider in priority order. It
collects every answer it gets (so the UI can show "2 engines consulted"), and
if NONE are available — no keys, or all free quotas spent — it computes a local
heuristic verdict and sets ``degraded=True``. It never raises, so the website
never stops working when a free API runs out.
"""
from __future__ import annotations

import time
from typing import Dict, List
from urllib.parse import urlsplit

from scanner.reputation.providers import CHAIN
from scanner.urlcheck.analyzer import analyze as url_analyze

# tiny in-memory TTL cache: target -> (expires_at, payload)
_CACHE: Dict[str, tuple] = {}
_TTL = 15 * 60  # 15 minutes

# instantiate providers once so their per-day budgets persist across calls
_PROVIDERS = [cls() for cls in CHAIN]


def _host_of(target: str) -> str:
    t = target.strip()
    if "://" not in t:
        t = "http://" + t
    return (urlsplit(t).hostname or "").lower()


def _heuristic(target: str, host: str) -> Dict:
    """Local, offline fallback verdict built from the URL analyzer."""
    mod = url_analyze(target, fetch=False)
    v = mod.data.get("verdict", {})
    level = v.get("level", "safe")
    # Heuristics have no blocklist confirmation, so never claim "malicious" —
    # the strongest a local read gives is "suspicious".
    mapping = {"safe": "unknown", "caution": "suspicious", "suspicious": "suspicious"}
    verdict = mapping.get(level, "unknown")
    return {
        "verdict": verdict,
        "score": {"malicious": 1 if verdict == "malicious" else 0,
                  "suspicious": 1 if verdict == "suspicious" else 0,
                  "clean": 0, "total": 1},
        "engines": [],
        "degraded": True,
        "fallback_reason": "No reputation engine available (no API key or free "
                           "quota spent) — showing CyberScore's own heuristic read.",
        "heuristic_reasons": v.get("reasons", []),
    }


def _aggregate(host: str, results: List) -> str:
    if any(r.verdict == "malicious" for r in results):
        return "malicious"
    if any(r.verdict == "suspicious" for r in results):
        return "suspicious"
    if any(r.verdict == "clean" for r in results):
        return "clean"
    return "unknown"


def check(target: str, use_cache: bool = True) -> Dict:
    host = _host_of(target)
    if not host:
        return {"verdict": "unknown", "engines": [], "degraded": True,
                "fallback_reason": "No host to check.", "score": {}, "host": host}

    key = target.strip().lower()
    now = time.time()
    if use_cache and key in _CACHE and _CACHE[key][0] > now:
        return _CACHE[key][1]

    results = []
    for p in _PROVIDERS:
        res = p.query(target, host)
        if res is not None:
            results.append(res)

    if not results:
        payload = _heuristic(target, host)
    else:
        verdict = _aggregate(host, results)
        positives = sum(r.positives for r in results)
        payload = {
            "verdict": verdict,
            "score": {
                "flagged_by": sum(1 for r in results if r.verdict in ("malicious", "suspicious")),
                "engines_consulted": len(results),
                "positives": positives,
            },
            "engines": [r.to_dict() for r in results],
            "degraded": False,
            "fallback_reason": "",
        }

    payload["host"] = host
    payload["target"] = target
    budgets = {p.name: p.budget_left() for p in _PROVIDERS}
    payload["provider_status"] = {
        p.name: ("ready" if (p.configured() and p.has_budget())
                 else "no key" if not p.configured()
                 else "quota spent")
        for p in _PROVIDERS
    }
    payload["budget_left"] = budgets

    if use_cache:
        _CACHE[key] = (now + _TTL, payload)
    return payload
