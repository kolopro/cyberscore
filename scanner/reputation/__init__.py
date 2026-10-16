"""Multi-engine URL/domain reputation with graceful fallback.

Public entry point: ``check(target)`` → dict. Never raises; when all paid/free
engines are exhausted or unconfigured it falls back to local heuristics and
sets ``degraded=True`` so the website keeps working even after free API quotas
run out.
"""
from scanner.reputation.coordinator import check  # noqa: F401
