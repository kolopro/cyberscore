"""Reputation provider base class + shared helpers.

A provider wraps one threat-intelligence source (URLhaus, Google Safe Browsing,
VirusTotal, ...). Each tracks its own per-day budget so the coordinator can skip
a provider once its free quota is spent, without that provider ever raising.
"""
from __future__ import annotations

import datetime
import os
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class ProviderResult:
    """Normalised output from a single provider."""
    provider: str
    verdict: str  # "clean" | "malicious" | "suspicious" | "unknown"
    detail: str = ""
    positives: int = 0          # engines/sources that flagged it
    total: int = 0              # engines/sources that were consulted
    reference: str = ""         # link a user can open for the full report
    data: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "provider": self.provider, "verdict": self.verdict,
            "detail": self.detail, "positives": self.positives,
            "total": self.total, "reference": self.reference,
        }


class Provider:
    """Base provider. Subclasses implement ``_lookup``; ``query`` is safe."""

    name = "provider"
    #: free calls allowed per day (0 = unlimited / not metered)
    daily_budget = 0
    #: env var holding the API key; None means no key needed
    key_env: Optional[str] = None

    def __init__(self) -> None:
        self._count_day = ""
        self._count = 0

    # -- budget bookkeeping --------------------------------------------------
    @property
    def api_key(self) -> str:
        return os.environ.get(self.key_env, "").strip() if self.key_env else ""

    def configured(self) -> bool:
        """Is this provider usable right now (has a key if it needs one)?"""
        return True if self.key_env is None else bool(self.api_key)

    def _today(self) -> str:
        return datetime.date.today().isoformat()

    def budget_left(self) -> Optional[int]:
        if not self.daily_budget:
            return None
        if self._count_day != self._today():
            return self.daily_budget
        return max(0, self.daily_budget - self._count)

    def has_budget(self) -> bool:
        left = self.budget_left()
        return left is None or left > 0

    def _spend(self) -> None:
        today = self._today()
        if self._count_day != today:
            self._count_day, self._count = today, 0
        self._count += 1

    # -- public API ----------------------------------------------------------
    def query(self, target: str, host: str) -> Optional[ProviderResult]:
        """Return a ProviderResult, or None if unavailable. Never raises."""
        if not self.configured() or not self.has_budget():
            return None
        try:
            res = self._lookup(target, host)
        except Exception:
            return None
        if res is not None:
            self._spend()
        return res

    def _lookup(self, target: str, host: str) -> Optional[ProviderResult]:
        raise NotImplementedError
