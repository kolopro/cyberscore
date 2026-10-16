"""Shared data models used across all scanner modules.

Keeping these framework-agnostic and serialisable means the exact same
objects can back a CLI today and a JSON API / web app / SaaS later.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(str, Enum):
    """Display status for a single check line in the report."""
    OK = "ok"        # ✓
    FAIL = "fail"    # ✗
    WARN = "warn"    # ⚠
    INFO = "info"    # •


@dataclass
class Check:
    """A single passive check with a pass/fail/warn outcome."""
    key: str
    label: str
    status: Status
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Finding:
    """A prioritised issue surfaced by a module. Feeds scoring + summary."""
    severity: Severity
    title: str
    module: str
    recommendation: str = ""
    evidence: str = ""
    code: str = ""  # stable id for remediation lookup, e.g. "http.no_hsts"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ModuleResult:
    """Output of one scanner module (http, tls, dns, ...)."""
    name: str
    checks: List[Check] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def add_check(self, key: str, label: str, status: Status, detail: str = "") -> None:
        self.checks.append(Check(key, label, status, detail))

    def add_finding(self, severity: Severity, title: str,
                    recommendation: str = "", evidence: str = "",
                    code: str = "") -> None:
        self.findings.append(
            Finding(severity, title, self.name, recommendation, evidence, code)
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "checks": [c.to_dict() for c in self.checks],
            "findings": [f.to_dict() for f in self.findings],
            "data": self.data,
            "error": self.error,
        }


@dataclass
class ScanResult:
    """The complete result of scanning one target."""
    target: str
    modules: Dict[str, ModuleResult] = field(default_factory=dict)
    score: int = 0
    grade: str = ""

    @property
    def all_findings(self) -> List[Finding]:
        out: List[Finding] = []
        for m in self.modules.values():
            out.extend(m.findings)
        return out

    def counts(self) -> Dict[str, int]:
        c = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.all_findings:
            if f.severity.value in c:
                c[f.severity.value] += 1
        return c

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "score": self.score,
            "grade": self.grade,
            "counts": self.counts(),
            "modules": {k: v.to_dict() for k, v in self.modules.items()},
        }
