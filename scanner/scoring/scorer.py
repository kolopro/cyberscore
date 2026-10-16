"""Deterministic risk scoring.

Score starts at 100 and loses points per finding by severity. This is
intentionally simple and transparent so results are reproducible and can be
explained to a user. Weights live here so scoring policy is one place.
"""
from __future__ import annotations

from scanner.models import ScanResult, Severity

# Points deducted per finding of each severity.
WEIGHTS = {
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

# Cap total deduction from any single severity bucket so one noisy category
# cannot drive the whole score to zero on its own.
BUCKET_CAP = {
    Severity.HIGH: 60,
    Severity.MEDIUM: 40,
    Severity.LOW: 20,
    Severity.INFO: 0,
}


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    if score >= 40:
        return "E"
    return "F"


def score(result: ScanResult) -> ScanResult:
    deductions = {s: 0 for s in WEIGHTS}
    for f in result.all_findings:
        deductions[f.severity] += WEIGHTS[f.severity]

    total_deduction = 0
    for sev, amount in deductions.items():
        total_deduction += min(amount, BUCKET_CAP[sev])

    result.score = max(0, 100 - total_deduction)
    result.grade = _grade(result.score)
    return result
