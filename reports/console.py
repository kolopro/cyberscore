"""Render a ScanResult as the ASCII console report."""
from __future__ import annotations

from typing import List

from scanner.models import ScanResult, Status, Check

_GLYPH = {
    Status.OK: "✓",    # ✓
    Status.FAIL: "✗",  # ✗
    Status.WARN: "⚠",  # ⚠
    Status.INFO: "•",  # •
}

_WIDTH = 40


def _line(char: str = "=") -> str:
    return char * _WIDTH


def _section(title: str, checks: List[Check], use_color: bool = False) -> List[str]:
    out = [f"[{title}]"]
    for c in checks:
        glyph = _GLYPH.get(c.status, "•")
        text = c.label
        if c.detail:
            text = f"{text} ({c.detail})"
        out.append(f"{glyph} {text}")
    return out


def render(result: ScanResult, use_color: bool = False) -> str:
    lines: List[str] = []
    lines.append(_line("="))
    lines.append("     CYBERSCORE  ·  SECURITY SCAN")
    lines.append(_line("="))
    lines.append(f"Target: {result.target}")
    lines.append(f"SECURITY SCORE: {result.score}/100  (grade {result.grade})")
    lines.append("")

    order = [
        ("http", "HTTPS / HEADERS"),
        ("tls", "TLS"),
        ("dns", "DNS"),
        ("email", "EMAIL"),
        ("technology", "TECHNOLOGY"),
    ]
    for key, title in order:
        mod = result.modules.get(key)
        if not mod:
            continue
        if mod.error and not mod.checks:
            lines.append(f"[{title}]")
            lines.append(f"{_GLYPH[Status.WARN]} {mod.error}")
            lines.append("")
            continue
        lines.extend(_section(title, mod.checks))
        lines.append("")

    counts = result.counts()
    lines.append(_line("-"))
    lines.append(f"HIGH:   {counts['HIGH']}")
    lines.append(f"MEDIUM: {counts['MEDIUM']}")
    lines.append(f"LOW:    {counts['LOW']}")
    lines.append(_line("-"))

    # Top findings, most severe first.
    findings = sorted(
        result.all_findings,
        key=lambda f: {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}[f.severity.value],
    )
    if findings:
        lines.append("TOP ISSUES:")
        for f in findings[:8]:
            lines.append(f"  [{f.severity.value}] {f.title}")
            if f.recommendation:
                lines.append(f"        -> {f.recommendation}")
        lines.append(_line("-"))

    return "\n".join(lines)
