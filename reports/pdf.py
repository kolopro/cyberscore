"""PDF report generator (reportlab, pure-Python — no system dependencies).

Produces a professional report:
  1. Cover / summary with score, grade and severity counts
  2. Check-by-check results per module
  3. Prioritised remediation plan (why it matters + step-by-step fix)

reportlab is used deliberately: it ships as pure-Python wheels, so the report
generator runs anywhere the scanner runs (no Chromium / cairo / pango needed).
"""
from __future__ import annotations

import datetime as _dt
from typing import List

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, ListFlowable, ListItem, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)

from scanner.models import ScanResult, Status
from scanner import remediation

# Palette -------------------------------------------------------------------
_INK = colors.HexColor("#1f2933")
_MUTED = colors.HexColor("#616e7c")
_LINE = colors.HexColor("#d6dbe0")
_HIGH = colors.HexColor("#c0392b")
_MEDIUM = colors.HexColor("#d68910")
_LOW = colors.HexColor("#2471a3")
_OK = colors.HexColor("#1e8449")
_BG = colors.HexColor("#f4f6f8")

_SEV_COLOR = {"HIGH": _HIGH, "MEDIUM": _MEDIUM, "LOW": _LOW, "INFO": _MUTED}
_STATUS_GLYPH = {
    Status.OK: ("PASS", _OK),
    Status.FAIL: ("FAIL", _HIGH),
    Status.WARN: ("WARN", _MEDIUM),
    Status.INFO: ("INFO", _MUTED),
}
_MODULE_TITLES = {
    "http": "HTTP / Security Headers",
    "tls": "TLS / Certificate",
    "dns": "DNS",
    "email": "Email Security",
    "technology": "Technology",
}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("H1x", parent=ss["Title"], textColor=_INK,
                          fontSize=22, spaceAfter=2))
    ss.add(ParagraphStyle("Sub", parent=ss["Normal"], textColor=_MUTED,
                          fontSize=10, spaceAfter=10))
    ss.add(ParagraphStyle("H2x", parent=ss["Heading2"], textColor=_INK,
                          fontSize=13, spaceBefore=14, spaceAfter=6))
    ss.add(ParagraphStyle("Body", parent=ss["Normal"], textColor=_INK,
                          fontSize=9.5, leading=13))
    ss.add(ParagraphStyle("BodyMuted", parent=ss["Normal"], textColor=_MUTED,
                          fontSize=9, leading=12))
    ss.add(ParagraphStyle("Step", parent=ss["Normal"], textColor=_INK,
                          fontSize=9, leading=12.5, alignment=TA_LEFT))
    ss.add(ParagraphStyle("Cell", parent=ss["Normal"], textColor=_INK,
                          fontSize=9, leading=11))
    # Big score number: leading must cover the 30pt glyph so it does not
    # overflow the cell background box.
    ss.add(ParagraphStyle("Score", parent=ss["Normal"], textColor=_INK,
                          fontSize=30, leading=34, alignment=TA_LEFT))
    return ss


def _score_color(score: int):
    if score >= 80:
        return _OK
    if score >= 60:
        return _MEDIUM
    return _HIGH


def _summary_block(result: ScanResult, ss) -> List:
    counts = result.counts()
    score_col = _score_color(result.score)

    score_tbl = Table(
        [[Paragraph(f'<font size=30 color="#{score_col.hexval()[2:]}"><b>{result.score}</b></font>'
                    f'<font size=12 color="#616e7c">/100</font>', ss["Score"]),
          Paragraph(f'<b>Grade {result.grade}</b>', ss["H2x"])]],
        colWidths=[55 * mm, 40 * mm],
    )
    score_tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (-1, -1), _BG),
        ("BOX", (0, 0), (-1, -1), 0.5, _LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))

    def chip(label, n, col):
        return Paragraph(
            f'<font color="#{col.hexval()[2:]}"><b>{n}</b></font><br/>'
            f'<font size=8 color="#616e7c">{label}</font>', ss["Body"])

    counts_tbl = Table(
        [[chip("HIGH", counts["HIGH"], _HIGH),
          chip("MEDIUM", counts["MEDIUM"], _MEDIUM),
          chip("LOW", counts["LOW"], _LOW)]],
        colWidths=[30 * mm, 30 * mm, 30 * mm],
    )
    counts_tbl.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (-1, -1), _BG),
        ("BOX", (0, 0), (-1, -1), 0.5, _LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, _LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))

    row = Table([[score_tbl, counts_tbl]], colWidths=[100 * mm, 95 * mm])
    row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    return [row]


def _module_tables(result: ScanResult, ss) -> List:
    out = []
    for key in ["http", "tls", "dns", "email", "technology"]:
        mod = result.modules.get(key)
        if not mod:
            continue
        out.append(Paragraph(_MODULE_TITLES.get(key, key.title()), ss["H2x"]))
        if mod.error and not mod.checks:
            out.append(Paragraph(f"Not available: {mod.error}", ss["BodyMuted"]))
            continue
        rows = []
        for c in mod.checks:
            label, col = _STATUS_GLYPH.get(c.status, ("INFO", _MUTED))
            rows.append([
                Paragraph(f'<font color="#{col.hexval()[2:]}"><b>{label}</b></font>', ss["Cell"]),
                Paragraph(c.label, ss["Cell"]),
                Paragraph(c.detail or "", ss["BodyMuted"]),
            ])
        tbl = Table(rows, colWidths=[16 * mm, 75 * mm, 104 * mm])
        tbl.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, _LINE),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ]))
        out.append(tbl)
    return out


def _remediation_block(result: ScanResult, ss) -> List:
    plan = remediation.build_plan(result.all_findings)
    out = [Paragraph("Remediation Plan", ss["H2x"])]
    if not plan:
        out.append(Paragraph("No issues found — nothing to remediate. Well done.",
                             ss["Body"]))
        return out
    out.append(Paragraph(
        "Ordered by priority (severity first). Each item explains why it matters "
        "and how to fix it.", ss["BodyMuted"]))
    out.append(Spacer(1, 4))

    for item in plan:
        sev = item["severity"]
        col = _SEV_COLOR.get(sev, _MUTED)
        header = Table(
            [[Paragraph(f'<b>{item["priority"]}. {item["title"]}</b>', ss["Body"]),
              Paragraph(f'<font color="#{col.hexval()[2:]}"><b>{sev}</b></font> '
                        f'<font size=8 color="#616e7c">· effort: {item["effort"]}</font>',
                        ss["Cell"])]],
            colWidths=[135 * mm, 60 * mm],
        )
        header.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ("BACKGROUND", (0, 0), (-1, -1), _BG),
            ("LINEBEFORE", (0, 0), (0, 0), 3, col),
            ("LEFTPADDING", (0, 0), (0, 0), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        out.append(header)

        if item["why"]:
            out.append(Paragraph(item["why"], ss["BodyMuted"]))
        if item["evidence"]:
            out.append(Paragraph(f'<i>Observed:</i> {item["evidence"]}', ss["BodyMuted"]))
        if item["steps"]:
            steps = ListFlowable(
                [ListItem(Paragraph(s, ss["Step"]), leftIndent=6) for s in item["steps"]],
                bulletType="1", start="1", leftIndent=14,
            )
            out.append(Spacer(1, 2))
            out.append(steps)
        if item["refs"]:
            refs = " · ".join(f'<link href="{r}" color="#2471a3">{r}</link>'
                              for r in item["refs"])
            out.append(Paragraph(f'Reference: {refs}', ss["BodyMuted"]))
        out.append(Spacer(1, 8))
    return out


def _build(result: ScanResult, target_file, generated_at: str = "") -> None:
    """Build the report into a path or file-like object (`target_file`)."""
    ss = _styles()
    doc = SimpleDocTemplate(
        target_file, pagesize=A4,
        leftMargin=15 * mm, rightMargin=15 * mm,
        topMargin=15 * mm, bottomMargin=15 * mm,
        title=f"CyberScore Report — {result.target}",
        author="CyberScore (cyberscore.cc)",
    )
    story: List = []
    story.append(Paragraph("CyberScore <font size=13 color=\"#616e7c\">— Website Security Report</font>", ss["H1x"]))
    stamp = generated_at or "generated by CyberScore"
    story.append(Paragraph(f"Target: <b>{result.target}</b>  ·  {stamp}  ·  cyberscore.cc", ss["Sub"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_LINE))
    story.append(Spacer(1, 10))
    story.extend(_summary_block(result, ss))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This is a passive, non-invasive scan (HTTP headers, TLS handshake, DNS "
        "and public fingerprinting). It performs no exploitation.", ss["BodyMuted"]))

    story.extend(_module_tables(result, ss))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1, color=_LINE))
    story.extend(_remediation_block(result, ss))

    doc.build(story)


def render(result: ScanResult, path: str, generated_at: str = "") -> str:
    """Write the PDF report to `path`. Returns the path."""
    _build(result, path, generated_at)
    return path


def render_bytes(result: ScanResult, generated_at: str = "") -> bytes:
    """Return the PDF report as bytes (for web responses, no temp file)."""
    import io
    buf = io.BytesIO()
    _build(result, buf, generated_at)
    return buf.getvalue()


def default_filename(target: str) -> str:
    safe = target.replace(".", "_").replace("/", "_")
    return f"cyberscore-report-{safe}.pdf"
