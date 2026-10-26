"""PDF report generator (reportlab, pure-Python — no system dependencies).

Charcoal / Amber branded report that mirrors the on-site results layout:
  1. Charcoal header band
  2. Summary score card (amber score, grade, qualifier) + High/Medium/Low cards
  3. Executive summary + "Assessment at a glance" category table
  4. Detailed check-by-check results per area
  5. Prioritised remediation plan (severity pill, why it matters, step-by-step fix)
  6. Important notes (passive-scan disclaimer)

reportlab is used deliberately: it ships as pure-Python wheels, so the report
generator runs anywhere the scanner runs (no Chromium / cairo / pango needed).
"""
from __future__ import annotations

from typing import List

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, NextPageTemplate, PageTemplate,
    HRFlowable, ListFlowable, ListItem, Paragraph, Spacer, Table, TableStyle,
)

from scanner.models import ScanResult, Status
from scanner import remediation

# Palette — Charcoal / Amber -------------------------------------------------
_CHARCOAL = colors.HexColor("#161c27")   # header band / score card
_SLATE    = colors.HexColor("#273244")   # secondary charcoal
_AMBER    = colors.HexColor("#f59e0b")   # brand accent / score
_AMBER_HI = colors.HexColor("#ffc247")   # bright accent
_INK      = colors.HexColor("#1f2933")   # body text on white
_MUTED    = colors.HexColor("#616e7c")   # secondary text
_LINE     = colors.HexColor("#e2e6ea")   # hairlines
_CARD     = colors.HexColor("#f7f8fa")   # light card fill
_WHITE    = colors.white

# Severity (semantic — kept distinct for accessibility)
_HIGH   = colors.HexColor("#d64545")
_MEDIUM = colors.HexColor("#e08a00")
_LOW    = colors.HexColor("#3b7dd8")
_OK     = colors.HexColor("#2e9e5b")

_SEV_COLOR = {"HIGH": _HIGH, "MEDIUM": _MEDIUM, "LOW": _LOW, "INFO": _MUTED}
_STATUS_GLYPH = {
    Status.OK:   ("PASS", _OK),
    Status.FAIL: ("FAIL", _HIGH),
    Status.WARN: ("WARN", _MEDIUM),
    Status.INFO: ("INFO", _LOW),
}
_MODULE_TITLES = {
    "http": "HTTP / Security Headers",
    "tls": "TLS / Certificate",
    "dns": "DNS",
    "email": "Email Security",
    "technology": "Technology",
}

_PAGE_W, _PAGE_H = A4
_MARGIN = 15 * mm


def _hx(c: colors.Color) -> str:
    return "#" + c.hexval()[2:]


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("H2x", parent=ss["Heading2"], textColor=_INK,
                          fontName="Helvetica-Bold", fontSize=13,
                          spaceBefore=16, spaceAfter=7))
    ss.add(ParagraphStyle("Body", parent=ss["Normal"], textColor=_INK,
                          fontSize=9.5, leading=13.5))
    ss.add(ParagraphStyle("BodyMuted", parent=ss["Normal"], textColor=_MUTED,
                          fontSize=9, leading=12.5))
    ss.add(ParagraphStyle("Step", parent=ss["Normal"], textColor=_INK,
                          fontSize=9, leading=12.5, alignment=TA_LEFT))
    ss.add(ParagraphStyle("Cell", parent=ss["Normal"], textColor=_INK,
                          fontSize=9, leading=11.5))
    ss.add(ParagraphStyle("CellMuted", parent=ss["Normal"], textColor=_MUTED,
                          fontSize=8.5, leading=11))
    return ss


# ---------------------------------------------------------------------------
# Canvas: header band + footer (per page)
# ---------------------------------------------------------------------------
def _draw_footer(c, doc):
    c.saveState()
    c.setStrokeColor(_AMBER)
    c.setLineWidth(0.8)
    c.line(_MARGIN, 12 * mm, _PAGE_W - _MARGIN, 12 * mm)
    c.setFont("Helvetica", 8)
    c.setFillColor(_MUTED)
    c.drawString(_MARGIN, 8 * mm, "CyberScore  ·  cyberscore.cc")
    c.drawRightString(_PAGE_W - _MARGIN, 8 * mm, f"Page {doc.page}")
    c.restoreState()


def _shield(c, x, y, s):
    """Tiny amber shield glyph at (x,y) baseline-ish, size s."""
    c.saveState()
    c.setFillColor(_AMBER)
    p = c.beginPath()
    p.moveTo(x, y + s)
    p.lineTo(x + s * 0.5, y + s * 1.15)
    p.lineTo(x + s, y + s)
    p.lineTo(x + s, y + s * 0.45)
    p.curveTo(x + s, y + s * 0.1, x + s * 0.5, y - s * 0.15, x + s * 0.5, y - s * 0.15)
    p.curveTo(x + s * 0.5, y - s * 0.15, x, y + s * 0.1, x, y + s * 0.45)
    p.close()
    c.drawPath(p, fill=1, stroke=0)
    c.restoreState()


def _on_first(c, doc):
    band_h = 30 * mm
    top = _PAGE_H - band_h
    c.saveState()
    c.setFillColor(_CHARCOAL)
    c.rect(0, top, _PAGE_W, band_h, fill=1, stroke=0)
    # amber accent strip along the bottom of the band
    c.setFillColor(_AMBER)
    c.rect(0, top, _PAGE_W, 1.4 * mm, fill=1, stroke=0)
    # shield + wordmark
    _shield(c, _MARGIN, _PAGE_H - 16 * mm, 6 * mm)
    c.setFillColor(_WHITE)
    c.setFont("Helvetica-Bold", 21)
    c.drawString(_MARGIN + 10 * mm, _PAGE_H - 15 * mm, "CyberScore")
    c.setFillColor(_AMBER_HI)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(_MARGIN + 10 * mm, _PAGE_H - 21 * mm, "Website Security Report")
    # right side meta
    c.setFillColor(colors.HexColor("#aab3bf"))
    c.setFont("Helvetica", 9)
    c.drawRightString(_PAGE_W - _MARGIN, _PAGE_H - 13 * mm, f"Target:  {doc._cs_target}")
    c.drawRightString(_PAGE_W - _MARGIN, _PAGE_H - 19 * mm, doc._cs_stamp)
    c.restoreState()
    _draw_footer(c, doc)


def _on_later(c, doc):
    band_h = 13 * mm
    top = _PAGE_H - band_h
    c.saveState()
    c.setFillColor(_CHARCOAL)
    c.rect(0, top, _PAGE_W, band_h, fill=1, stroke=0)
    c.setFillColor(_AMBER)
    c.rect(0, top, _PAGE_W, 1 * mm, fill=1, stroke=0)
    c.setFillColor(_WHITE)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(_MARGIN, _PAGE_H - 9 * mm, "CyberScore")
    c.setFillColor(_AMBER_HI)
    c.setFont("Helvetica", 9)
    c.drawString(_MARGIN + 26 * mm, _PAGE_H - 9 * mm, "Security Report")
    c.setFillColor(colors.HexColor("#aab3bf"))
    c.setFont("Helvetica", 8.5)
    c.drawRightString(_PAGE_W - _MARGIN, _PAGE_H - 9 * mm, doc._cs_target)
    c.restoreState()
    _draw_footer(c, doc)


# ---------------------------------------------------------------------------
# Content blocks
# ---------------------------------------------------------------------------
def _score_qual(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 80:
        return "Good"
    if score >= 60:
        return "Needs improvement"
    return "Poor"


def _score_color(score: int):
    if score >= 80:
        return _OK
    if score >= 60:
        return _AMBER
    return _HIGH


def _summary_block(result: ScanResult, ss) -> List:
    counts = result.counts()
    total_issues = counts["HIGH"] + counts["MEDIUM"] + counts["LOW"]
    sc_col = _score_color(result.score)

    # --- left: charcoal score card (outer 84mm, 12mm side padding -> 60mm content) ---
    score_para = Paragraph(
        f'<font name="Helvetica-Bold" size=40 color="{_hx(_AMBER)}">{result.score}</font>'
        f'<font size=14 color="#aab3bf">/100</font>',
        ParagraphStyle("score", leading=46))
    grade_para = Paragraph(
        f'<font name="Helvetica-Bold" size=14 color="{_hx(_WHITE)}">Grade {result.grade}</font>'
        f'<br/><font size=9 color="{_hx(_AMBER_HI)}">{_score_qual(result.score)}</font>',
        ParagraphStyle("gr", alignment=TA_RIGHT, leading=15))
    score_inner = Table([[score_para, grade_para]], colWidths=[30 * mm, 30 * mm])
    score_inner.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    label = Paragraph(
        f'<font size=8 color="#8b95a3">SECURITY SCORE</font>',
        ParagraphStyle("lbl", leading=10))
    score_card = Table([[label], [score_inner]], colWidths=[84 * mm])
    score_card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _CHARCOAL),
        ("LINEBEFORE", (0, 0), (0, -1), 3, _AMBER),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (0, 0), 12),
        ("BOTTOMPADDING", (0, 0), (0, 0), 4),
        ("TOPPADDING", (0, 1), (0, 1), 2),
        ("BOTTOMPADDING", (0, 1), (0, 1), 14),
    ]))

    # --- right: three severity cards ---
    def sev_card(label, n, col):
        return Table(
            [[Paragraph(f'<font name="Helvetica-Bold" size=22 color="{_hx(col)}">{n}</font>',
                        ParagraphStyle("n", alignment=TA_CENTER, leading=24))],
             [Paragraph(f'<font size=8 color="{_hx(_MUTED)}">{label}</font>',
                        ParagraphStyle("l", alignment=TA_CENTER, leading=10))]],
            colWidths=[30 * mm])
    cards = Table(
        [[sev_card("HIGH", counts["HIGH"], _HIGH),
          sev_card("MEDIUM", counts["MEDIUM"], _MEDIUM),
          sev_card("LOW", counts["LOW"], _LOW)]],
        colWidths=[32 * mm, 32 * mm, 32 * mm])
    cards.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _CARD),
        ("BOX", (0, 0), (-1, -1), 0.6, _LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.6, _LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 11),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
    ]))

    row = Table([[score_card, cards]], colWidths=[84 * mm, 96 * mm])
    row.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (0, 0), 0),
        ("LEFTPADDING", (1, 0), (1, 0), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))

    # status banner
    if counts["HIGH"]:
        btxt, bcol = "Action needed — high-severity issues were found.", _HIGH
    elif counts["MEDIUM"]:
        btxt, bcol = "Some improvements recommended — medium-severity issues found.", _MEDIUM
    elif total_issues:
        btxt, bcol = "Looking good — only minor items to tidy up.", _LOW
    else:
        btxt, bcol = "No issues found — this target passed every check.", _OK
    banner = Table([[Paragraph(
        f'<font name="Helvetica-Bold" color="{_hx(bcol)}">{btxt}</font>', ss["Cell"])]],
        colWidths=[180 * mm])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _CARD),
        ("LINEBEFORE", (0, 0), (0, 0), 3, bcol),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))

    return [row, Spacer(1, 7), banner]


def _exec_summary(result: ScanResult, ss) -> List:
    counts = result.counts()
    n_mod = len([m for m in result.modules.values() if m.checks])
    total_checks = sum(len(m.checks) for m in result.modules.values())
    passed = sum(1 for m in result.modules.values()
                 for c in m.checks if c.status == Status.OK)
    issues = counts["HIGH"] + counts["MEDIUM"] + counts["LOW"]
    if issues:
        parts = []
        if counts["HIGH"]:
            parts.append(f'{counts["HIGH"]} high')
        if counts["MEDIUM"]:
            parts.append(f'{counts["MEDIUM"]} medium')
        if counts["LOW"]:
            parts.append(f'{counts["LOW"]} low')
        sev_txt = ", ".join(parts)
        txt = (f'CyberScore ran a passive security assessment of '
               f'<b>{result.target}</b> across {n_mod} areas '
               f'({total_checks} checks, {passed} passed) and scored it '
               f'<b>{result.score}/100</b> (Grade {result.grade}). '
               f'{issues} issue(s) need attention: {sev_txt}. '
               f'The prioritised remediation plan below explains each one and how to fix it.')
    else:
        txt = (f'CyberScore ran a passive security assessment of '
               f'<b>{result.target}</b> across {n_mod} areas '
               f'({total_checks} checks, all passed) and scored it '
               f'<b>{result.score}/100</b> (Grade {result.grade}). '
               f'No issues were found — this target follows current best practices.')
    return [Paragraph("Executive summary", ss["H2x"]),
            Paragraph(txt, ss["Body"])]


def _at_a_glance(result: ScanResult, ss) -> List:
    header = [Paragraph(f'<font color="{_hx(_WHITE)}"><b>Area</b></font>', ss["Cell"]),
              Paragraph(f'<font color="{_hx(_WHITE)}"><b>Checks passed</b></font>', ss["Cell"]),
              Paragraph(f'<font color="{_hx(_WHITE)}"><b>Status</b></font>', ss["Cell"])]
    rows = [header]
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), _SLATE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, _LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]
    for ridx, key in enumerate(["http", "tls", "dns", "email", "technology"], start=1):
        mod = result.modules.get(key)
        if not mod:
            continue
        title = _MODULE_TITLES.get(key, key.title())
        if mod.error and not mod.checks:
            rows.append([Paragraph(title, ss["Cell"]),
                         Paragraph("—", ss["CellMuted"]),
                         Paragraph(f'<font color="{_hx(_MUTED)}">Not available</font>', ss["Cell"])])
            continue
        total = len(mod.checks)
        passed = sum(1 for c in mod.checks if c.status == Status.OK)
        has_fail = any(c.status == Status.FAIL for c in mod.checks)
        has_warn = any(c.status == Status.WARN for c in mod.checks)
        if has_fail:
            stxt, scol = "Needs attention", _HIGH
        elif has_warn:
            stxt, scol = "Review", _MEDIUM
        else:
            stxt, scol = "Good", _OK
        rows.append([
            Paragraph(title, ss["Cell"]),
            Paragraph(f"{passed} / {total}", ss["Cell"]),
            Paragraph(f'<font name="Helvetica-Bold" color="{_hx(scol)}">{stxt}</font>', ss["Cell"]),
        ])
        if ridx % 2 == 0:
            style.append(("BACKGROUND", (0, ridx), (-1, ridx), _CARD))
    tbl = Table(rows, colWidths=[85 * mm, 45 * mm, 50 * mm])
    tbl.setStyle(TableStyle(style))
    return [Paragraph("Assessment at a glance", ss["H2x"]), tbl]


def _module_tables(result: ScanResult, ss) -> List:
    out = [Paragraph("Detailed results", ss["H2x"])]
    for key in ["http", "tls", "dns", "email", "technology"]:
        mod = result.modules.get(key)
        if not mod:
            continue
        title = _MODULE_TITLES.get(key, key.title())
        heading = Table([[Paragraph(
            f'<font name="Helvetica-Bold" size=10.5 color="{_hx(_INK)}">{title}</font>', ss["Cell"])]],
            colWidths=[180 * mm])
        heading.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), _CARD),
            ("LINEBEFORE", (0, 0), (0, 0), 3, _AMBER),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        out.append(Spacer(1, 4))
        out.append(heading)
        if mod.error and not mod.checks:
            out.append(Paragraph(f"Not available: {mod.error}", ss["BodyMuted"]))
            continue
        rows = []
        for c in mod.checks:
            lbl, col = _STATUS_GLYPH.get(c.status, ("INFO", _MUTED))
            rows.append([
                Paragraph(f'<font name="Helvetica-Bold" color="{_hx(col)}">{lbl}</font>', ss["Cell"]),
                Paragraph(c.label, ss["Cell"]),
                Paragraph(c.detail or "", ss["CellMuted"]),
            ])
        tbl = Table(rows, colWidths=[16 * mm, 70 * mm, 94 * mm])
        tbl.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, _LINE),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (0, -1), 4),
        ]))
        out.append(tbl)
    return out


def _remediation_block(result: ScanResult, ss) -> List:
    plan = remediation.build_plan(result.all_findings)
    out = [Paragraph("Remediation plan", ss["H2x"])]
    if not plan:
        out.append(Paragraph("No issues found — nothing to remediate. Well done.", ss["Body"]))
        return out
    out.append(Paragraph(
        "Ordered by priority (severity first). Each item explains why it matters "
        "and how to fix it.", ss["BodyMuted"]))
    out.append(Spacer(1, 6))

    for item in plan:
        sev = item["severity"]
        col = _SEV_COLOR.get(sev, _MUTED)
        # severity pill (white text on colored bg) via a one-cell table
        pill = Table([[Paragraph(
            f'<font name="Helvetica-Bold" size=7.5 color="{_hx(_WHITE)}">{sev}</font>',
            ParagraphStyle("p", alignment=TA_CENTER, leading=9))]], colWidths=[18 * mm])
        pill.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), col),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        title_p = Paragraph(
            f'<font name="Helvetica-Bold" size=10 color="{_hx(_INK)}">'
            f'{item["priority"]}. {item["title"]}</font>'
            f'<br/><font size=8 color="{_hx(_MUTED)}">Area: {item["module"].upper()}'
            f'  ·  Effort: {item["effort"]}</font>', ss["Cell"])
        header = Table([[title_p, pill]], colWidths=[162 * mm, 18 * mm])
        header.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ("BACKGROUND", (0, 0), (-1, -1), _CARD),
            ("LINEBEFORE", (0, 0), (0, 0), 3, col),
            ("LEFTPADDING", (0, 0), (0, 0), 9),
            ("RIGHTPADDING", (1, 0), (1, 0), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        body = []
        if item["why"]:
            body.append(Paragraph(item["why"], ss["BodyMuted"]))
        if item["evidence"]:
            body.append(Paragraph(f'<i>Observed:</i> {item["evidence"]}', ss["BodyMuted"]))
        if item["steps"]:
            body.append(Spacer(1, 2))
            body.append(ListFlowable(
                [ListItem(Paragraph(s, ss["Step"]), leftIndent=6) for s in item["steps"]],
                bulletType="1", start="1", leftIndent=14))
        if item["refs"]:
            refs = " · ".join(f'<link href="{r}" color="{_hx(_LOW)}">{r}</link>'
                              for r in item["refs"])
            body.append(Paragraph(f'Reference: {refs}', ss["BodyMuted"]))
        out.append(header)
        if body:
            wrap = Table([[body]], colWidths=[180 * mm])
            wrap.setStyle(TableStyle([
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LINEBELOW", (0, 0), (-1, -1), 0.5, _LINE),
                ("LINEAFTER", (0, 0), (-1, -1), 0.5, _LINE),
                ("LINEBEFORE", (0, 0), (-1, -1), 0.5, _LINE),
            ]))
            out.append(wrap)
        out.append(Spacer(1, 9))
    return out


def _notes_block(ss) -> List:
    txt = ("This is a <b>passive, non-invasive</b> assessment. CyberScore inspects "
           "HTTP response headers, the TLS handshake and certificate, public DNS "
           "records and publicly visible technology fingerprints. It performs no "
           "exploitation, login attempts or intrusive probing, so results reflect "
           "what any visitor could observe. A clean score is not a guarantee of "
           "overall security — application-level and internal risks are out of scope.")
    box = Table([[Paragraph(txt, ss["BodyMuted"])]], colWidths=[180 * mm])
    box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _CARD),
        ("BOX", (0, 0), (-1, -1), 0.6, _LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return [Paragraph("Important notes", ss["H2x"]), box]


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
def _build(result: ScanResult, target_file, generated_at: str = "") -> None:
    ss = _styles()
    doc = BaseDocTemplate(
        target_file, pagesize=A4,
        leftMargin=_MARGIN, rightMargin=_MARGIN,
        topMargin=_MARGIN, bottomMargin=18 * mm,
        title=f"CyberScore Report — {result.target}",
        author="CyberScore (cyberscore.cc)",
    )
    doc._cs_target = result.target
    doc._cs_stamp = generated_at or "Passive security scan"

    # first page: content frame starts below the 30mm header band
    first_frame = Frame(_MARGIN, 18 * mm, _PAGE_W - 2 * _MARGIN,
                        _PAGE_H - 34 * mm - 18 * mm, id="first")
    later_frame = Frame(_MARGIN, 18 * mm, _PAGE_W - 2 * _MARGIN,
                        _PAGE_H - 16 * mm - 18 * mm, id="later")
    doc.addPageTemplates([
        PageTemplate(id="first", frames=[first_frame], onPage=_on_first),
        PageTemplate(id="later", frames=[later_frame], onPage=_on_later),
    ])

    story: List = [NextPageTemplate("later")]
    story.extend(_summary_block(result, ss))
    story.extend(_exec_summary(result, ss))
    story.extend(_at_a_glance(result, ss))
    story.extend(_module_tables(result, ss))
    story.extend(_remediation_block(result, ss))
    story.extend(_notes_block(ss))
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
