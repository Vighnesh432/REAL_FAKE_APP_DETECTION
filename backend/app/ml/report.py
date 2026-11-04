from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
    TableStyle,
)

INK = colors.HexColor("#0B1524")
MUTED = colors.HexColor("#5A6B82")
EM_DASH = "—"
LINE = colors.HexColor("#D3DAE6")

BAND_COLOR = {
    "Critical": colors.HexColor("#B3243C"), "High": colors.HexColor("#C4562A"),
    "Moderate": colors.HexColor("#B07A0A"), "Low": colors.HexColor("#3F7A46"),
    "Minimal": colors.HexColor("#0C7C6B"),
}
SEVERITY_COLOR = {
    "critical": colors.HexColor("#B3243C"), "high": colors.HexColor("#C4562A"),
    "medium": colors.HexColor("#B07A0A"), "low": MUTED,
}


def _styles():
    s = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=s["Title"], fontName="Helvetica-Bold",
                                fontSize=19, textColor=INK, spaceAfter=2, alignment=TA_LEFT),
        "sub": ParagraphStyle("s", parent=s["Normal"], fontName="Helvetica",
                              fontSize=9, textColor=MUTED, spaceAfter=10),
        "h2": ParagraphStyle("h", parent=s["Heading2"], fontName="Helvetica-Bold",
                             fontSize=11, textColor=INK, spaceBefore=14, spaceAfter=6),
        "body": ParagraphStyle("b", parent=s["Normal"], fontName="Helvetica",
                               fontSize=9, textColor=INK, leading=13),
        "small": ParagraphStyle("sm", parent=s["Normal"], fontName="Helvetica",
                                fontSize=7.5, textColor=MUTED, leading=10),
        "verdict": ParagraphStyle("v", parent=s["Normal"], fontName="Helvetica-Bold",
                                  fontSize=24, leading=27),
    }


def _kv_table(rows, widths=(45 * mm, 120 * mm)):
    t = Table(rows, colWidths=widths, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 8.5),
        ("FONT", (1, 0), (1, -1), "Helvetica", 8.5),
        ("TEXTCOLOR", (0, 0), (0, -1), MUTED), ("TEXTCOLOR", (1, 0), (1, -1), INK),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE),
    ]))
    return t


def build_report(scan: dict) -> bytes:
    st = _styles()
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"Security Report - {scan['app']['app_name']}",
        author="Real-Time Fake App Detection System",
    )
    app = scan["app"]
    ev = scan.get("evidence", {})
    band = scan["risk_band"]
    band_col = BAND_COLOR.get(band, MUTED)
    story = []

    story.append(Paragraph("Application Security Report", st["title"]))
    story.append(Paragraph(
        f"Generated {datetime.now(timezone.utc).strftime('%d %B %Y, %H:%M UTC')} &nbsp;\u00b7&nbsp; "
        f"Report ID {scan.get('scan_id') or EM_DASH}", st["sub"]))
    story.append(HRFlowable(width="100%", color=INK, thickness=1.2, spaceAfter=12))

    verdict_tbl = Table([[
        Paragraph(f'<font color="{band_col.hexval()}">{scan["verdict"].upper()}</font>', st["verdict"]),
        _kv_table([
            ["Risk score", f"{scan['risk_score']} / 100  ({band})"],
            ["Fake probability", f"{scan['fake_probability']:.1%}"],
            ["Model confidence", f"{scan['confidence']:.1%}"],
            ["Classifier used", scan["model_used"].replace("_", " ").title()],
        ], widths=(30 * mm, 70 * mm)),
    ]], colWidths=(52 * mm, 122 * mm), hAlign="LEFT")
    verdict_tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (0, 0), 0),
        ("BOX", (0, 0), (-1, -1), 0.6, LINE),
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#F4F6FA")),
        ("LEFTPADDING", (0, 0), (0, 0), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(verdict_tbl)
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"<b>Recommendation.</b> {scan['recommendation']}", st["body"]))

    story.append(Paragraph("Application details", st["h2"]))
    story.append(_kv_table([
        ["Name", app.get("app_name") or "\u2014"],
        ["Package", app.get("package_name") or "Not provided"],
        ["Category", app.get("category") or "\u2014"],
    ]))

    story.append(Paragraph("Findings", st["h2"]))
    grouped = ev.get("grouped", {})
    any_found = False
    for group, items in grouped.items():
        if not items:
            continue
        any_found = True
        rows = [["Severity", "Signal", "Explanation"]]
        for it in items:
            rows.append([
                Paragraph(f'<font color="{SEVERITY_COLOR.get(it["severity"], MUTED).hexval()}">'
                         f'<b>{it["severity"].upper()}</b></font>', st["small"]),
                Paragraph(f'<b>{it["signal"]}</b>', st["small"]),
                Paragraph(it["detail"], st["small"]),
            ])
        tbl = Table(rows, colWidths=(18 * mm, 40 * mm, 106 * mm), hAlign="LEFT", repeatRows=1)
        tbl.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 7.5),
            ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F4F6FA")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.3, LINE),
            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(KeepTogether([
            Paragraph(f"<b>{group.replace('_', ' ').title()}</b>", st["body"]),
            Spacer(1, 4), tbl, Spacer(1, 9),
        ]))

    if not any_found:
        story.append(Paragraph("No risk indicators were triggered for this application.", st["body"]))

    story.append(PageBreak())
    story.append(Paragraph("How this verdict was produced", st["h2"]))
    story.append(Paragraph(
        "The application was scored by a machine learning classifier trained on labelled "
        "genuine and fraudulent listings, blended with an independent rule engine that "
        "evaluates known fraud indicators. Features were drawn from TF-IDF vectors over the "
        "preprocessed description and user reviews, engineered numeric signals covering "
        "permissions, review authenticity and marketplace metadata, and the application category.",
        st["body"]))
    story.append(Spacer(1, 8))
    story.append(_kv_table([
        ["Rule-based score", f"{ev.get('rule_risk_score', 0)} / 100"],
        ["Final (hybrid) score", f"{scan['risk_score']} / 100"],
        ["Agreement", f"{scan.get('model_alignment', 1):.0%}"],
        ["Risk signals", str(ev.get("risk_signal_count", 0))],
        ["Trust signals", str(ev.get("trust_signal_count", 0))],
    ]))
    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", color=LINE, thickness=0.5, spaceAfter=6))
    story.append(Paragraph(
        "This report is an automated risk assessment produced for academic and advisory "
        "purposes. It is not a definitive determination of fraud, and it does not replace "
        "the security review performed by an official application marketplace.", st["small"]))

    doc.build(story)
    return buf.getvalue()
