"""Generate a concise, print-friendly passive security report with ReportLab."""
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from ..scanner.models import ScanResult


def build_pdf(report: ScanResult) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=1.6 * cm,
        leftMargin=1.6 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="Score",
            parent=styles["Title"],
            fontSize=28,
            textColor=colors.HexColor("#0F766E"),
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="TableCell",
            parent=styles["BodyText"],
            fontSize=7.5,
            leading=9.5,
            spaceAfter=0,
        )
    )
    styles.add(
        ParagraphStyle(
            name="TableHeader",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9.5,
            textColor=colors.white,
            spaceAfter=0,
        )
    )

    cell = styles["TableCell"]
    header = styles["TableHeader"]

    story = [
        Paragraph("VulnScan Lite", styles["Title"]),
        Paragraph("Passive Security Health Report", styles["Heading2"]),
        Paragraph(
            "Only scan websites you own or have permission to assess. "
            "This tool performs passive analysis only; it is not a penetration test.",
            styles["BodyText"],
        ),
        Spacer(1, 14),
        Paragraph(f"{report.score}/100 - Grade {report.grade}", styles["Score"]),
    ]

    summary_rows = [
        [Paragraph("Target", header), Paragraph(report.target_url, cell)],
        [Paragraph("Scanned", header), Paragraph(report.scanned_at.isoformat(timespec="seconds"), cell)],
        [Paragraph("HTTP status", header), Paragraph(str(report.http_status or "n/a"), cell)],
    ]
    summary_table = Table(
        summary_rows,
        colWidths=[3 * cm, 14 * cm],
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story += [summary_table, Spacer(1, 14)]

    if report.tls:
        story += [
            Paragraph("TLS / HTTPS", styles["Heading2"]),
            Paragraph(
                f"Protocol: {report.tls.protocol or 'not available'}<br/>"
                f"Cipher: {report.tls.cipher or 'n/a'}<br/>"
                f"Issuer: {report.tls.issuer or 'n/a'}",
                styles["BodyText"],
            ),
            Spacer(1, 10),
        ]

    if report.cms:
        story += [
            Paragraph("CMS Detection", styles["Heading2"]),
            Paragraph(
                f"{report.cms.name or 'No supported CMS detected'} - "
                f"version: {report.cms.version or 'unknown'} - "
                f"confidence: {report.cms.confidence.value}",
                styles["BodyText"],
            ),
            Spacer(1, 10),
        ]

    story.append(Paragraph("Findings and remediation", styles["Heading2"]))

    rows = [[
        Paragraph("Status", header),
        Paragraph("Finding", header),
        Paragraph("Evidence", header),
        Paragraph("Recommended action", header),
    ]]

    for finding in report.findings:
        rows.append([
            Paragraph(finding.status.value.title(), cell),
            Paragraph(finding.name, cell),
            Paragraph(finding.evidence or "n/a", cell),
            Paragraph(finding.remediation or "No action required.", cell),
        ])

    # Keep the table inside the A4 content width and use Paragraph cells so
    # long evidence/remediation text wraps instead of overflowing/clipping.
    table = Table(
        rows,
        colWidths=[2.0 * cm, 3.1 * cm, 4.7 * cm, 7.9 * cm],
        repeatRows=1,
    )
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("LEADING", (0, 0), (-1, -1), 9.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(table)

    doc.build(story)
    return buffer.getvalue()
