from app.reports.pdf_generator import build_pdf
from app.scanner.models import Finding, FindingStatus, Severity, ScanResult


def test_pdf_report_is_generated():
    report = ScanResult(target_url="https://example.com", score=90, grade="A", duration_ms=42,
        findings=[Finding(name="Content-Security-Policy", category="Security Headers", status=FindingStatus.passed, severity=Severity.info, explanation="Present.", evidence="default-src 'self'")])
    document = build_pdf(report)
    assert document.startswith(b"%PDF")
    assert len(document) > 1_000


def test_pdf_handles_long_target_and_missing_optional_results():
    report = ScanResult(
        target_url="https://example.com/" + "path/" * 250,
        score=0,
        grade="F",
        duration_ms=0,
        findings=[Finding(name="Long finding", category="Other Findings", status=FindingStatus.failed, severity=Severity.high, explanation="x" * 500, evidence="y" * 500, remediation="z" * 500)],
    )
    document = build_pdf(report)
    assert document.startswith(b"%PDF")
