from app.scanner.models import Finding, FindingStatus, Severity
from app.scanner.scoring import calculate_score


def test_score_is_bounded_and_graded_deterministically():
    finding = Finding(name="test", category="test", status=FindingStatus.failed, severity=Severity.high, score_impact=-150, explanation="x", evidence="x")
    assert calculate_score([finding]) == (0, "F")
    assert calculate_score([]) == (100, "A")
