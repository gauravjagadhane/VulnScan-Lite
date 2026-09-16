"""Deterministic 0-100 passive-security scoring policy."""
from .models import Finding


def calculate_score(findings: list[Finding]) -> tuple[int, str]:
    score = max(0, min(100, 100 + sum(f.score_impact for f in findings)))
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    return score, grade
