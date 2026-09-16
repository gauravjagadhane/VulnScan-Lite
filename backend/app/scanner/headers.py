"""Documented policy checks for common browser security response headers."""
from collections.abc import Mapping
from .models import Finding, FindingStatus, Severity

_REMEDIATION = {
    "Content-Security-Policy": "Define a restrictive Content-Security-Policy, starting with default-src 'self', and tailor allowed sources to the application.",
    "X-Frame-Options": "Set X-Frame-Options to DENY or SAMEORIGIN (or enforce frame-ancestors in CSP) to reduce clickjacking exposure.",
    "Strict-Transport-Security": "After confirming HTTPS works across all subdomains, send Strict-Transport-Security with max-age of at least 15552000 and consider includeSubDomains.",
    "X-Content-Type-Options": "Set X-Content-Type-Options: nosniff so browsers do not MIME-sniff responses.",
    "Referrer-Policy": "Set Referrer-Policy to strict-origin-when-cross-origin or a stricter policy appropriate for the application.",
    "Permissions-Policy": "Set a Permissions-Policy that disables browser features your application does not use.",
}


def analyze_headers(headers: Mapping[str, str], is_https: bool) -> list[Finding]:
    """Evaluate header presence and conservative value policies without overclaiming."""
    normalized = {key.lower(): value.strip() for key, value in headers.items()}
    findings: list[Finding] = []
    required = [
        ("Content-Security-Policy", "content-security-policy", -10),
        ("X-Frame-Options", "x-frame-options", -10),
        ("Strict-Transport-Security", "strict-transport-security", -10),
    ]
    for label, key, penalty in required:
        value = normalized.get(key)
        applicable = not (label == "Strict-Transport-Security" and not is_https)
        if not value:
            findings.append(Finding(name=label, category="Security Headers", status=FindingStatus.failed if applicable else FindingStatus.warning,
                severity=Severity.medium, score_impact=penalty if applicable else 0,
                explanation=f"{label} is a required policy check and was not present.", evidence="Header was not present.", remediation=_REMEDIATION[label]))
        elif label == "X-Frame-Options" and value.upper() not in {"DENY", "SAMEORIGIN"}:
            findings.append(Finding(name=label, category="Security Headers", status=FindingStatus.warning, severity=Severity.low, score_impact=-3,
                explanation="The header is present but its value is not one of the scanner's recognized protective values.", evidence=f"Observed value: {value[:200]}", remediation=_REMEDIATION[label]))
        elif label == "Strict-Transport-Security" and "max-age=" not in value.lower():
            findings.append(Finding(name=label, category="Security Headers", status=FindingStatus.warning, severity=Severity.low, score_impact=-3,
                explanation="HSTS is present but does not declare a max-age directive.", evidence=f"Observed value: {value[:200]}", remediation=_REMEDIATION[label]))
        else:
            findings.append(Finding(name=label, category="Security Headers", status=FindingStatus.passed, severity=Severity.info,
                explanation="The header is present and meets this scanner's baseline policy.", evidence=f"Observed value: {value[:200]}"))
    for label in ("X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"):
        value = normalized.get(label.lower())
        findings.append(Finding(name=label, category="Security Headers", status=FindingStatus.passed if value else FindingStatus.warning,
            severity=Severity.info if value else Severity.low, score_impact=0,
            explanation="Bonus hardening header is present." if value else "Bonus hardening header was not present.",
            evidence=f"Observed value: {value[:200]}" if value else "Header was not present.", remediation=None if value else _REMEDIATION[label]))
    return findings
