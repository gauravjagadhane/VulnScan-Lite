from app.scanner.headers import analyze_headers
from fixtures import MISSING_SECURITY_HEADERS, SECURE_HEADERS


def test_missing_required_headers_have_documented_penalties():
    findings = analyze_headers(MISSING_SECURITY_HEADERS, True)
    penalties = {item.name: item.score_impact for item in findings}
    assert penalties["Content-Security-Policy"] == -10
    assert penalties["X-Frame-Options"] == -10
    assert penalties["Strict-Transport-Security"] == -10


def test_baseline_headers_pass_case_insensitively():
    headers = {key.swapcase(): value for key, value in SECURE_HEADERS.items()}
    findings = analyze_headers(headers, True)
    assert all(item.status.value == "passed" for item in findings[:3])


def test_http_target_is_not_penalized_for_missing_hsts():
    hsts = next(item for item in analyze_headers({}, is_https=False) if item.name == "Strict-Transport-Security")
    assert (hsts.status.value, hsts.score_impact) == ("warning", 0)


def test_empty_required_header_is_treated_as_missing():
    csp = next(item for item in analyze_headers({"Content-Security-Policy": "  "}, is_https=True) if item.name == "Content-Security-Policy")
    assert (csp.status.value, csp.score_impact) == ("failed", -10)
