"""Orchestrates one bounded, passive web security assessment."""
from collections.abc import Callable
from time import perf_counter
from urllib.parse import urljoin, urlparse
import httpx
from .cms import detect_cms
from .headers import analyze_headers
from .models import Finding, FindingStatus, Severity, ScanResult
from .safety import assert_public_host, validate_target_url
from .scoring import calculate_score
from .tls import inspect_tls


class ScannerEngine:
    """Performs normal GET and TLS-handshake inspection with strict resource bounds."""
    user_agent = "VulnScan-Lite/1.0 (passive security assessment)"

    def __init__(
        self,
        timeout_seconds: float = 12,
        max_response_bytes: int = 1_000_000,
        max_redirects: int = 3,
        transport: httpx.BaseTransport | None = None,
    ):
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.max_redirects = max_redirects
        self.transport = transport

    def _fetch(self, target: str) -> tuple[str, httpx.Response, str]:
        current = target
        with httpx.Client(
            timeout=httpx.Timeout(self.timeout_seconds),
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
            follow_redirects=False,
            headers={"User-Agent": self.user_agent, "Accept": "text/html,application/xhtml+xml"},
            trust_env=False,
            transport=self.transport,
        ) as client:
            for _ in range(self.max_redirects + 1):
                parsed = urlparse(current)
                assert parsed.hostname
                assert_public_host(parsed.hostname)
                with client.stream("GET", current) as response:
                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            raise ValueError("Target returned a redirect without a Location header.")
                        current = validate_target_url(urljoin(str(response.url), location))
                        continue
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in response.iter_bytes():
                        total += len(chunk)
                        if total > self.max_response_bytes:
                            raise ValueError("Target response exceeded the 1 MB scan safety limit.")
                        chunks.append(chunk)
                    body = b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
                    return current, response, body
            raise ValueError(f"Target exceeded the redirect limit of {self.max_redirects}.")

    def scan(self, url: str, on_stage: Callable[[str], None] | None = None) -> ScanResult:
        """Assess one URL and optionally report completed stages to a job runner."""
        started = perf_counter()
        target = validate_target_url(url)
        self._report_stage(on_stage, "fetching_target")
        final_url, response, body = self._fetch(target)
        is_https = urlparse(final_url).scheme == "https"
        findings = analyze_headers(response.headers, is_https)
        self._report_stage(on_stage, "headers_analyzed")
        tls_info, tls_findings = inspect_tls(final_url, self.timeout_seconds)
        findings.extend(tls_findings)
        self._report_stage(on_stage, "tls_analyzed")
        if response.status_code >= 400:
            findings.append(Finding(name="HTTP response", category="Other Findings", status=FindingStatus.warning, severity=Severity.low,
                explanation="The target returned an HTTP error response; header analysis still reflects the response received.", evidence=f"HTTP {response.status_code}.", remediation="Review availability and ensure security headers are also applied to error responses."))
        cms = detect_cms(body, dict(response.headers))
        findings.append(Finding(name="CMS detection", category="CMS Detection", status=FindingStatus.info, severity=Severity.info,
            explanation=f"{cms.name} detected passively." if cms.name else "No supported CMS was detected passively.", evidence=cms.evidence or "No evidence.", confidence=cms.confidence))
        self._report_stage(on_stage, "cms_analyzed")
        score, grade = calculate_score(findings)
        self._report_stage(on_stage, "score_calculated")
        return ScanResult(target_url=final_url, score=score, grade=grade, findings=findings, tls=tls_info, cms=cms,
            http_status=response.status_code, duration_ms=round((perf_counter() - started) * 1000))

    @staticmethod
    def _report_stage(callback: Callable[[str], None] | None, stage: str) -> None:
        if callback:
            callback(stage)
