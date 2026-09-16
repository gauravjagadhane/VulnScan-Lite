import httpx
import pytest

from app.scanner import engine as engine_module
from app.scanner.engine import ScannerEngine
from app.scanner.models import TLSInfo
from app.scanner.safety import UnsafeTargetError


def test_redirect_to_private_address_is_blocked(monkeypatch):
    def validate_redirect(url: str) -> str:
        if "localhost" in url:
            raise UnsafeTargetError("Internal hostnames are not allowed.")
        return url

    monkeypatch.setattr(engine_module, "validate_target_url", validate_redirect)
    monkeypatch.setattr(engine_module, "assert_public_host", lambda hostname: ["93.184.216.34"])
    transport = httpx.MockTransport(lambda request: httpx.Response(302, headers={"Location": "http://localhost/admin"}))
    scanner = ScannerEngine(transport=transport)

    with pytest.raises(UnsafeTargetError):
        scanner._fetch("https://example.com")


def test_scan_progress_callbacks_follow_completed_scanner_stages(monkeypatch):
    response = httpx.Response(200, headers={"Content-Security-Policy": "default-src 'self'"})
    monkeypatch.setattr(engine_module, "validate_target_url", lambda url: url)
    monkeypatch.setattr(ScannerEngine, "_fetch", lambda self, target: (target, response, "<html></html>"))
    monkeypatch.setattr(engine_module, "inspect_tls", lambda url, timeout: (TLSInfo(available=False), []))
    stages: list[str] = []

    ScannerEngine().scan("https://example.com", on_stage=stages.append)

    assert stages == ["fetching_target", "headers_analyzed", "tls_analyzed", "cms_analyzed", "score_calculated"]


def test_redirect_limit_blocks_an_excessive_redirect_chain(monkeypatch):
    monkeypatch.setattr(engine_module, "validate_target_url", lambda url: url)
    monkeypatch.setattr(engine_module, "assert_public_host", lambda hostname: ["93.184.216.34"])
    transport = httpx.MockTransport(lambda request: httpx.Response(302, headers={"Location": "https://example.com/next"}))
    scanner = ScannerEngine(max_redirects=1, transport=transport)

    with pytest.raises(ValueError, match="redirect limit"):
        scanner._fetch("https://example.com")
