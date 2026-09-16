import socket
import pytest
from app.scanner.safety import UnsafeTargetError, assert_public_host, validate_target_url


def test_only_http_schemes_are_allowed():
    with pytest.raises(UnsafeTargetError):
        validate_target_url("file:///etc/passwd")


def test_localhost_is_rejected_before_dns():
    with pytest.raises(UnsafeTargetError):
        validate_target_url("http://localhost:8080")


@pytest.mark.parametrize("target", ["http://127.0.0.1", "http://[::1]", "http://[fc00::1]", "http://[fe80::1]"])
def test_non_public_ip_literals_are_rejected(target):
    with pytest.raises(UnsafeTargetError):
        validate_target_url(target)


def test_malformed_port_is_a_friendly_validation_error():
    with pytest.raises(UnsafeTargetError):
        validate_target_url("https://example.com:not-a-port")


def test_urls_with_embedded_credentials_are_rejected():
    with pytest.raises(UnsafeTargetError):
        validate_target_url("https://username:password@example.com")


def test_private_resolutions_are_rejected(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, ("10.0.0.4", 0))])
    with pytest.raises(UnsafeTargetError):
        assert_public_host("example.org")
