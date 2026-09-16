from datetime import datetime, timedelta, timezone
import ssl

from app.scanner.models import FindingStatus
from app.scanner import tls as tls_module
from app.scanner.tls import (
    certificate_expiration_finding,
    certificate_verification_failure,
    negotiated_tls_findings,
)


class _ContextManager:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self.value

    def __exit__(self, *args):
        return False


class _VerifiedConnection:
    def getpeercert(self):
        return {
            "notAfter": "Dec 31 23:59:59 2030 GMT",
            "issuer": ((('commonName', 'Test issuer'),),),
            "subject": ((('commonName', 'example.com'),),),
        }

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def version(self):
        return "TLSv1.3"


class _VerifiedContext:
    def wrap_socket(self, raw_socket, server_hostname):
        return _ContextManager(_VerifiedConnection())


def test_expiring_certificate_is_reported_as_warning():
    finding = certificate_expiration_finding(datetime.now(timezone.utc) + timedelta(days=14))
    assert (finding.status, finding.score_impact) == (FindingStatus.warning, -5)


def test_expired_certificate_verification_error_is_distinguished():
    finding = certificate_verification_failure(10, "certificate has expired")
    assert finding.name == "Certificate expiration"
    assert finding.score_impact == -25


def test_hostname_mismatch_verification_error_is_distinguished():
    finding = certificate_verification_failure(62, "Hostname mismatch, certificate is not valid for example.com")
    assert finding.name == "Certificate hostname"
    assert finding.status == FindingStatus.failed


def test_weak_negotiated_tls_is_penalized():
    findings = negotiated_tls_findings("TLSv1", ("AES128-SHA", "TLSv1", 128))
    assert {finding.name: finding.score_impact for finding in findings} == {"TLS protocol": -20, "TLS cipher": 0}


def test_verified_handshake_exposes_certificate_metadata(monkeypatch):
    monkeypatch.setattr(tls_module.ssl, "create_default_context", lambda: _VerifiedContext())
    monkeypatch.setattr(tls_module.socket, "create_connection", lambda *args, **kwargs: _ContextManager(object()))

    info, findings = tls_module.inspect_tls("https://example.com", timeout=1)

    assert info.hostname_verified is True
    assert info.protocol == "TLSv1.3"
    assert [finding.name for finding in findings] == ["Certificate validation", "Certificate expiration", "TLS protocol", "TLS cipher"]


def test_mocked_expired_certificate_verification_is_not_a_generic_tls_failure(monkeypatch):
    error = ssl.SSLCertVerificationError(1, "certificate has expired")
    error.verify_code = 10

    class FailingContext:
        def wrap_socket(self, raw_socket, server_hostname):
            raise error

    monkeypatch.setattr(tls_module.ssl, "create_default_context", lambda: FailingContext())
    monkeypatch.setattr(tls_module.socket, "create_connection", lambda *args, **kwargs: _ContextManager(object()))

    info, findings = tls_module.inspect_tls("https://example.com", timeout=1)

    assert info.hostname_verified is False
    assert findings[0].name == "Certificate expiration"
