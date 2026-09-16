"""TLS inspection using a verified stdlib SSL handshake, never active probing."""
from __future__ import annotations

from datetime import datetime, timezone
import socket
import ssl
from urllib.parse import urlparse

from .models import Finding, FindingStatus, Severity, TLSInfo

_EXPIRED_CERTIFICATE_VERIFY_CODE = 10
_SUPPORTED_PROTOCOLS = {"TLSv1.2", "TLSv1.3"}


def _name(parts: tuple[tuple[tuple[str, str], ...], ...]) -> str | None:
    values = [f"{key}={value}" for group in parts for key, value in group]
    return ", ".join(values) or None


def certificate_expiration_finding(expires_at: datetime) -> Finding:
    """Evaluate an expiration date only after a certificate passed verification."""
    now = datetime.now(timezone.utc)
    if expires_at <= now:
        return Finding(
            name="Certificate expiration",
            category="TLS / HTTPS",
            status=FindingStatus.failed,
            severity=Severity.high,
            score_impact=-25,
            explanation="The certificate is expired.",
            evidence=f"Expired at {expires_at.isoformat()}.",
            remediation="Renew and deploy a valid certificate through the hosting provider or certificate authority.",
        )
    if (expires_at - now).days <= 30:
        return Finding(
            name="Certificate expiration",
            category="TLS / HTTPS",
            status=FindingStatus.warning,
            severity=Severity.medium,
            score_impact=-5,
            explanation="The certificate expires within 30 days.",
            evidence=f"Expires at {expires_at.isoformat()}.",
            remediation="Schedule certificate renewal before expiration.",
        )
    return Finding(
        name="Certificate expiration",
        category="TLS / HTTPS",
        status=FindingStatus.passed,
        severity=Severity.info,
        explanation="The certificate is currently valid for more than 30 days.",
        evidence=f"Expires at {expires_at.isoformat()}.",
    )


def negotiated_tls_findings(protocol: str | None, cipher: tuple[str, str, int] | None) -> list[Finding]:
    """Evaluate the single, verified protocol and cipher negotiated by the server."""
    findings: list[Finding] = []
    if protocol not in _SUPPORTED_PROTOCOLS:
        findings.append(
            Finding(
                name="TLS protocol",
                category="TLS / HTTPS",
                status=FindingStatus.failed,
                severity=Severity.high,
                score_impact=-20,
                explanation="The negotiated protocol is below the scanner baseline of TLS 1.2.",
                evidence=f"Negotiated protocol: {protocol or 'not reported'}.",
                remediation="Disable legacy TLS protocols and enable TLS 1.2 and TLS 1.3.",
            )
        )
    else:
        findings.append(
            Finding(
                name="TLS protocol",
                category="TLS / HTTPS",
                status=FindingStatus.passed,
                severity=Severity.info,
                explanation="The negotiated TLS protocol meets the TLS 1.2+ baseline.",
                evidence=f"Negotiated protocol: {protocol}.",
            )
        )

    bits = cipher[2] if cipher else 0
    if not cipher or bits < 128:
        findings.append(
            Finding(
                name="TLS cipher",
                category="TLS / HTTPS",
                status=FindingStatus.failed,
                severity=Severity.high,
                score_impact=-15,
                explanation="The negotiated cipher does not meet the 128-bit baseline.",
                evidence=f"Cipher: {cipher or 'not reported'}.",
                remediation="Use a current server TLS configuration with modern AEAD cipher suites.",
            )
        )
    else:
        findings.append(
            Finding(
                name="TLS cipher",
                category="TLS / HTTPS",
                status=FindingStatus.passed,
                severity=Severity.info,
                explanation="The negotiated cipher meets the scanner's 128-bit baseline.",
                evidence=f"Cipher: {cipher[0]} ({bits} bits).",
            )
        )
    return findings


def certificate_verification_failure(verify_code: int | None, message: str) -> Finding:
    """Convert a verified-handshake failure into a specific, non-sensitive finding."""
    evidence = f"Certificate verification failed: {message[:180]}"
    if verify_code == _EXPIRED_CERTIFICATE_VERIFY_CODE or "expired" in message.lower():
        return Finding(
            name="Certificate expiration",
            category="TLS / HTTPS",
            status=FindingStatus.failed,
            severity=Severity.high,
            score_impact=-25,
            explanation="The certificate could not be verified because it is expired.",
            evidence=evidence,
            remediation="Renew and deploy a valid certificate through the hosting provider or certificate authority.",
        )
    if "hostname mismatch" in message.lower():
        return Finding(
            name="Certificate hostname",
            category="TLS / HTTPS",
            status=FindingStatus.failed,
            severity=Severity.high,
            score_impact=-25,
            explanation="The certificate does not match the requested hostname.",
            evidence=evidence,
            remediation="Deploy a certificate whose subject alternative names include the public hostname.",
        )
    return Finding(
        name="Certificate validation",
        category="TLS / HTTPS",
        status=FindingStatus.failed,
        severity=Severity.high,
        score_impact=-25,
        explanation="The certificate chain could not be verified.",
        evidence=evidence,
        remediation="Check the certificate chain, intermediate certificates, and issuing certificate authority.",
    )


def inspect_tls(url: str, timeout: float) -> tuple[TLSInfo, list[Finding]]:
    """Connect once using strict hostname and certificate verification.

    Invalid certificates are not retried with verification disabled. When OpenSSL
    provides a verification reason, it is reported; certificate fields are only
    emitted after a successful verified handshake.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return TLSInfo(available=False), [
            Finding(
                name="HTTPS availability",
                category="TLS / HTTPS",
                status=FindingStatus.warning,
                severity=Severity.medium,
                score_impact=-15,
                explanation="The scanned URL uses HTTP, so a verified TLS connection was not available.",
                evidence="Target scheme is http.",
                remediation="Serve the application over HTTPS and redirect HTTP requests to HTTPS.",
            )
        ]

    try:
        context = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=parsed.hostname) as connection:
                certificate = connection.getpeercert()
                cipher = connection.cipher()
                protocol = connection.version()
    except ssl.SSLCertVerificationError as error:
        finding = certificate_verification_failure(getattr(error, "verify_code", None), str(error))
        return TLSInfo(available=False, hostname_verified=False), [finding]
    except (ssl.SSLError, OSError, ValueError) as error:
        return TLSInfo(available=False, hostname_verified=False), [
            Finding(
                name="TLS connection",
                category="TLS / HTTPS",
                status=FindingStatus.failed,
                severity=Severity.high,
                score_impact=-25,
                explanation="A verified TLS connection could not be established.",
                evidence=f"{type(error).__name__}: {str(error)[:180]}",
                remediation="Check the certificate chain, hostname coverage, supported TLS versions, and network reachability.",
            )
        ]

    try:
        expires_at = datetime.strptime(certificate["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except (KeyError, TypeError, ValueError):
        return TLSInfo(available=True, protocol=protocol, cipher=cipher[0] if cipher else None, hostname_verified=True), [
            Finding(
                name="Certificate metadata",
                category="TLS / HTTPS",
                status=FindingStatus.warning,
                severity=Severity.low,
                score_impact=0,
                explanation="The verified connection did not provide a parseable certificate expiration date.",
                evidence="The certificate validity window was unavailable from the TLS runtime.",
                remediation="Confirm that the server presents a standards-compliant X.509 certificate.",
            ),
            *negotiated_tls_findings(protocol, cipher),
        ]

    info = TLSInfo(
        available=True,
        protocol=protocol,
        cipher=cipher[0] if cipher else None,
        issuer=_name(certificate.get("issuer", ())),
        subject=_name(certificate.get("subject", ())),
        expires_at=expires_at,
        hostname_verified=True,
    )
    findings = [
        Finding(
            name="Certificate validation",
            category="TLS / HTTPS",
            status=FindingStatus.passed,
            severity=Severity.info,
            explanation="The certificate chain and hostname were accepted by Python's verified TLS context.",
            evidence=f"Certificate expires {expires_at.date().isoformat()}.",
        ),
        certificate_expiration_finding(expires_at),
        *negotiated_tls_findings(protocol, cipher),
    ]
    return info, findings
