"""SSRF guardrails for every outbound scanner connection.

Only public HTTP(S) destinations are allowed. DNS is resolved before every request
(including redirects), and all returned addresses must be globally routable.
"""
import ipaddress
import socket
from urllib.parse import urlparse


class UnsafeTargetError(ValueError):
    """Raised when a target could direct the scanner into a private network."""


def validate_target_url(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeTargetError("Enter an absolute http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise UnsafeTargetError("URLs with credentials are not allowed.")
    try:
        port = parsed.port
    except ValueError as error:
        raise UnsafeTargetError("The URL port is invalid.") from error
    if port and not 1 <= port <= 65535:
        raise UnsafeTargetError("The URL port is invalid.")
    assert_public_host(parsed.hostname)
    return parsed.geturl()


def assert_public_host(hostname: str) -> list[str]:
    lowered = hostname.rstrip(".").lower()
    if lowered in {"localhost", "localhost.localdomain"} or ".local" in lowered or ".internal" in lowered:
        raise UnsafeTargetError("Internal hostnames are not allowed.")
    try:
        addresses = {entry[4][0] for entry in socket.getaddrinfo(lowered, None, type=socket.SOCK_STREAM)}
    except socket.gaierror as error:
        raise UnsafeTargetError("The hostname could not be resolved.") from error
    if not addresses:
        raise UnsafeTargetError("The hostname did not resolve to an address.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        # is_global deliberately also blocks loopback, private, link-local, multicast and documentation ranges.
        if not ip.is_global:
            raise UnsafeTargetError("Targets resolving to non-public IP addresses are not allowed.")
    return sorted(addresses)
