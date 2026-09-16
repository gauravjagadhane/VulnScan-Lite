"""Passive CMS fingerprinting with explicitly bounded confidence."""
import re

from bs4 import BeautifulSoup

from .models import CMSInfo, Confidence

_GENERATOR_PATTERNS = {
    "WordPress": re.compile(r"^wordpress(?:\s+([0-9][\w.-]*))?", re.IGNORECASE),
    "Drupal": re.compile(r"^drupal(?:\s+([0-9][\w.-]*))?", re.IGNORECASE),
    "Joomla": re.compile(r"^joomla!?\s*([0-9][\w.-]+)?", re.IGNORECASE),
}

_HTML_MARKERS = {
    "WordPress": ("/wp-content/", "/wp-includes/"),
    "Drupal": ("/sites/default/files/", "/core/misc/drupal", "drupalsettings"),
    "Joomla": ("/media/system/", "/components/com_", "/modules/mod_"),
}


def _generator_detection(generator: str) -> CMSInfo | None:
    for name, pattern in _GENERATOR_PATTERNS.items():
        match = pattern.match(generator.strip())
        if match:
            return CMSInfo(
                name=name,
                version=match.group(1),
                confidence=Confidence.high,
                evidence="Detected from the generator meta tag.",
            )
    return None


def _marker_detection(html: str) -> CMSInfo | None:
    observed = html[:100_000].lower()
    for name, markers in _HTML_MARKERS.items():
        matched = [marker for marker in markers if marker in observed]
        if matched:
            return CMSInfo(
                name=name,
                confidence=Confidence.medium,
                evidence=f"Detected from public response markers: {', '.join(matched[:2])}.",
            )
    return None


def _powered_by_detection(powered_by: str) -> CMSInfo | None:
    for name, pattern in _GENERATOR_PATTERNS.items():
        if pattern.fullmatch(powered_by.strip()):
            return CMSInfo(
                name=name,
                confidence=Confidence.medium,
                evidence="Detected from the X-Powered-By response header.",
            )
    return None


def detect_cms(html: str, headers: dict[str, str]) -> CMSInfo:
    """Detect supported CMSs only from generator metadata or stable public paths.

    Generic product names in page copy are deliberately ignored to avoid presenting
    a marketing sentence or article reference as a CMS identification.
    """
    soup = BeautifulSoup(html, "html.parser")
    generator_tag = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.IGNORECASE)})
    generator = generator_tag.get("content", "") if generator_tag else ""
    detection = _generator_detection(generator)
    if detection:
        return detection

    normalized_headers = {key.lower(): value for key, value in headers.items()}
    detection = _powered_by_detection(normalized_headers.get("x-powered-by", ""))
    if detection:
        return detection

    detection = _marker_detection(html)
    if detection:
        return detection
    return CMSInfo(evidence="No supported CMS fingerprint was observed.")
