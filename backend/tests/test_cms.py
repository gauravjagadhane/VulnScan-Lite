from app.scanner.cms import detect_cms
from fixtures import (
    CMS_FALSE_POSITIVE_HTML,
    DRUPAL_GENERATOR_HTML,
    JOOMLA_GENERATOR_HTML,
    WORDPRESS_GENERATOR_HTML,
)


def test_generator_evidence_is_high_confidence():
    result = detect_cms(WORDPRESS_GENERATOR_HTML, {})
    assert result.name == "WordPress"
    assert result.version == "6.6"
    assert result.confidence.value == "high"


def test_drupal_generator_is_detected_with_version():
    result = detect_cms(DRUPAL_GENERATOR_HTML, {})
    assert (result.name, result.version, result.confidence.value) == ("Drupal", "10.3", "high")


def test_joomla_generator_is_detected_with_version():
    result = detect_cms(JOOMLA_GENERATOR_HTML, {})
    assert (result.name, result.version, result.confidence.value) == ("Joomla", "5.2", "high")


def test_arbitrary_wordpress_text_is_not_a_cms_fingerprint():
    result = detect_cms(CMS_FALSE_POSITIVE_HTML, {})
    assert result.name is None
    assert result.confidence.value == "low"


def test_exact_powered_by_header_is_medium_confidence_evidence():
    result = detect_cms("<html></html>", {"X-Powered-By": "Drupal"})
    assert (result.name, result.version, result.confidence.value) == ("Drupal", None, "medium")


def test_no_cms_does_not_guess():
    result = detect_cms("<html><title>Plain site</title></html>", {})
    assert result.name is None
    assert result.version is None
