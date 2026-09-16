"""Controlled response samples used by scanner behavior tests."""

SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
}

MISSING_SECURITY_HEADERS: dict[str, str] = {}

WORDPRESS_GENERATOR_HTML = '<html><meta name="generator" content="WordPress 6.6"></html>'
DRUPAL_GENERATOR_HTML = '<html><meta name="generator" content="Drupal 10.3"></html>'
JOOMLA_GENERATOR_HTML = '<html><meta name="generator" content="Joomla! 5.2"></html>'
CMS_FALSE_POSITIVE_HTML = '<html><p>We migrated away from WordPress last year.</p></html>'
