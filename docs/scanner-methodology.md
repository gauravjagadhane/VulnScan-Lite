# Scanner methodology

VulnScan Lite performs one bounded HTTP `GET` per redirect hop and, for HTTPS targets, one verified TLS handshake. It does not send exploit payloads, attempt authentication, enumerate directories, scan ports, or modify target state.

## Headers

Required baseline checks are Content-Security-Policy, X-Frame-Options, and Strict-Transport-Security when HTTPS applies. Missing required headers reduce the passive security score by 10 points. X-Frame-Options must be `DENY` or `SAMEORIGIN`; HSTS must include `max-age`.

The scanner currently checks CSP presence rather than parsing every directive. A present CSP is reported as a baseline pass, not as proof that its source policy is complete or safe.

X-Content-Type-Options, Referrer-Policy, and Permissions-Policy are reported as bonus hardening checks and do not affect the score.

## TLS

The scanner uses Python's verified default SSL context. A certificate is accepted only when the certificate chain and hostname pass validation. For a verified connection, it reports certificate expiry, protocol, negotiated cipher, issuer, and subject. The baseline is TLS 1.2 or TLS 1.3 and a cipher with at least 128 effective bits.

When certificate validation fails, the scanner reports an expired certificate, hostname mismatch, or chain-validation failure if the TLS runtime exposes that reason. It does not retry an invalid certificate with verification disabled to collect metadata.

## CMS detection

WordPress, Drupal, and Joomla detection uses a generator meta tag first, then an exact CMS value in `X-Powered-By`, then stable public asset/path markers such as `/wp-content/`. A CMS name in visible page text is not sufficient evidence. Generator metadata is high confidence; header and path markers are medium confidence. Versions are shown only when generator metadata includes one.

## Score

The score starts at 100 and sums documented penalties from findings before being clamped to 0-100. Grades are A (90-100), B (80-89), C (70-79), D (60-69), and F (0-59). It is a limited passive posture indicator, not a penetration-test result.
