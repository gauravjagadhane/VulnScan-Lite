# Security controls and assumptions

## Outbound scan safety

Only absolute `http` and `https` URLs are accepted. URLs with embedded credentials, internal hostnames, malformed ports, or non-public DNS answers are rejected. The scanner checks each redirect destination before following it, limits redirects to three, disables environment proxy configuration with `trust_env=False`, applies a timeout, and limits each response body to 1 MB.

The application is not an HTTP proxy. It does not expose arbitrary request methods, headers, body forwarding, or target response streaming.

DNS is resolved and checked before each outbound request. A time-of-check/time-of-use DNS rebinding guarantee cannot be made solely in this application because the underlying client resolves hostnames when connecting. Production workers should run with egress controls that deny private and metadata address ranges; this is a required deployment defense in addition to the application checks.

## API protection

The scan endpoint is rate-limited by source IP, per-user hourly scan counts, and system-wide active scan capacity. Scan reports, status, PDFs, and history are scoped to the authenticated owner. Passwords are stored as bcrypt hashes and bearer tokens are signed with `SECRET_KEY`.

The rate limiter uses the current application process's limiter storage. It is appropriate for local development and a single API process, but a horizontally scaled deployment needs shared rate-limit storage and a distributed scan-capacity lock.

API responses use a narrow CORS allowlist from `CORS_ORIGINS` and set browser-facing response headers including `X-Content-Type-Options`, `X-Frame-Options`, CSP, Referrer-Policy, and `Cache-Control: no-store`.

## Secrets and logging

Secrets are loaded from environment variables. `.env` is ignored by Git and `.env.example` contains placeholders only. Production startup rejects the development default JWT secret.

The frontend keeps its bearer token in `localStorage` for this small single-page application. A production deployment should consider an HttpOnly cookie/session design with CSRF protections appropriate to its authentication model.

Worker and API logs are JSON records with scan IDs, hostname, stage, duration, and score where relevant. Passwords, authorization headers, tokens, database URLs, and secret values are not logged.

## Hosted deployment controls

For a hosted deployment, set `ENVIRONMENT=production`, keep the generated `SECRET_KEY` private, and set `CORS_ORIGINS` to the exact HTTPS Vercel production origin. Render's Key Value instance is configured without public IP access; the API and worker consume its private connection string. Keep database and queue credentials in Render-managed environment variables rather than Vercel or repository files.
