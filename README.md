# VulnScan Lite

VulnScan Lite is a passive web security scanner that checks HTTP security headers, TLS configuration, and basic CMS fingerprints. An authorized user submits a public `http` or `https` URL and receives an asynchronous report.

> Only scan websites you own or have permission to assess. This tool performs passive analysis only.

This is a passive security assessment tool, not a full penetration-testing platform. It deliberately does not send exploit payloads, brute-force paths or credentials, scan ports, or attempt authentication bypasses.

## Features

- FastAPI API with built-in Swagger documentation at `/docs`
- Authenticated registration/login with bcrypt password hashes and signed bearer tokens
- Dedicated Celery worker backed by Redis: request handlers never run target scans
- PostgreSQL scan history, ownership checks, timestamps, and score trends
- A React/Vite dashboard with progress, responsive result cards, and history chart
- Print-friendly ReportLab PDF reports
- Clear, deterministic 0-100 **VulnScan Lite Passive Security Score** and A-F grade
- Pinned dependencies, Docker Compose development stack, and meaningful pytest coverage

## Architecture

```text
React dashboard ── authenticated REST ──> FastAPI ──> PostgreSQL
                                         │
                                         └── Celery / Redis ──> passive scanner
                                                                  ├─ bounded HTTP GET
                                                                  ├─ response headers
                                                                  ├─ verified TLS handshake
                                                                  └─ CMS fingerprints
```

The scanner is intentionally separate from HTTP routes in `backend/app/scanner`, so it can be independently tested and later extended without coupling it to FastAPI or Celery.

Further engineering documentation: [architecture](docs/architecture.md), [scanner methodology](docs/scanner-methodology.md), [security controls](docs/security.md), and [API reference](docs/api.md).

## Technology stack

| Area | Choice |
| --- | --- |
| API/data | Python 3.12+, FastAPI, Pydantic, SQLAlchemy, PostgreSQL |
| Worker | Celery and Redis |
| Scanner | httpx, BeautifulSoup4, Python `ssl` and `socket` |
| UI | React, Vite, Recharts, modern CSS |
| Reports | ReportLab |
| Tests | pytest / FastAPI TestClient |

## Run with Docker (recommended)

1. Copy the environment template: `Copy-Item .env.example .env` on PowerShell (or `cp .env.example .env` on Unix).
2. Replace `SECRET_KEY` with a long random value before any non-local deployment.
3. Start all services: `docker compose up --build`.
4. Open the dashboard at `http://localhost:5173`, API docs at `http://localhost:8000/docs`, and health check at `http://localhost:8000/health`.

Docker starts five containers: `frontend`, `backend`, `worker`, `redis`, and `postgres`.

## Vercel and Render deployment

The repository includes [render.yaml](render.yaml) for a Render FastAPI web service, Celery worker, PostgreSQL database, and Key Value queue. It does not deploy the frontend; deploy `frontend/` as a separate Vercel project.

1. Push this repository to a private or public Git provider repository. Do not include `.env`, local databases, caches, or build output.
2. In Render, create a Blueprint from the repository. Render creates the API, worker, PostgreSQL, and Key Value resources from `render.yaml`.
3. In the Render API service, set `CORS_ORIGINS` to the exact Vercel production URL after it is known, for example `https://your-project.vercel.app`. Render generates `SECRET_KEY`; do not replace it with a committed value.
4. In Vercel, import the same repository with `frontend` as the Root Directory. Set `VITE_API_URL` to the Render API's public HTTPS URL, without a trailing slash, and deploy.
5. Update Render's `CORS_ORIGINS` if the Vercel production domain changes, then redeploy the API. `VITE_API_URL` is a build-time public value, so redeploy Vercel after changing it.

The worker should remain private. The browser communicates only with the Vercel frontend and public Render API; PostgreSQL and Key Value are reached on Render's private network.

## Local development

Requires Python 3.12+, Node 22+, PostgreSQL, and Redis.

```powershell
Copy-Item .env.example .env
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```

In a second terminal:

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
celery -A app.celery_app.celery_app worker --loglevel=INFO
```

And in a third:

```powershell
cd frontend
npm.cmd ci
npm.cmd run dev
```

For standalone API test development, the default configuration falls back to a local SQLite file. Use PostgreSQL and Redis for the complete asynchronous environment.

## API

All scan and history routes require `Authorization: Bearer <token>`.

| Method | Route | Description |
| --- | --- | --- |
| POST | `/api/auth/register` | Creates an account (password: 12+ characters) and returns a token |
| POST | `/api/auth/login` | Returns a token |
| POST | `/api/scan` | Validates then queues a passive assessment; returns `{scan_id,status}` |
| GET | `/api/scan/{id}/status` | Returns queued/running/completed/failed state and progress |
| GET | `/api/scan/{id}` | Returns the completed structured report |
| GET | `/api/scan/{id}/pdf` | Downloads an authenticated PDF report |
| GET | `/api/history` | Returns the current user's last 100 scans |
| GET | `/health` | Lightweight service health response |

Swagger/OpenAPI provides request and response schemas at `/docs`.

## Scanner methodology

The scanner performs one normal `GET` request per redirect hop and one verified TLS handshake for an HTTPS target. Response content is capped at 1 MB and only used for documented, passive fingerprints.

### Header policy

Required baseline checks are `Content-Security-Policy`, `X-Frame-Options`, and `Strict-Transport-Security` (when HTTPS applies). A missing baseline header costs 10 points. `X-Frame-Options` must be `DENY` or `SAMEORIGIN`; HSTS must include `max-age`. CSP is currently checked for presence rather than every directive. Bonus observations are `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`; they offer remediation but no score penalty.

### TLS policy

Python's default verified SSL context checks the certificate chain and hostname. The scanner records protocol, negotiated cipher, subject/issuer, and expiration only after a verified handshake. It separately reports expired certificates, hostname mismatches, and certificate-chain failures when the TLS runtime provides that reason. Baseline protocol is TLS 1.2+ and cipher strength is 128+ effective bits from the negotiated cipher metadata - not a fragile cipher-name substring check. A failed verified TLS connection costs 25, HTTP-only availability 15, legacy protocol 20, a sub-baseline cipher 15, expired certificate 25, and a certificate expiring within 30 days 5.

### CMS policy

WordPress, Drupal, and Joomla are detected from `meta[name=generator]`, exact CMS values in `X-Powered-By`, and stable public asset/path markers. A CMS name in ordinary page text is not sufficient evidence. Generator metadata earns high confidence; header and path markers earn medium confidence. Versions are reported only when generator metadata includes one. CMS presence by itself has no penalty.

### Progress and polling

The worker persists progress only after real stages complete: startup (5), target fetch (20), header analysis (40), TLS inspection (60), CMS detection (80), score calculation (95), and completion (100). The dashboard makes one status request approximately every two seconds for an active scan and stops its timer on completion, failure, or component unmount.

### Scoring

The score begins at 100, sums documented finding penalties, and is clamped to 0-100. Grades: A 90-100, B 80-89, C 70-79, D 60-69, and F 0-59. This score describes this limited passive assessment only; it is not a vulnerability count or a penetration-test result.

## SSRF and abuse controls

The application does not act as an unrestricted proxy.

- Permits only absolute HTTP(S) URLs, with no embedded credentials.
- Rejects localhost/internal names and DNS answers that are not globally routable (loopback, private, link-local, multicast, and reserved addresses).
- Re-validates the destination before every outbound request, including manual redirects. Redirects are capped at 3.
- Uses `trust_env=False`, a fixed descriptive User-Agent, 12-second timeout, and 1 MB response limit by default.
- Limits `POST /api/scan` to 5 requests per minute per IP, 10 scans per hour per user, and 3 system-wide queued/running scans by default.
- Enforces ownership on report, status, PDF, and history access.

The built-in guard reduces SSRF risk but cannot eliminate DNS rebinding risk by itself because the HTTP/TLS clients resolve hostnames when connecting. Production workers must use egress firewall rules that deny private and metadata address ranges.

## Security review notes

- Secrets are configuration-only; `.env` is ignored. Use a random production `SECRET_KEY`, TLS termination, secure cookie/session policy if auth evolves, and secret management in deployment.
- API errors intentionally return friendly messages while worker logs retain diagnostic exception information.
- CORS is an explicit allow list from `CORS_ORIGINS`.
- Bearer tokens are stored in browser `localStorage` for this portfolio SPA. A production deployment should evaluate an HttpOnly cookie/session model and CSRF controls.
- The backend should sit behind a reverse proxy that sets its own browser-facing security headers and HTTPS policy.
- Run dependency scanning (`pip-audit`, `npm audit`) in CI before production deployment.

## Testing

```powershell
cd backend
python -m pytest -q
```

The test suite validates header policy, scoring boundaries, CMS confidence/version handling and false-positive prevention, SSRF validation and redirect revalidation, TLS decisions with mocked SSL/socket behavior, PDF generation, ownership protection, scan status, and async API scan creation. It does not contact arbitrary external websites.

Frontend build verification:

```powershell
cd frontend
npm.cmd ci
npm.cmd run build
```

The frontend has no browser-test harness. Manually verify polling by starting the Docker stack, submitting an authorized URL, and confirming that the browser issues one status request about every two seconds until the scan reaches `completed` or `failed`; navigating away from the dashboard should stop further requests.

## Important environment variables

`DATABASE_URL`, `REDIS_URL`, `SECRET_KEY`, `CORS_ORIGINS`, `REQUEST_TIMEOUT_SECONDS`, `MAX_RESPONSE_BYTES`, `MAX_REDIRECTS`, `MAX_CONCURRENT_SCANS`, and `SCANS_PER_HOUR` are defined in `.env.example`.

For Render, `DATABASE_URL` and `REDIS_URL` are wired from managed services by `render.yaml`; do not enter them in Vercel. `VITE_API_URL` belongs only in Vercel because all Vite variables prefixed with `VITE_` are embedded in the browser build and must not contain secrets.

## Limitations and next improvements

- Only three CMS families and conservative public fingerprints are supported.
- TLS inspection evaluates the negotiated default handshake, not every server-supported cipher suite.
- The in-process rate limiter and active-scan capacity check are not distributed across multiple API instances.
- The current authentication flow is suitable for a portfolio/local project; production should add email verification, password reset, revocation, audit events, and stronger distributed rate limiting.
- Schema creation currently occurs at application startup; add a tested migration workflow before a multi-environment deployment. Other production improvements include a Redis-backed distributed concurrency lock, CSP parsing depth, signed report URLs, OpenTelemetry, and CI/CD with container/dependency scanning.

## License

MIT - see `LICENSE`.
