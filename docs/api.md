# API reference

FastAPI publishes the complete OpenAPI schema and interactive documentation at `/docs`. All routes below are rooted at the backend URL.

| Method | Path | Authentication | Result |
| --- | --- | --- | --- |
| POST | `/api/auth/register` | No | Creates an account and returns a bearer token. |
| POST | `/api/auth/login` | No | Returns a bearer token for valid credentials. |
| POST | `/api/scan` | Bearer token | Validates and queues a passive scan; returns `202` with scan ID. |
| GET | `/api/scan/{id}/status` | Owner token | Returns `queued`, `running`, `completed`, or `failed` and persisted progress. |
| GET | `/api/scan/{id}` | Owner token | Returns the structured result when available. |
| GET | `/api/scan/{id}/pdf` | Owner token | Downloads a completed PDF report. |
| GET | `/api/history` | Bearer token | Returns the caller's most recent 100 scans. |
| GET | `/health` | No | Returns service health. |

Invalid URLs return `400`. Missing or invalid bearer tokens return `401`; resources outside the caller's ownership return `404` to avoid revealing their existence. Rate limits return `429`. Unexpected failures are logged server-side and are not returned with a stack trace.
