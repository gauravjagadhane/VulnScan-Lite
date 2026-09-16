# Architecture

VulnScan Lite separates request handling from outbound scanner work.

```text
React client -> FastAPI -> PostgreSQL
                  |
                  +-> Celery -> Redis -> ScannerEngine
```

`POST /api/scan` validates the requested URL, creates a `Scan` row, and queues a Celery task. The worker owns the network activity and updates the same row as each scanner stage completes. The client polls the status endpoint every two seconds while the scan is active.

The scanner lives in `backend/app/scanner` and has no dependency on FastAPI, database models, or Celery. This keeps the passive checks testable in isolation.

## Persistence

SQLAlchemy creates the current schema at application startup. This is appropriate for the small local-development scope of the project, but it is not a substitute for managed migrations in a multi-environment deployment. Alembic was deliberately not introduced during the final stabilization pass to avoid an untested schema-management change.

## Operational boundaries

The API service handles authentication, authorization, history, and report retrieval. Only the worker makes outbound target connections. Redis carries task messages; PostgreSQL persists the scan record and final structured result.

## Hosted deployment

The included `render.yaml` defines a FastAPI web service, Celery worker, Render PostgreSQL database, and Render Key Value instance. The web service and worker use private datastore connection strings. The React application is deployed independently from `frontend/` to Vercel and calls the API URL embedded in `VITE_API_URL` at build time.
