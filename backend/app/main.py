"""FastAPI application for VulnScan Lite."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi import _rate_limit_exceeded_handler
from .api import auth, history, reports, scan
from .config import get_settings
from .database import Base, engine
from .logging_utils import configure_logging

configure_logging()
settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.validate_production_configuration()
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="VulnScan Lite API", version="1.0.0", description="Authenticated, passive website security health assessments.", lifespan=lifespan)
app.state.limiter = scan.limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origin_list, allow_credentials=True, allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])
app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(history.router)
app.include_router(reports.router)


@app.middleware("http")
async def response_security_headers(request: Request, call_next):
    """Harden the API's own browser-facing responses without affecting scanner output."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Cache-Control"] = "no-store"
    if settings.environment == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "vulnscan-lite"}
