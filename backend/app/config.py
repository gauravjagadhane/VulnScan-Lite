"""Environment-driven application configuration; no deployment secrets live in code."""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


def normalize_database_url(value: str) -> str:
    """Adapt provider PostgreSQL URLs to SQLAlchemy's installed psycopg dialect."""
    url = value.strip()
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url.removeprefix("postgres://")
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql://")
    return url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    app_name: str = "VulnScan Lite"
    environment: str = "development"
    database_url: str = "sqlite:///./vulnscan.db"
    redis_url: str = "redis://redis:6379/0"
    secret_key: str = "development-only-change-me"
    access_token_minutes: int = 480
    cors_origins: str = "http://localhost:5173"
    max_response_bytes: int = 1_000_000
    request_timeout_seconds: float = 12.0
    max_redirects: int = 3
    max_concurrent_scans: int = 3
    scans_per_hour: int = 10

    def __init__(self, **values: object) -> None:
        super().__init__(**values)
        self.database_url = normalize_database_url(self.database_url)

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    def validate_production_configuration(self) -> None:
        """Fail fast when a deploy would start with development-only settings."""
        if self.environment.lower() != "production":
            return
        if self.secret_key == "development-only-change-me" or len(self.secret_key) < 32:
            raise RuntimeError("SECRET_KEY must be a non-default value of at least 32 characters in production.")
        if self.database_url.startswith("sqlite"):
            raise RuntimeError("DATABASE_URL must point to PostgreSQL in production.")
        if not self.cors_origin_list or any(not origin.startswith("https://") for origin in self.cors_origin_list):
            raise RuntimeError("CORS_ORIGINS must contain one or more HTTPS origins in production.")


@lru_cache
def get_settings() -> Settings:
    return Settings()
