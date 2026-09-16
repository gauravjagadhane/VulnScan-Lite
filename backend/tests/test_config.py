import pytest

from app.config import Settings, normalize_database_url


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("postgres://user:password@db.internal/app", "postgresql+psycopg://user:password@db.internal/app"),
        ("postgresql://user:password@db.internal/app", "postgresql+psycopg://user:password@db.internal/app"),
        ("sqlite:///./local.db", "sqlite:///./local.db"),
    ],
)
def test_normalizes_provider_database_urls(source, expected):
    assert normalize_database_url(source) == expected


def test_production_requires_a_non_default_secret_and_postgresql():
    settings = Settings(environment="production", secret_key="development-only-change-me", database_url="sqlite:///./local.db", cors_origins="https://app.example.com")
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        settings.validate_production_configuration()


def test_production_configuration_accepts_render_database_url():
    settings = Settings(environment="production", secret_key="x" * 32, database_url="postgresql://user:password@db.internal/app", cors_origins="https://app.example.com")
    settings.validate_production_configuration()
    assert settings.database_url.startswith("postgresql+psycopg://")
