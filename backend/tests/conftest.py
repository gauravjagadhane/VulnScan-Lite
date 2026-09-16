import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["DATABASE_URL"] = "sqlite:///./test_vulnscan.db"

import pytest

from app.database import Base, engine


@pytest.fixture(autouse=True)
def reset_database():
    """Keep API tests independent of scans created by an earlier test run."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
