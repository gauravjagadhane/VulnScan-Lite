from fastapi.testclient import TestClient
from uuid import uuid4
from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.security import create_access_token


def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_scan_creation_queues_a_safe_target(monkeypatch):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    user = User(email=f"test-api-{uuid4()}@example.com", password_hash="not-used")
    db.add(user)
    db.commit()
    db.refresh(user)
    monkeypatch.setattr("app.api.scan.validate_target_url", lambda value: "https://example.com")
    queued: list[str] = []
    monkeypatch.setattr("app.api.scan.run_scan.delay", lambda scan_id: queued.append(scan_id))
    with TestClient(app) as client:
        response = client.post("/api/scan", json={"target_url": "https://example.com"}, headers={"Authorization": f"Bearer {create_access_token(user.id)}"})
    db.close()
    assert response.status_code == 202
    assert response.json()["status"] == "queued"
    assert queued == [response.json()["scan_id"]]


def test_scan_creation_rejects_an_unsafe_url(monkeypatch):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    user = User(email=f"unsafe-target-{uuid4()}@example.com", password_hash="not-used")
    db.add(user)
    db.commit()
    db.refresh(user)

    with TestClient(app) as client:
        response = client.post(
            "/api/scan",
            json={"target_url": "http://localhost"},
            headers={"Authorization": f"Bearer {create_access_token(user.id)}"},
        )
    db.close()

    assert response.status_code == 400
    assert response.json()["detail"] == "Internal hostnames are not allowed."


def test_scan_status_is_limited_to_the_owner():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    owner = User(email=f"owner-{uuid4()}@example.com", password_hash="not-used")
    other_user = User(email=f"other-{uuid4()}@example.com", password_hash="not-used")
    db.add_all([owner, other_user])
    db.commit()
    db.refresh(owner)
    db.refresh(other_user)
    scan = Scan(user_id=owner.id, target_url="https://example.com", status=ScanStatus.running, progress=40)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    with TestClient(app) as client:
        own_response = client.get(f"/api/scan/{scan.id}/status", headers={"Authorization": f"Bearer {create_access_token(owner.id)}"})
        other_response = client.get(f"/api/scan/{scan.id}/status", headers={"Authorization": f"Bearer {create_access_token(other_user.id)}"})
    db.close()

    assert own_response.status_code == 200
    assert own_response.json()["progress"] == 40
    assert other_response.status_code == 404
