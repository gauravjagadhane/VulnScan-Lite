"""Asynchronous scan creation and status/report retrieval endpoints."""
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session
from ..celery_app import celery_app
from ..config import get_settings
from ..database import get_db
from ..models.scan import Scan, ScanStatus
from ..models.user import User
from ..scanner.models import ScanResult
from ..scanner.safety import UnsafeTargetError, validate_target_url
from ..schemas.scan import ScanCreated, ScanReportResponse, ScanRequest, ScanStatusResponse
from ..security import get_current_user
from ..tasks.scan_tasks import run_scan

router = APIRouter(prefix="/api", tags=["scans"])
limiter = Limiter(key_func=get_remote_address)


def _owned_scan(scan_id: str, user: User, db: Session) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan or scan.user_id != user.id:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@router.post("/scan", response_model=ScanCreated, status_code=202)
@limiter.limit("5/minute")
def create_scan(request: Request, payload: ScanRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> ScanCreated:
    settings = get_settings()
    try:
        safe_url = validate_target_url(payload.target_url)
    except UnsafeTargetError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    since = datetime.utcnow() - timedelta(hours=1)
    if db.query(Scan).filter(Scan.user_id == user.id, Scan.created_at >= since).count() >= settings.scans_per_hour:
        raise HTTPException(status_code=429, detail="Hourly scan limit reached. Please try again later.")
    active = db.query(Scan).filter(Scan.status.in_([ScanStatus.queued, ScanStatus.running])).count()
    if active >= settings.max_concurrent_scans:
        raise HTTPException(status_code=429, detail="Scanner capacity is temporarily full. Please retry shortly.")
    scan = Scan(user_id=user.id, target_url=safe_url)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    run_scan.delay(scan.id)
    return ScanCreated(scan_id=scan.id, status=scan.status)


@router.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
def scan_status(scan_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> ScanStatusResponse:
    scan = _owned_scan(scan_id, user, db)
    return ScanStatusResponse(scan_id=scan.id, status=scan.status, progress=scan.progress, error=scan.error)


@router.get("/scan/{scan_id}", response_model=ScanReportResponse)
def scan_report(scan_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> ScanReportResponse:
    scan = _owned_scan(scan_id, user, db)
    result = ScanResult.model_validate(scan.results) if scan.results else None
    return ScanReportResponse(scan_id=scan.id, status=scan.status, created_at=scan.created_at, completed_at=scan.completed_at, result=result)
