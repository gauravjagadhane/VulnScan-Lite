"""PDF report download endpoint."""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from ..database import get_db
from ..models.scan import Scan, ScanStatus
from ..models.user import User
from ..reports.pdf_generator import build_pdf
from ..scanner.models import ScanResult
from ..security import get_current_user

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/scan/{scan_id}/pdf")
def pdf(scan_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> Response:
    scan = db.get(Scan, scan_id)
    if not scan or scan.user_id != user.id:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if scan.status != ScanStatus.completed or not scan.results:
        raise HTTPException(status_code=409, detail="The report is not ready yet.")
    content = build_pdf(ScanResult.model_validate(scan.results))
    return Response(content, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="vulnscan-{scan.id}.pdf"'})
