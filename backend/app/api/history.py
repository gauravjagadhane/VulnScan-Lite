"""Per-user scan history, intentionally scoped to the authenticated owner."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..database import get_db
from ..models.scan import Scan
from ..models.user import User
from ..schemas.scan import HistoryItem
from ..security import get_current_user

router = APIRouter(prefix="/api", tags=["history"])


@router.get("/history", response_model=list[HistoryItem])
def history(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[HistoryItem]:
    scans = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.created_at.desc()).limit(100).all()
    return [HistoryItem(id=item.id, target_url=item.target_url, score=item.score, grade=item.grade, status=item.status, created_at=item.created_at) for item in scans]
