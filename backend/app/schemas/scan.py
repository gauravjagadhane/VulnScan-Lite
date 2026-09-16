from datetime import datetime
from pydantic import BaseModel, Field
from ..models.scan import ScanStatus
from ..scanner.models import ScanResult


class ScanRequest(BaseModel):
    target_url: str = Field(max_length=2048, examples=["https://example.com"])


class ScanCreated(BaseModel):
    scan_id: str
    status: ScanStatus


class ScanStatusResponse(ScanCreated):
    progress: int
    error: str | None = None


class ScanReportResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    created_at: datetime
    completed_at: datetime | None
    result: ScanResult | None = None


class HistoryItem(BaseModel):
    id: str
    target_url: str
    score: float | None
    grade: str | None
    status: ScanStatus
    created_at: datetime
