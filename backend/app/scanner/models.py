"""Stable, serializable domain models returned by the passive scanner."""
from datetime import datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field, HttpUrl


class FindingStatus(str, Enum):
    passed = "passed"
    warning = "warning"
    failed = "failed"
    info = "info"


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"


class Confidence(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"


class Finding(BaseModel):
    name: str
    category: str
    status: FindingStatus
    severity: Severity
    score_impact: int = 0
    explanation: str
    evidence: str
    remediation: str | None = None
    confidence: Confidence = Confidence.high


class TLSInfo(BaseModel):
    available: bool
    protocol: str | None = None
    cipher: str | None = None
    issuer: str | None = None
    subject: str | None = None
    expires_at: datetime | None = None
    hostname_verified: bool | None = None


class CMSInfo(BaseModel):
    name: str | None = None
    version: str | None = None
    confidence: Confidence = Confidence.low
    evidence: str | None = None


class ScanResult(BaseModel):
    target_url: str
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    score: int
    grade: str
    findings: list[Finding]
    tls: TLSInfo | None = None
    cms: CMSInfo | None = None
    http_status: int | None = None
    duration_ms: int
