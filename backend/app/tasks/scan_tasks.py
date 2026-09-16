"""Worker entry point. The API never executes scanner network work synchronously."""
from datetime import datetime
import logging
from sqlalchemy.orm import Session
from ..celery_app import celery_app
from ..config import get_settings
from ..database import SessionLocal
from ..models.scan import Scan, ScanStatus
from ..scanner.engine import ScannerEngine

logger = logging.getLogger(__name__)

_STAGE_PROGRESS = {
    "fetching_target": 20,
    "headers_analyzed": 40,
    "tls_analyzed": 60,
    "cms_analyzed": 80,
    "score_calculated": 95,
}


@celery_app.task(name="vulnscan.run_scan")
def run_scan(scan_id: str) -> None:
    db: Session = SessionLocal()
    scan = db.get(Scan, scan_id)
    if not scan:
        logger.warning("scan_not_found", extra={"scan_id": scan_id})
        return
    try:
        scan.status, scan.progress, scan.started_at = ScanStatus.running, 5, datetime.utcnow()
        db.commit()
        hostname = scan.target_url.split("/")[2]
        logger.info("scan_started", extra={"scan_id": scan.id, "target_hostname": hostname})

        def report_stage(stage: str) -> None:
            scan.progress = _STAGE_PROGRESS[stage]
            db.commit()
            logger.info(
                "scan_stage_completed",
                extra={"scan_id": scan.id, "target_hostname": hostname, "stage": stage, "progress": scan.progress},
            )

        settings = get_settings()
        scanner = ScannerEngine(settings.request_timeout_seconds, settings.max_response_bytes, settings.max_redirects)
        result = scanner.scan(scan.target_url, on_stage=report_stage)
        scan.results, scan.score, scan.grade = result.model_dump(mode="json"), result.score, result.grade
        scan.status, scan.progress, scan.completed_at = ScanStatus.completed, 100, datetime.utcnow()
        db.commit()
        logger.info(
            "scan_completed",
            extra={"scan_id": scan.id, "target_hostname": hostname, "score": scan.score, "duration_ms": result.duration_ms},
        )
    except Exception as error:
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status, scan.progress, scan.error, scan.completed_at = ScanStatus.failed, 100, "The target could not be scanned safely. Check the URL and try again.", datetime.utcnow()
            db.commit()
        logger.exception("scan_failed", extra={"scan_id": scan_id, "error_type": type(error).__name__})
    finally:
        db.close()
