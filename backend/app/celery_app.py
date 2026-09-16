"""Celery application used by the API producer and dedicated worker process."""
from celery import Celery
from .config import get_settings

settings = get_settings()
celery_app = Celery("vulnscan", broker=settings.redis_url, backend=settings.redis_url, include=["app.tasks.scan_tasks"])
celery_app.conf.update(task_serializer="json", result_serializer="json", accept_content=["json"], task_track_started=True, broker_connection_retry_on_startup=True)
