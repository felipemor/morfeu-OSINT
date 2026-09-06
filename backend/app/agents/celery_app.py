"""
Celery Application Configuration
"""
from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "pentest",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.agents.orchestrator",
        "app.agents.recon_agent",
        "app.agents.crawler_agent",
        "app.agents.vuln_agent",
        "app.agents.screenshot_agent",
        "app.agents.report_agent",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "app.agents.orchestrator.*": {"queue": "default"},
        "app.agents.recon_agent.*": {"queue": "recon"},
        "app.agents.crawler_agent.*": {"queue": "crawler"},
        "app.agents.vuln_agent.*": {"queue": "vuln"},
        "app.agents.screenshot_agent.*": {"queue": "screenshot"},
        "app.agents.report_agent.*": {"queue": "report"},
    },
    task_soft_time_limit=3600,   # 1 hour soft limit
    task_time_limit=7200,        # 2 hour hard limit
    worker_max_tasks_per_child=100,
)
