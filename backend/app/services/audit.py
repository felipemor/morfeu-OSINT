"""
Audit Log Service — Record all significant actions
"""
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.models import AuditLog

logger = structlog.get_logger(__name__)


async def log_action(
    db: AsyncSession,
    action: str,
    user_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    project_id: Optional[str] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    result: str = "SUCCESS",
    error_message: Optional[str] = None,
):
    """Record an audit log entry. Never raises — logs failures to structlog."""
    try:
        entry = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            project_id=project_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            result=result,
            error_message=error_message,
        )
        db.add(entry)
        await db.flush()  # Don't commit — let the caller's transaction handle it

        logger.info(
            "Audit",
            action=action,
            user_id=user_id,
            resource=f"{resource_type}/{resource_id}",
            result=result,
        )
    except Exception as e:
        # Audit log failure must NEVER break the main flow
        logger.error("Failed to write audit log", error=str(e), action=action)
