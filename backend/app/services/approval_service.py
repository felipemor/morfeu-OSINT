"""
Human-In-The-Loop Approval Service

Manages approval workflows for AI-suggested high-risk or production actions:
Levels:
- AUTOMATIC (safe actions, passive checks)
- APPROVAL_REQUIRED (active destructive probes, privileged functions)
- BLOCKED (forbidden patterns, out-of-scope targets)
"""
from datetime import datetime, timezone
from typing import Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from app.models import ApprovalRequest, ApprovalStatus, User, UserRole

logger = structlog.get_logger(__name__)


class ApprovalService:
    """Handles submission, review, and status tracking of pending security actions."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_pending_approvals(self, project_id: Optional[str] = None) -> list[ApprovalRequest]:
        """Returns all actions awaiting human review."""
        stmt = select(ApprovalRequest).where(ApprovalRequest.status == ApprovalStatus.PENDING)
        if project_id:
            stmt = stmt.where(ApprovalRequest.project_id == project_id)
        stmt = stmt.order_by(ApprovalRequest.created_at.desc())

        result = await self.db.execute(stmt)
        return result.scalars().all()

    async def process_approval(
        self,
        request_id: str,
        reviewer_id: str,
        approve: bool,
        decision_reason: Optional[str] = None,
    ) -> ApprovalRequest:
        """
        Approves or rejects a queued action.
        """
        result = await self.db.execute(select(ApprovalRequest).where(ApprovalRequest.id == request_id))
        approval = result.scalar_one_or_none()
        if not approval:
            raise ValueError(f"Approval request {request_id} not found.")

        if approval.status != ApprovalStatus.PENDING:
            raise ValueError(f"Approval request is already in status: {approval.status.value}")

        approval.status = ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED
        approval.reviewed_by = reviewer_id
        approval.decision_reason = decision_reason or ("Approved by security operator." if approve else "Rejected by security operator.")
        approval.reviewed_at = datetime.now(timezone.utc)

        await self.db.commit()
        await self.db.refresh(approval)

        logger.info(
            "AI Action Approval decision recorded",
            request_id=request_id,
            approved=approve,
            reviewer=reviewer_id,
        )

        return approval
