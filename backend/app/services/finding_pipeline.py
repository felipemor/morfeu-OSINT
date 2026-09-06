"""
Finding Lifecycle & Triage Pipeline Service

Manages state transitions and verification pipeline:
Observation → Potential Finding → Validation → Evidence → Confirmed Finding
"""
from datetime import datetime, timezone
from typing import Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from app.models import Finding, FindingStatus, Severity

logger = structlog.get_logger(__name__)

# Valid state machine transitions
ALLOWED_TRANSITIONS: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.NEW: {
        FindingStatus.TRIAGED,
        FindingStatus.VALIDATING,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.DUPLICATE,
    },
    FindingStatus.TRIAGED: {
        FindingStatus.VALIDATING,
        FindingStatus.CONFIRMED,
        FindingStatus.ACCEPTED_RISK,
        FindingStatus.FALSE_POSITIVE,
    },
    FindingStatus.VALIDATING: {
        FindingStatus.CONFIRMED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.OPEN,
    },
    FindingStatus.CONFIRMED: {
        FindingStatus.REPORTED,
        FindingStatus.REMEDIATION,
        FindingStatus.ACCEPTED_RISK,
        FindingStatus.IN_PROGRESS,
    },
    FindingStatus.OPEN: {
        FindingStatus.IN_PROGRESS,
        FindingStatus.RETEST_PENDING,
        FindingStatus.FIXED,
        FindingStatus.ACCEPTED,
        FindingStatus.FALSE_POSITIVE,
    },
    FindingStatus.IN_PROGRESS: {
        FindingStatus.RETEST_PENDING,
        FindingStatus.FIXED,
        FindingStatus.REMEDIATION,
    },
    FindingStatus.REMEDIATION: {
        FindingStatus.RETEST,
        FindingStatus.RETEST_PENDING,
    },
    FindingStatus.RETEST: {
        FindingStatus.RESOLVED,
        FindingStatus.REMEDIATION,
        FindingStatus.CONFIRMED,
    },
    FindingStatus.RETEST_PENDING: {
        FindingStatus.FIXED,
        FindingStatus.IN_PROGRESS,
    },
    FindingStatus.FIXED: {
        FindingStatus.RESOLVED,
        FindingStatus.RETEST_PENDING,
    },
    FindingStatus.RESOLVED: {
        FindingStatus.RETEST,  # Can retest regression
    },
    FindingStatus.FALSE_POSITIVE: set(),
    FindingStatus.DUPLICATE: set(),
    FindingStatus.ACCEPTED_RISK: {FindingStatus.REMEDIATION},
    FindingStatus.ACCEPTED: {FindingStatus.IN_PROGRESS},
    FindingStatus.MITIGATED: {FindingStatus.RESOLVED, FindingStatus.RETEST},
}


class InvalidFindingTransitionError(Exception):
    pass


class FindingPipelineService:
    """Service to process observations and transition finding lifecycle states."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def transition_finding_status(
        self,
        finding_id: str,
        new_status: FindingStatus,
        reason: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> Finding:
        """
        Validates and transitions finding status according to the lifecycle state machine.
        """
        result = await self.db.execute(select(Finding).where(Finding.id == finding_id))
        finding = result.scalar_one_or_none()
        if not finding:
            raise ValueError(f"Finding with ID {finding_id} not found.")

        current_status = finding.status
        allowed = ALLOWED_TRANSITIONS.get(current_status, set())

        # Allow admin overrides or same-status update
        if new_status != current_status and new_status not in allowed:
            raise InvalidFindingTransitionError(
                f"Cannot transition finding from '{current_status.value}' to '{new_status.value}'. "
                f"Allowed transitions: {[s.value for s in allowed]}"
            )

        finding.status = new_status
        finding.updated_at = datetime.now(timezone.utc)

        if new_status == FindingStatus.FALSE_POSITIVE:
            finding.is_false_positive = True
            finding.false_positive_reason = reason or "Marked as false positive during triage."

        await self.db.commit()
        await self.db.refresh(finding)

        logger.info(
            "Finding status transitioned",
            finding_id=finding_id,
            from_status=current_status.value,
            to_status=new_status.value,
            user_id=user_id,
        )

        return finding

    @staticmethod
    def evaluate_observation(
        confidence: int,
        evidence_count: int,
        reproducibility: str = "HIGH",
        false_positive_prob: float = 0.05,
    ) -> tuple[FindingStatus, str]:
        """
        Evaluates raw observation metrics to determine if it should be confirmed as a finding.
        """
        if confidence >= 80 and evidence_count >= 1 and false_positive_prob <= 0.15:
            return FindingStatus.CONFIRMED, "High confidence with solid evidence."
        elif confidence >= 50:
            return FindingStatus.VALIDATING, "Medium confidence; requires secondary validation."
        else:
            return FindingStatus.TRIAGED, "Low confidence observation queued for triage."
