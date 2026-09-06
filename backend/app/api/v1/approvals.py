"""
Approvals API Router — Endpoints for reviewing and deciding on AI actions
"""
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel
from app.api.deps import CurrentUser, DbSession, RequireManager
from app.models import ApprovalRequest, ApprovalStatus
from app.services.approval_service import ApprovalService
from app.services.audit import log_action

router = APIRouter()


class ApprovalDecisionRequest(BaseModel):
    approved: bool
    reason: Optional[str] = None


class ApprovalResponse(BaseModel):
    id: str
    project_id: str
    scan_id: Optional[str]
    requested_by: str
    action_type: str
    target: str
    reason: str
    risk_level: str
    status: str
    decision_reason: Optional[str]

    class Config:
        from_attributes = True


@router.get("/", response_model=list[ApprovalResponse])
async def get_pending_approvals(
    current_user: CurrentUser,
    db: DbSession,
    project_id: Optional[str] = None,
):
    """List all actions requiring human operator review."""
    svc = ApprovalService(db)
    return await svc.list_pending_approvals(project_id=project_id)


@router.post("/{approval_id}/decision", response_model=ApprovalResponse)
async def decide_approval(
    approval_id: str,
    body: ApprovalDecisionRequest,
    current_user: RequireManager,
    db: DbSession,
    request: Request,
):
    """
    Approve or reject a pending AI action.
    Requires SECURITY_MANAGER or ADMIN role.
    """
    svc = ApprovalService(db)
    try:
        updated = await svc.process_approval(
            request_id=approval_id,
            reviewer_id=current_user.id,
            approve=body.approved,
            decision_reason=body.reason,
        )
        await log_action(
            db=db,
            user_id=current_user.id,
            action="APPROVAL_DECISION",
            resource_type="ApprovalRequest",
            resource_id=approval_id,
            details={"approved": body.approved, "reason": body.reason},
            request=request,
        )
        return updated
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
