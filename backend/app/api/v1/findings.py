"""
Findings Router — CRUD, validation, false positive management
"""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, status, Query
from pydantic import BaseModel
from sqlalchemy import select, func
import structlog

from app.api.deps import CurrentUser, DbSession
from app.models import Finding, Severity, FindingStatus, Evidence, Retest, ScanStatus, Project, UserRole
from app.services.audit import log_action
from app.services.risk_engine import calculate_project_risk

logger = structlog.get_logger(__name__)
router = APIRouter()


class FindingUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[Severity] = None
    status: Optional[FindingStatus] = None
    description: Optional[str] = None
    business_impact: Optional[str] = None
    technical_impact: Optional[str] = None
    root_cause: Optional[str] = None
    recommendation: Optional[str] = None
    is_false_positive: Optional[bool] = None
    false_positive_reason: Optional[str] = None
    confidence: Optional[int] = None


class FindingResponse(BaseModel):
    id: str
    project_id: str
    title: str
    severity: str
    status: str
    owasp_category: Optional[str]
    cwe_id: Optional[str]
    cvss_score: Optional[float]
    confidence: int
    risk_score: Optional[float]
    affected_url: Optional[str]
    affected_asset: Optional[str]
    parameter: Optional[str]
    description: str
    business_impact: Optional[str]
    technical_impact: Optional[str]
    root_cause: Optional[str]
    steps_to_reproduce: Optional[str]
    recommendation: Optional[str]
    developer_recommendation: Optional[str]
    compensating_controls: Optional[str]
    references: list
    discovered_by: Optional[str]
    is_false_positive: bool
    false_positive_reason: Optional[str]
    created_at: datetime
    updated_at: datetime
    evidence_count: int = 0

    class Config:
        from_attributes = True


@router.get("")
@router.get("/")
async def list_all_findings(
    current_user: CurrentUser,
    db: DbSession,
    project_id: Optional[str] = Query(None),
    severity: Optional[Severity] = Query(None),
    status_filter: Optional[FindingStatus] = Query(None, alias="status"),
    is_false_positive: Optional[bool] = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
):
    """List findings with filters."""
    query = select(Finding)

    if project_id:
        query = query.where(Finding.project_id == project_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if status_filter:
        query = query.where(Finding.status == status_filter)
    if is_false_positive is not None:
        query = query.where(Finding.is_false_positive == is_false_positive)

    query = query.order_by(Finding.created_at.desc()).limit(limit).offset(offset)

    result = await db.execute(query)
    findings = result.scalars().all()

    responses = []
    for finding in findings:
        ev_count_result = await db.execute(
            select(func.count(Evidence.id)).where(Evidence.finding_id == finding.id)
        )
        responses.append(FindingResponse(
            **{k: v for k, v in finding.__dict__.items() if not k.startswith("_")},
            evidence_count=ev_count_result.scalar() or 0,
        ))

    return responses


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str, current_user: CurrentUser, db: DbSession):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    ev_count_result = await db.execute(
        select(func.count(Evidence.id)).where(Evidence.finding_id == finding.id)
    )

    return FindingResponse(
        **{k: v for k, v in finding.__dict__.items() if not k.startswith("_")},
        evidence_count=ev_count_result.scalar() or 0,
    )


@router.put("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: str,
    body: FindingUpdate,
    current_user: CurrentUser,
    db: DbSession,
    request: Request,
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(finding, field, value)

    await db.commit()
    await db.refresh(finding)

    # Recalculate risk score
    await calculate_project_risk(db, finding.project_id)

    await log_action(
        db=db, user_id=current_user.id, action="FINDING_UPDATED",
        resource_type="finding", resource_id=finding.id,
        project_id=finding.project_id,
        details=body.model_dump(exclude_unset=True),
        ip_address=request.client.host if request.client else None,
    )

    ev_count_result = await db.execute(
        select(func.count(Evidence.id)).where(Evidence.finding_id == finding.id)
    )
    return FindingResponse(
        **{k: v for k, v in finding.__dict__.items() if not k.startswith("_")},
        evidence_count=ev_count_result.scalar() or 0,
    )


@router.post("/{finding_id}/retest", status_code=201)
async def create_retest(
    finding_id: str,
    current_user: CurrentUser,
    db: DbSession,
    request: Request,
):
    """Schedule a retest for a finding after remediation."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    retest = Retest(
        finding_id=finding_id,
        project_id=finding.project_id,
        initiated_by=current_user.id,
        scan_status=ScanStatus.PENDING,
    )
    db.add(retest)

    # Update finding status
    finding.status = FindingStatus.RETEST_PENDING
    await db.commit()
    await db.refresh(retest)

    # Launch retest Celery task
    from app.agents.orchestrator import run_retest
    task = run_retest.apply_async(
        args=[retest.id, finding_id],
        queue="default",
    )

    await log_action(
        db=db, user_id=current_user.id, action="RETEST_INITIATED",
        resource_type="retest", resource_id=retest.id,
        project_id=finding.project_id,
        details={"finding_id": finding_id, "task_id": task.id},
        ip_address=request.client.host if request.client else None,
    )

    return {"retest_id": retest.id, "status": "PENDING", "task_id": task.id}


@router.get("/project/{project_id}/summary")
async def get_findings_summary(project_id: str, current_user: CurrentUser, db: DbSession):
    """Summarized finding counts by severity for a project."""
    counts = {}
    for sev in Severity:
        result = await db.execute(
            select(func.count(Finding.id)).where(
                Finding.project_id == project_id,
                Finding.severity == sev,
                Finding.is_false_positive == False,
            )
        )
        counts[sev.value] = result.scalar() or 0

    fp_result = await db.execute(
        select(func.count(Finding.id)).where(
            Finding.project_id == project_id,
            Finding.is_false_positive == True,
        )
    )
    counts["FALSE_POSITIVE"] = fp_result.scalar() or 0

    return counts
