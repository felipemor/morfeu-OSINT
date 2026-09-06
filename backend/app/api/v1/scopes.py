"""
Scope Router — Manage project scope (allowlist, exclusions, rate limits)
"""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select
import structlog

from app.api.deps import CurrentUser, DbSession
from app.models import Scope, Project, Target, TargetType, ScanMode, BusinessCriticality
from app.services.audit import log_action

logger = structlog.get_logger(__name__)
router = APIRouter()


class ScopeCreate(BaseModel):
    allowed_domains: list[str] = []
    allowed_ips: list[str] = []
    allowed_cidrs: list[str] = []
    allowed_urls: list[str] = []
    excluded_domains: list[str] = []
    excluded_ips: list[str] = []
    excluded_paths: list[str] = []
    max_requests_per_minute: int = 30
    max_concurrent_requests: int = 5
    execution_window_start: Optional[str] = None
    execution_window_end: Optional[str] = None
    authorization_confirmed: bool = False
    authorized_by: Optional[str] = None
    authorization_document: Optional[str] = None
    allow_private_ips: bool = False
    scan_mode: ScanMode = ScanMode.PASSIVE
    notes: Optional[str] = None

    @field_validator("max_requests_per_minute")
    @classmethod
    def validate_rate_limit(cls, v: int) -> int:
        if v > 300:
            raise ValueError("Rate limit cannot exceed 300 req/min for safety")
        return v

    @field_validator("max_concurrent_requests")
    @classmethod
    def validate_concurrency(cls, v: int) -> int:
        if v > 20:
            raise ValueError("Max concurrent requests cannot exceed 20 for safety")
        return v


class TargetCreate(BaseModel):
    value: str
    target_type: TargetType
    business_criticality: BusinessCriticality = BusinessCriticality.MEDIUM
    is_internet_facing: bool = True
    notes: Optional[str] = None


class ScopeResponse(BaseModel):
    id: str
    project_id: str
    allowed_domains: list
    allowed_ips: list
    allowed_cidrs: list
    allowed_urls: list
    excluded_domains: list
    excluded_ips: list
    excluded_paths: list
    max_requests_per_minute: int
    max_concurrent_requests: int
    execution_window_start: Optional[str]
    execution_window_end: Optional[str]
    authorization_confirmed: bool
    authorized_by: Optional[str]
    allow_private_ips: bool
    scan_mode: str
    notes: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


@router.post("/{project_id}/scope", response_model=ScopeResponse)
async def set_scope(
    project_id: str,
    body: ScopeCreate,
    current_user: CurrentUser,
    db: DbSession,
    request: Request,
):
    """Create or update the scope for a project."""
    proj_result = await db.execute(select(Project).where(Project.id == project_id))
    if not proj_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")

    # Validate scope has at least one target
    if not any([body.allowed_domains, body.allowed_ips, body.allowed_cidrs, body.allowed_urls]):
        raise HTTPException(
            status_code=400,
            detail="Scope must include at least one authorized target (domain, IP, CIDR, or URL)",
        )

    # Upsert scope
    scope_result = await db.execute(select(Scope).where(Scope.project_id == project_id))
    scope = scope_result.scalar_one_or_none()

    if scope:
        for field, value in body.model_dump().items():
            setattr(scope, field, value)
    else:
        scope = Scope(project_id=project_id, **body.model_dump())
        db.add(scope)

    await db.commit()
    await db.refresh(scope)

    await log_action(
        db=db, user_id=current_user.id, action="SCOPE_CONFIGURED",
        resource_type="scope", resource_id=scope.id,
        project_id=project_id,
        details={
            "domains": body.allowed_domains,
            "ips": body.allowed_ips,
            "cidrs": body.allowed_cidrs,
            "authorization_confirmed": body.authorization_confirmed,
            "scan_mode": body.scan_mode.value,
        },
        ip_address=request.client.host if request.client else None,
    )

    logger.info("Scope configured", project_id=project_id, domains=body.allowed_domains)
    return scope


@router.get("/{project_id}/scope", response_model=ScopeResponse)
async def get_scope(project_id: str, current_user: CurrentUser, db: DbSession):
    scope_result = await db.execute(select(Scope).where(Scope.project_id == project_id))
    scope = scope_result.scalar_one_or_none()
    if not scope:
        raise HTTPException(status_code=404, detail="No scope configured for this project")
    return scope


@router.post("/{project_id}/targets", status_code=201)
async def add_target(
    project_id: str,
    body: TargetCreate,
    current_user: CurrentUser,
    db: DbSession,
    request: Request,
):
    """Add an authorized target to the project."""
    proj_result = await db.execute(select(Project).where(Project.id == project_id))
    if not proj_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")

    target = Target(
        project_id=project_id,
        value=body.value,
        target_type=body.target_type,
        business_criticality=body.business_criticality,
        is_internet_facing=body.is_internet_facing,
        notes=body.notes,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    await log_action(
        db=db, user_id=current_user.id, action="TARGET_ADDED",
        project_id=project_id, resource_id=target.id,
        details={"value": body.value, "type": body.target_type.value},
        ip_address=request.client.host if request.client else None,
    )

    return {"id": target.id, "value": target.value, "type": target.target_type.value}


@router.get("/{project_id}/targets")
async def list_targets(project_id: str, current_user: CurrentUser, db: DbSession):
    result = await db.execute(select(Target).where(Target.project_id == project_id))
    targets = result.scalars().all()
    return [
        {
            "id": t.id, "value": t.value, "type": t.target_type.value,
            "criticality": t.business_criticality.value,
            "internet_facing": t.is_internet_facing,
        }
        for t in targets
    ]
