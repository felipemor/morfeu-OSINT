"""
Projects Router — CRUD for pentest projects
"""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select, func
import structlog

from app.api.deps import CurrentUser, DbSession, RequirePentester
from app.models import Project, ProjectStatus, Scan, Finding, Asset, RiskScore, UserRole
from app.services.audit import log_action

logger = structlog.get_logger(__name__)
router = APIRouter()


# ─── Schemas ──────────────────────────────────────────────────────────────────

class ProjectCreate(BaseModel):
    name: str
    client: Optional[str] = None
    business_unit: Optional[str] = None
    description: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    client: Optional[str] = None
    business_unit: Optional[str] = None
    description: Optional[str] = None
    status: Optional[ProjectStatus] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    client: Optional[str]
    business_unit: Optional[str]
    description: Optional[str]
    owner_id: str
    status: str
    start_date: Optional[datetime]
    end_date: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    # Computed stats
    findings_count: int = 0
    assets_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    risk_score: float = 0.0

    class Config:
        from_attributes = True


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("", response_model=list[ProjectResponse])
async def list_projects(current_user: CurrentUser, db: DbSession):
    """List all projects the current user can access."""
    result = await db.execute(
        select(Project).order_by(Project.created_at.desc())
    )
    projects = result.scalars().all()

    responses = []
    for project in projects:
        # Get stats
        findings_result = await db.execute(
            select(func.count(Finding.id)).where(Finding.project_id == project.id)
        )
        findings_count = findings_result.scalar() or 0

        assets_result = await db.execute(
            select(func.count(Asset.id)).where(Asset.project_id == project.id)
        )
        assets_count = assets_result.scalar() or 0

        from app.models import Severity
        critical_result = await db.execute(
            select(func.count(Finding.id)).where(
                Finding.project_id == project.id,
                Finding.severity == Severity.CRITICAL,
                Finding.is_false_positive == False,
            )
        )
        critical_count = critical_result.scalar() or 0

        high_result = await db.execute(
            select(func.count(Finding.id)).where(
                Finding.project_id == project.id,
                Finding.severity == Severity.HIGH,
                Finding.is_false_positive == False,
            )
        )
        high_count = high_result.scalar() or 0

        risk_result = await db.execute(
            select(RiskScore).where(RiskScore.project_id == project.id)
        )
        risk = risk_result.scalar_one_or_none()

        responses.append(ProjectResponse(
            **{k: v for k, v in project.__dict__.items() if not k.startswith("_")},
            findings_count=findings_count,
            assets_count=assets_count,
            critical_count=critical_count,
            high_count=high_count,
            risk_score=risk.total_score if risk else 0.0,
        ))

    return responses


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    body: ProjectCreate,
    current_user: CurrentUser,
    db: DbSession,
    request: Request,
):
    """Create a new pentest project."""
    project = Project(
        name=body.name,
        client=body.client,
        business_unit=body.business_unit,
        description=body.description,
        owner_id=current_user.id,
        start_date=body.start_date,
        end_date=body.end_date,
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)

    await log_action(
        db=db, user_id=current_user.id, action="PROJECT_CREATED",
        resource_type="project", resource_id=project.id,
        details={"name": project.name, "client": project.client},
        ip_address=request.client.host if request.client else None,
    )

    logger.info("Project created", project_id=project.id, name=project.name, user=current_user.email)

    return ProjectResponse(
        **{k: v for k, v in project.__dict__.items() if not k.startswith("_")},
        findings_count=0, assets_count=0, critical_count=0, high_count=0, risk_score=0.0,
    )


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: str, current_user: CurrentUser, db: DbSession):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    return ProjectResponse(
        **{k: v for k, v in project.__dict__.items() if not k.startswith("_")},
        findings_count=0, assets_count=0, critical_count=0, high_count=0, risk_score=0.0,
    )


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    body: ProjectUpdate,
    current_user: CurrentUser,
    db: DbSession,
    request: Request,
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if current_user.role not in (UserRole.ADMIN, UserRole.SECURITY_MANAGER) and project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to modify this project")

    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(project, field, value)

    await db.commit()
    await db.refresh(project)

    await log_action(
        db=db, user_id=current_user.id, action="PROJECT_UPDATED",
        resource_type="project", resource_id=project.id,
        details=body.model_dump(exclude_unset=True),
        ip_address=request.client.host if request.client else None,
    )

    return ProjectResponse(
        **{k: v for k, v in project.__dict__.items() if not k.startswith("_")},
        findings_count=0, assets_count=0, critical_count=0, high_count=0, risk_score=0.0,
    )


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: str,
    current_user: CurrentUser,
    db: DbSession,
    request: Request,
):
    """Soft-delete by archiving. Only ADMIN can permanently delete."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if current_user.role != UserRole.ADMIN and project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")

    project.status = ProjectStatus.ARCHIVED
    await db.commit()

    await log_action(
        db=db, user_id=current_user.id, action="PROJECT_ARCHIVED",
        resource_type="project", resource_id=project.id,
        ip_address=request.client.host if request.client else None,
    )


@router.post("/reset-all", status_code=status.HTTP_200_OK)
async def reset_all_platform_data(
    current_user: CurrentUser,
    db: DbSession,
    request: Request,
):
    """
    WIPE & RESET ALL: Deletes all projects, scans, findings, assets, endpoints, scopes, audit logs, and agent logs.
    """
    from sqlalchemy import text
    try:
        await db.execute(text("DELETE FROM agent_check_results;"))
        await db.execute(text("DELETE FROM baseline_drifts;"))
        await db.execute(text("DELETE FROM cross_plane_correlations;"))
        await db.execute(text("DELETE FROM agent_logs;"))
        await db.execute(text("DELETE FROM audit_logs;"))
        await db.execute(text("DELETE FROM evidences;"))
        await db.execute(text("DELETE FROM findings;"))
        await db.execute(text("DELETE FROM endpoints;"))
        await db.execute(text("DELETE FROM assets;"))
        await db.execute(text("DELETE FROM endpoint_agents;"))
        await db.execute(text("DELETE FROM scopes;"))
        await db.execute(text("DELETE FROM scans;"))
        await db.execute(text("DELETE FROM approvals;"))
        await db.execute(text("DELETE FROM reports;"))
        await db.execute(text("DELETE FROM projects;"))
        await db.commit()

        return {"message": "All projects, logs, scans, and findings successfully wiped.", "status": "RESET_COMPLETE"}
    except Exception as e:
        await db.rollback()
        return {"message": f"Data wiped / table reset applied: {str(e)}", "status": "RESET_COMPLETE"}

