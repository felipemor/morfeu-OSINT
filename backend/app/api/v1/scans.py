"""
Scans Router — Start/Stop pentest scans, kill switch
"""
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, status, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy import select
import structlog

from app.api.deps import CurrentUser, DbSession, RequirePentester
from app.models import Scan, Project, Scope, ScanMode, ScanStatus, ProjectStatus
from app.services.audit import log_action
from app.services.kill_switch import activate_kill_switch, is_kill_switch_active

logger = structlog.get_logger(__name__)
router = APIRouter()


class ScanCreate(BaseModel):
    mode: ScanMode = ScanMode.PASSIVE
    targets: Optional[list[str]] = None  # Optional override — uses scope targets if None


class ScanResponse(BaseModel):
    id: str
    project_id: str
    mode: str
    status: str
    progress: int
    current_phase: Optional[str]
    assets_discovered: int
    endpoints_found: int
    findings_count: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    celery_task_id: Optional[str]

    class Config:
        from_attributes = True


@router.post("/{project_id}/scan", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def start_scan(
    project_id: str,
    body: ScanCreate,
    current_user: CurrentUser,
    db: DbSession,
    request: Request,
):
    """
    Start an autonomous pentest scan.
    
    SAFETY: Validates scope authorization before starting.
    Kill switch must not be active.
    """
    # Check kill switch
    if await is_kill_switch_active():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Kill switch is active. Deactivate it before starting new scans.",
        )

    # Validate project exists
    proj_result = await db.execute(select(Project).where(Project.id == project_id))
    project = proj_result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Validate scope exists and is authorized
    scope_result = await db.execute(select(Scope).where(Scope.project_id == project_id))
    scope = scope_result.scalar_one_or_none()

    if not scope:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Project has no scope defined. Configure scope before scanning.",
        )

    if not scope.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authorization not confirmed. You must confirm authorization before active scanning.",
        )

    if not (scope.allowed_domains or scope.allowed_ips or scope.allowed_cidrs or scope.allowed_urls):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scope has no allowed targets. Add at least one authorized target.",
        )

    # AUTHORIZED_ADVERSARY requires explicit role check
    if body.mode == ScanMode.AUTHORIZED_ADVERSARY:
        from app.models import UserRole
        if current_user.role not in (UserRole.ADMIN, UserRole.SECURITY_MANAGER, UserRole.PENTESTER):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="AUTHORIZED_ADVERSARY mode requires PENTESTER role or higher.",
            )

    # Check no active scan for this project
    active_scan_result = await db.execute(
        select(Scan).where(
            Scan.project_id == project_id,
            Scan.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
        )
    )
    active_scan = active_scan_result.scalar_one_or_none()
    if active_scan:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan {active_scan.id} is already active for this project.",
        )

    # Create scan record
    scan = Scan(
        project_id=project_id,
        mode=body.mode,
        status=ScanStatus.PENDING,
        initiated_by=current_user.id,
    )
    db.add(scan)
    project.status = ProjectStatus.SCANNING
    await db.commit()
    await db.refresh(scan)

    # Launch Celery task
    from app.agents.orchestrator import run_pentest_orchestrator
    task = run_pentest_orchestrator.apply_async(
        args=[scan.id, project_id],
        queue="default",
        task_id=f"scan_{scan.id}",
    )
    scan.celery_task_id = task.id
    await db.commit()

    await log_action(
        db=db, user_id=current_user.id, action="SCAN_STARTED",
        resource_type="scan", resource_id=scan.id,
        project_id=project_id,
        details={"mode": body.mode.value, "task_id": task.id},
        ip_address=request.client.host if request.client else None,
    )

    logger.info("Scan started", scan_id=scan.id, mode=body.mode, project=project_id, user=current_user.email)

    return scan


@router.post("/{project_id}/stop", status_code=status.HTTP_200_OK)
async def stop_scan(
    project_id: str,
    current_user: CurrentUser,
    db: DbSession,
    request: Request,
    global_kill: bool = False,
):
    """
    KILL SWITCH — Stop all active tests for this project (or globally).
    
    Immediately:
    - Revokes Celery tasks
    - Sets Redis kill flag
    - Preserves all evidence collected so far
    - Records emergency stop in audit log
    """
    await log_action(
        db=db, user_id=current_user.id, action="KILL_SWITCH_ACTIVATED",
        resource_type="project", resource_id=project_id,
        project_id=project_id,
        details={"global": global_kill, "reason": "User initiated stop"},
        ip_address=request.client.host if request.client else None,
        result="EMERGENCY_STOP",
    )

    # Get active scans
    active_result = await db.execute(
        select(Scan).where(
            Scan.project_id == project_id,
            Scan.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
        )
    )
    active_scans = active_result.scalars().all()

    killed_count = 0
    for scan in active_scans:
        # Revoke Celery task
        if scan.celery_task_id:
            from app.agents.celery_app import celery_app
            celery_app.control.revoke(scan.celery_task_id, terminate=True, signal="SIGKILL")

        scan.status = ScanStatus.KILLED
        scan.killed_at = datetime.now(timezone.utc)
        killed_count += 1

    # Set project status back
    proj_result = await db.execute(select(Project).where(Project.id == project_id))
    project = proj_result.scalar_one_or_none()
    if project and project.status == ProjectStatus.SCANNING:
        project.status = ProjectStatus.PAUSED

    # Activate global kill switch if requested
    if global_kill:
        await activate_kill_switch(activated_by=current_user.id)

    await db.commit()

    logger.warning(
        "🚨 KILL SWITCH ACTIVATED",
        project_id=project_id,
        killed_scans=killed_count,
        global_kill=global_kill,
        user=current_user.email,
    )

    return {
        "message": "All tests stopped",
        "killed_scans": killed_count,
        "global_kill_switch": global_kill,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/{project_id}/scan/status")
async def get_scan_status(project_id: str, current_user: CurrentUser, db: DbSession):
    """Get status of the current/last scan for a project."""
    result = await db.execute(
        select(Scan).where(Scan.project_id == project_id).order_by(Scan.created_at.desc()).limit(1)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        return {"status": "NO_SCAN", "project_id": project_id}

    # Get recent agent logs
    from app.models import AgentLog
    logs_result = await db.execute(
        select(AgentLog).where(AgentLog.scan_id == scan.id).order_by(AgentLog.timestamp.desc()).limit(20)
    )
    logs = logs_result.scalars().all()

    return {
        "scan_id": scan.id,
        "status": scan.status.value,
        "mode": scan.mode.value,
        "progress": scan.progress,
        "current_phase": scan.current_phase,
        "assets_discovered": scan.assets_discovered,
        "endpoints_found": scan.endpoints_found,
        "findings_count": scan.findings_count,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "kill_switch_active": await is_kill_switch_active(),
        "recent_logs": [
            {
                "timestamp": log.timestamp.isoformat(),
                "agent": log.agent_type.value,
                "level": log.level,
                "message": log.message,
                "target": log.target,
            }
            for log in reversed(logs)
        ],
    }
