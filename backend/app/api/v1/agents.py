from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from app.core.database import get_db
from app.api.deps import get_current_user
from app.models import User, UserRole, EndpointAgent, AgentStatus, AgentEnrollmentToken
from app.services.agent_service import agent_service
from app.services.baseline_drift_service import baseline_drift_service
from app.services.cross_plane_correlation import cross_plane_correlation
from app.checks.endpoint.registry import endpoint_check_registry

router = APIRouter()


# ─── Pydantic Schemas ────────────────────────────────────────────────────────

class TokenGenerateRequest(BaseModel):
    name: Optional[str] = "Default Enrollment Token"
    project_id: Optional[str] = None
    expires_in_hours: int = Field(default=24, ge=1, le=720)
    max_uses: int = Field(default=1, ge=1, le=100)


class AgentEnrollRequest(BaseModel):
    token: str
    installation_id: str
    hostname: str
    platform: str
    os_version: Optional[str] = ""
    arch: Optional[str] = ""
    ip_addresses: Optional[List[str]] = []
    mac_addresses: Optional[List[str]] = []
    public_key: Optional[str] = None
    agent_version: Optional[str] = "1.0.0"
    capabilities: Optional[List[str]] = []


class HeartbeatRequest(BaseModel):
    telemetry: Optional[Dict[str, Any]] = None


class CreateTaskRequest(BaseModel):
    check_id: str
    parameters: Optional[Dict[str, Any]] = None
    campaign_id: Optional[str] = None


class TaskResultSubmission(BaseModel):
    status: str
    execution_time_ms: int = 0
    findings_data: Optional[List[Dict[str, Any]]] = None
    evidence_data: Optional[Dict[str, Any]] = None
    raw_output: Optional[str] = None
    error_message: Optional[str] = None


class BaselineCaptureRequest(BaseModel):
    baseline_data: Dict[str, Any]


class RevokeAgentRequest(BaseModel):
    reason: Optional[str] = "Revoked by administrator"


# ─── Management Endpoints (User Authenticated) ───────────────────────────────

@router.post("/tokens", status_code=status.HTTP_201_CREATED)
async def create_enrollment_token(
    payload: TokenGenerateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a single-use or bounded enrollment token."""
    token = await agent_service.generate_enrollment_token(
        db=db,
        org_id=current_user.organization_id,
        project_id=payload.project_id,
        created_by_id=current_user.id,
        name=payload.name,
        expires_in_hours=payload.expires_in_hours,
        max_uses=payload.max_uses,
    )
    return {
        "token": token.token,
        "id": token.id,
        "expires_at": token.expires_at,
        "max_uses": token.max_uses,
        "org_id": token.org_id,
        "project_id": token.project_id,
    }


@router.get("", status_code=status.HTTP_200_OK)
async def list_agents(
    project_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List endpoint agents belonging to user's organization or project."""
    stmt = select(EndpointAgent).where(EndpointAgent.org_id == current_user.organization_id)
    if project_id:
        stmt = stmt.where(EndpointAgent.project_id == project_id)

    agents = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": a.id,
            "hostname": a.hostname,
            "platform": a.platform,
            "os_version": a.os_version,
            "arch": a.arch,
            "ip_addresses": a.ip_addresses,
            "status": a.status.value,
            "last_heartbeat_at": a.last_heartbeat_at,
            "project_id": a.project_id,
            "agent_version": a.agent_version,
        }
        for a in agents
    ]


@router.get("/checks", status_code=status.HTTP_200_OK)
async def list_available_checks(
    platform: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    """List all available non-destructive endpoint assessment checks."""
    if platform:
        checks = endpoint_check_registry.get_checks_for_platform(platform)
    else:
        checks = endpoint_check_registry.list_checks()

    return [
        {
            "check_id": getattr(c, "id", getattr(c, "check_id", "")),
            "name": c.name,
            "category": getattr(c, "category", "GENERAL"),
            "severity": c.severity.value,
            "cwe_id": getattr(c, "cwe_id", ""),
            "owasp_category": getattr(c, "owasp_category", ""),
            "supported_platforms": c.supported_platforms,
        }
        for c in checks
    ]


@router.get("/{agent_id}", status_code=status.HTTP_200_OK)
async def get_agent_details(
    agent_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get endpoint agent details."""
    stmt = select(EndpointAgent).where(
        and_(
            EndpointAgent.id == agent_id,
            EndpointAgent.org_id == current_user.organization_id,
        )
    )
    agent = (await db.execute(stmt)).scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    return {
        "id": agent.id,
        "hostname": agent.hostname,
        "platform": agent.platform,
        "os_version": agent.os_version,
        "arch": agent.arch,
        "ip_addresses": agent.ip_addresses,
        "mac_addresses": agent.mac_addresses,
        "status": agent.status.value,
        "last_heartbeat_at": agent.last_heartbeat_at,
        "telemetry_data": agent.telemetry_data,
        "project_id": agent.project_id,
        "created_at": agent.created_at,
    }


@router.post("/{agent_id}/tasks", status_code=status.HTTP_201_CREATED)
async def dispatch_agent_task(
    agent_id: str,
    payload: CreateTaskRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Dispatch a validated assessment check task to an agent."""
    try:
        task = await agent_service.create_task(
            db=db,
            agent_id=agent_id,
            check_id=payload.check_id,
            parameters=payload.parameters,
            campaign_id=payload.campaign_id,
            created_by_id=current_user.id,
        )
        return {
            "task_id": task.id,
            "check_id": task.check_id,
            "status": task.status.value,
            "signature": task.signature,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{agent_id}/baseline", status_code=status.HTTP_201_CREATED)
async def capture_baseline(
    agent_id: str,
    payload: BaselineCaptureRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Capture a baseline for the endpoint."""
    try:
        baseline = await baseline_drift_service.capture_baseline(
            db=db,
            agent_id=agent_id,
            baseline_data=payload.baseline_data,
            created_by_id=current_user.id,
        )
        return {
            "baseline_id": baseline.id,
            "version": baseline.version,
            "fingerprint": baseline.fingerprint,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{agent_id}/revoke", status_code=status.HTTP_200_OK)
async def revoke_agent(
    agent_id: str,
    payload: RevokeAgentRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke an agent to immediately halt any further check distribution."""
    if current_user.role not in [UserRole.ADMIN, UserRole.SECURITY_ENGINEER]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    try:
        agent = await agent_service.revoke_agent(
            db=db,
            agent_id=agent_id,
            revoked_by_id=current_user.id,
            reason=payload.reason or "Revoked by administrator",
        )
        return {"agent_id": agent.id, "status": agent.status.value}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ─── Agent Pull Protocol Endpoints (Polled by Untrusted Agent) ───────────────

@router.post("/enroll", status_code=status.HTTP_200_OK)
async def agent_enroll(
    payload: AgentEnrollRequest,
    db: AsyncSession = Depends(get_db),
):
    """Agent enrollment endpoint (pull-based onboarding)."""
    try:
        agent = await agent_service.enroll_agent(
            db=db,
            token_str=payload.token,
            installation_id=payload.installation_id,
            hostname=payload.hostname,
            platform_name=payload.platform,
            os_version=payload.os_version or "",
            arch=payload.arch or "",
            ip_addresses=payload.ip_addresses,
            mac_addresses=payload.mac_addresses,
            public_key=payload.public_key,
            agent_version=payload.agent_version or "1.0.0",
            capabilities=payload.capabilities,
        )
        return {
            "status": "ENROLLED",
            "agent_id": agent.id,
            "heartbeat_interval_seconds": 30,
            "org_id": agent.org_id,
            "project_id": agent.project_id,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{agent_id}/heartbeat", status_code=status.HTTP_200_OK)
async def agent_heartbeat(
    agent_id: str,
    payload: HeartbeatRequest,
    db: AsyncSession = Depends(get_db),
):
    """Agent heartbeat checking status and kill-switch."""
    try:
        res = await agent_service.process_heartbeat(
            db=db, agent_id=agent_id, telemetry=payload.telemetry
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{agent_id}/tasks", status_code=status.HTTP_200_OK)
async def agent_fetch_tasks(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Agent fetches pending tasks to execute."""
    tasks = await agent_service.fetch_pending_tasks(db=db, agent_id=agent_id)
    return {"tasks": tasks}


@router.post("/{agent_id}/tasks/{task_id}/results", status_code=status.HTTP_200_OK)
async def agent_submit_results(
    agent_id: str,
    task_id: str,
    payload: TaskResultSubmission,
    db: AsyncSession = Depends(get_db),
):
    """Agent submits task execution results."""
    try:
        result = await agent_service.submit_task_result(
            db=db,
            agent_id=agent_id,
            task_id=task_id,
            status=payload.status,
            execution_time_ms=payload.execution_time_ms,
            findings_data=payload.findings_data,
            evidence_data=payload.evidence_data,
            raw_output=payload.raw_output,
            error_message=payload.error_message,
        )

        # Also trigger drift detection if baseline evidence data is present
        if payload.evidence_data and "baseline_snapshot" in payload.evidence_data:
            await baseline_drift_service.detect_drift(
                db=db,
                agent_id=agent_id,
                current_data=payload.evidence_data["baseline_snapshot"],
            )

        return {"result_id": result.id, "status": result.status.value}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ─── Cross-Plane Correlation Endpoint ────────────────────────────────────────

@router.get("/correlations/{project_id}", status_code=status.HTTP_200_OK)
async def get_cross_plane_correlations(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Analyze and retrieve cross-plane correlation between external exposure and endpoint posture."""
    correlations = await cross_plane_correlation.correlate_project_assets(
        db=db, project_id=project_id
    )
    return {"project_id": project_id, "correlations": correlations}
