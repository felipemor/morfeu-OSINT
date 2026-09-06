"""
Topology & Reasoning API Router — Attack Surface Graph, Hypotheses, Compliance
"""
from typing import Optional, Any
from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select
from app.api.deps import CurrentUser, DbSession
from app.models import SecurityHypothesis
from app.services.attack_surface import AttackSurfaceService
from app.services.compliance import ComplianceService
from app.services.evidence_service import EvidenceService

router = APIRouter()


@router.get("/{project_id}/attack-surface/graph")
async def get_attack_surface_graph(
    project_id: str,
    current_user: CurrentUser,
    db: DbSession,
):
    """Returns the full node-edge attack surface graph for visual exploration."""
    svc = AttackSurfaceService(db)
    return await svc.get_attack_surface_graph(project_id)


@router.get("/{project_id}/attack-surface/exposed")
async def get_exposed_assets(
    project_id: str,
    current_user: CurrentUser,
    db: DbSession,
):
    """Returns internet-exposed assets."""
    svc = AttackSurfaceService(db)
    return await svc.get_exposed_assets(project_id)


@router.get("/{project_id}/hypotheses")
async def get_project_hypotheses(
    project_id: str,
    current_user: CurrentUser,
    db: DbSession,
):
    """Returns AI-formulated security hypotheses with explainable reasoning."""
    res = await db.execute(
        select(SecurityHypothesis)
        .where(SecurityHypothesis.project_id == project_id)
        .order_by(SecurityHypothesis.created_at.desc())
    )
    return res.scalars().all()


@router.get("/{project_id}/compliance")
async def get_project_compliance(
    project_id: str,
    current_user: CurrentUser,
    db: DbSession,
):
    """Returns compliance framework alignment (OWASP, CIS, NIST, ISO 27001)."""
    svc = ComplianceService(db)
    return await svc.get_project_compliance_summary(project_id)


@router.get("/scans/{scan_id}/timeline")
async def get_scan_timeline(
    scan_id: str,
    current_user: CurrentUser,
    db: DbSession,
):
    """Returns the visual pentest timeline."""
    svc = EvidenceService(db)
    return await svc.get_pentest_timeline(scan_id)
