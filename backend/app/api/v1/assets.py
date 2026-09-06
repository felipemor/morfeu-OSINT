"""
Assets and Endpoints Router
"""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import select, func
import structlog

from app.api.deps import CurrentUser, DbSession
from app.models import Asset, Endpoint, AssetType

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.get("/{project_id}/assets")
async def list_assets(
    project_id: str,
    current_user: CurrentUser,
    db: DbSession,
    asset_type: Optional[AssetType] = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
):
    """List all discovered assets for a project."""
    query = select(Asset).where(Asset.project_id == project_id)
    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
    query = query.order_by(Asset.discovered_at.desc()).limit(limit).offset(offset)

    result = await db.execute(query)
    assets = result.scalars().all()

    return [
        {
            "id": a.id,
            "type": a.asset_type.value,
            "value": a.value,
            "ip_address": a.ip_address,
            "port": a.port,
            "protocol": a.protocol,
            "status_code": a.status_code,
            "title": a.title,
            "server": a.server,
            "technologies": a.technologies,
            "is_internet_facing": a.is_internet_facing,
            "business_criticality": a.business_criticality.value,
            "screenshot_path": a.screenshot_path,
            "discovered_at": a.discovered_at.isoformat(),
        }
        for a in assets
    ]


@router.get("/{project_id}/endpoints")
async def list_endpoints(
    project_id: str,
    current_user: CurrentUser,
    db: DbSession,
    is_api: Optional[bool] = Query(None),
    limit: int = Query(200, le=2000),
    offset: int = Query(0),
):
    """List all discovered endpoints for a project."""
    query = select(Endpoint).where(Endpoint.project_id == project_id)
    if is_api is not None:
        query = query.where(Endpoint.is_api == is_api)
    query = query.order_by(Endpoint.discovered_at.desc()).limit(limit).offset(offset)

    result = await db.execute(query)
    endpoints = result.scalars().all()

    return [
        {
            "id": e.id,
            "url": e.url,
            "method": e.method,
            "path": e.path,
            "parameters": e.parameters,
            "auth_required": e.auth_required,
            "auth_type": e.auth_type,
            "content_type": e.content_type,
            "status_code": e.status_code,
            "is_api": e.is_api,
            "source": e.source,
            "discovered_at": e.discovered_at.isoformat(),
        }
        for e in endpoints
    ]


@router.get("/{project_id}/attack-surface")
async def get_attack_surface(project_id: str, current_user: CurrentUser, db: DbSession):
    """Get attack surface data for graph visualization."""
    assets_result = await db.execute(
        select(Asset).where(Asset.project_id == project_id)
    )
    assets = assets_result.scalars().all()

    endpoints_result = await db.execute(
        select(Endpoint).where(Endpoint.project_id == project_id).limit(500)
    )
    endpoints = endpoints_result.scalars().all()

    from app.models import Finding, Severity
    findings_result = await db.execute(
        select(Finding).where(
            Finding.project_id == project_id,
            Finding.is_false_positive == False,
        )
    )
    findings = findings_result.scalars().all()

    # Build graph nodes and edges
    nodes = []
    edges = []

    # Root node
    nodes.append({"id": "internet", "label": "Internet", "type": "root", "level": 0})

    for asset in assets:
        nodes.append({
            "id": f"asset_{asset.id}",
            "label": asset.value,
            "type": asset.asset_type.value,
            "level": 1,
            "technologies": asset.technologies,
            "ip": asset.ip_address,
            "criticality": asset.business_criticality.value,
        })
        edges.append({"from": "internet", "to": f"asset_{asset.id}"})

    for endpoint in endpoints[:200]:  # Limit graph size
        nodes.append({
            "id": f"ep_{endpoint.id}",
            "label": f"{endpoint.method} {endpoint.path}",
            "type": "endpoint",
            "level": 2,
            "is_api": endpoint.is_api,
        })
        edges.append({"from": f"asset_{endpoint.asset_id}", "to": f"ep_{endpoint.id}"})

    severity_colors = {
        "CRITICAL": "#ff0000",
        "HIGH": "#ff6600",
        "MEDIUM": "#ffaa00",
        "LOW": "#ffff00",
        "INFO": "#00aaff",
    }

    for finding in findings:
        nodes.append({
            "id": f"finding_{finding.id}",
            "label": finding.title,
            "type": "finding",
            "level": 3,
            "severity": finding.severity.value,
            "color": severity_colors.get(finding.severity.value, "#gray"),
            "confidence": finding.confidence,
        })
        if finding.endpoint_id:
            edges.append({"from": f"ep_{finding.endpoint_id}", "to": f"finding_{finding.id}"})
        elif finding.asset_id:
            edges.append({"from": f"asset_{finding.asset_id}", "to": f"finding_{finding.id}"})

    return {"nodes": nodes, "edges": edges}
