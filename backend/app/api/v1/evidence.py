"""
Evidence Router
"""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
import structlog

from app.api.deps import CurrentUser, DbSession
from app.models import Evidence, Finding

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.get("")
async def list_evidence(
    current_user: CurrentUser,
    db: DbSession,
    finding_id: Optional[str] = Query(None),
    project_id: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
):
    query = select(Evidence)
    if finding_id:
        query = query.where(Evidence.finding_id == finding_id)
    elif project_id:
        # Join through finding
        query = query.join(Finding, Evidence.finding_id == Finding.id).where(
            Finding.project_id == project_id
        )
    query = query.order_by(Evidence.collected_at.desc()).limit(limit)

    result = await db.execute(query)
    evidence_list = result.scalars().all()

    return [
        {
            "id": e.id,
            "finding_id": e.finding_id,
            "http_method": e.http_method,
            "url": e.url,
            "request_headers": e.request_headers,
            "request_body": e.request_body,
            "response_status": e.response_status,
            "response_headers": e.response_headers,
            "response_body": e.response_body,
            "screenshot_path": e.screenshot_path,
            "screenshot_url": e.screenshot_url,
            "evidence_hash": e.evidence_hash,
            "agent_type": e.agent_type,
            "test_executed": e.test_executed,
            "collected_at": e.collected_at.isoformat(),
        }
        for e in evidence_list
    ]


@router.get("/{evidence_id}")
async def get_evidence(evidence_id: str, current_user: CurrentUser, db: DbSession):
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    return {
        "id": evidence.id,
        "finding_id": evidence.finding_id,
        "http_method": evidence.http_method,
        "url": evidence.url,
        "request_headers": evidence.request_headers,
        "request_body": evidence.request_body,
        "response_status": evidence.response_status,
        "response_headers": evidence.response_headers,
        "response_body": evidence.response_body,
        "screenshot_path": evidence.screenshot_path,
        "screenshot_url": evidence.screenshot_url,
        "dom_snapshot": evidence.dom_snapshot,
        "additional_data": evidence.additional_data,
        "evidence_hash": evidence.evidence_hash,
        "agent_type": evidence.agent_type,
        "test_executed": evidence.test_executed,
        "collected_at": evidence.collected_at.isoformat(),
    }
