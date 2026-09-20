"""BIN Monitor Router — card-testing velocity tracking and BIN attack defense."""
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, desc
from typing import Optional, List

from app.api.deps import CurrentUser, DbSession
from app.models import BINIncident
from app.services import bin_monitor_service as svc

router = APIRouter()


class AnalyzeRequest(BaseModel):
    bin_prefix: str
    window_minutes: Optional[int] = 1
    transactions: Optional[List[dict]] = None


class MitigateRequest(BaseModel):
    action: str  # "BLOCK_SUBNET", "ENFORCE_3DS", "POW_CHALLENGE", "RESOLVE"
    notes: Optional[str] = None


@router.post("/analyze", status_code=status.HTTP_200_OK)
async def analyze_bin(body: AnalyzeRequest, current_user: CurrentUser, db: DbSession):
    """
    Analyzes transaction stream for BIN attack patterns.
    Computes velocity spikes, decline rate anomalies, and IP concentration.
    """
    if not body.bin_prefix or len(body.bin_prefix.strip()) < 4:
        raise HTTPException(status_code=400, detail="bin_prefix deve conter pelo menos 4 dígitos.")

    prefix = body.bin_prefix.strip()[:6]
    result = svc.analyze_bin_telemetry(
        bin_prefix=prefix,
        transactions=body.transactions,
        window_minutes=body.window_minutes or 1,
    )

    if result.get("is_active_attack"):
        incident = BINIncident(
            bin_prefix=prefix,
            bank_name=result.get("bin_info", {}).get("bank"),
            card_brand=result.get("bin_info", {}).get("brand"),
            attempts_per_minute=result.get("metrics", {}).get("attempts_per_minute", 0.0),
            decline_rate=result.get("metrics", {}).get("decline_rate_pct", 0.0) / 100.0,
            source_ips=result.get("source_ips", []),
            merchants_affected=result.get("merchants_affected", []),
            severity=result.get("severity", "HIGH"),
            is_active=True,
            mitigation_applied="NONE",
        )
        db.add(incident)
        await db.commit()
        await db.refresh(incident)
        result["incident_id"] = incident.id

    return result


@router.get("/incidents", status_code=status.HTTP_200_OK)
async def list_incidents(current_user: CurrentUser, db: DbSession, limit: int = 50, active_only: bool = True):
    """List detected BIN attack incidents."""
    q = select(BINIncident).order_by(desc(BINIncident.detected_at)).limit(limit)
    if active_only:
        q = q.where(BINIncident.is_active == True)  # noqa: E712
    res = await db.execute(q)
    incidents = res.scalars().all()

    if not incidents and active_only:
        simulated = svc.get_active_incidents(limit=limit)
        return simulated

    return [
        {
            "id": inc.id,
            "bin_prefix": inc.bin_prefix,
            "bank_name": inc.bank_name,
            "card_brand": inc.card_brand,
            "attempts_per_minute": inc.attempts_per_minute,
            "decline_rate_pct": round(inc.decline_rate * 100, 1),
            "severity": inc.severity,
            "is_active": inc.is_active,
            "mitigation_applied": inc.mitigation_applied,
            "source_ips": inc.source_ips,
            "merchants_affected": inc.merchants_affected,
            "detected_at": inc.detected_at.isoformat(),
            "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
        }
        for inc in incidents
    ]


@router.post("/incidents/{incident_id}/mitigate", status_code=status.HTTP_200_OK)
async def apply_mitigation(incident_id: str, body: MitigateRequest, current_user: CurrentUser, db: DbSession):
    """Apply defense mitigation to an active BIN attack incident."""
    res = await db.execute(select(BINIncident).where(BINIncident.id == incident_id))
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    incident.mitigation_applied = body.action
    if body.action == "RESOLVE":
        incident.is_active = False
        incident.resolved_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(incident)
    return {
        "id": incident.id,
        "status": "MITIGATED",
        "mitigation": incident.mitigation_applied,
        "is_active": incident.is_active,
    }
