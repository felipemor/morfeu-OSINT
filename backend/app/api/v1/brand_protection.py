"""Brand Protection Router — typosquatting, takedown, and abuse monitoring."""
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, desc
from typing import Optional

from app.api.deps import CurrentUser, DbSession
from app.models import BrandAlert, BrandAlertType, BrandAlertStatus
from app.services import brand_protection_service as svc

router = APIRouter()


class MonitorRequest(BaseModel):
    brand_domain: str
    scan_depth: str = "FULL"


class TakedownRequest(BaseModel):
    domain: str
    brand: str
    alert_id: Optional[str] = None
    evidence: dict = {}


@router.post("/monitor", status_code=status.HTTP_200_OK)
async def monitor_brand(body: MonitorRequest, current_user: CurrentUser, db: DbSession):
    """
    Scan for typosquatting, homoglyph, combosquatting and phishing clones
    of the given brand domain. Returns prioritized threat list.
    """
    if not body.brand_domain or len(body.brand_domain) < 3:
        raise HTTPException(status_code=400, detail="brand_domain is required.")

    result = await svc.monitor_brand(body.brand_domain, body.scan_depth)

    # Persist alerts
    for alert in result.get("alerts", [])[:20]:  # persist top 20
        db.add(BrandAlert(
            brand=body.brand_domain,
            suspicious_domain=alert.get("suspicious_domain", ""),
            alert_type=_map_alert_type(alert.get("alert_type", "TYPOSQUATTING")),
            similarity_score=alert.get("similarity_score", 0.0),
            registrar=alert.get("registrar"),
            registered_at=alert.get("registered_at"),
            ip_address=alert.get("ip_address"),
            hosting_provider=alert.get("hosting_provider"),
            status=BrandAlertStatus.OPEN,
            evidence=alert.get("evidence", {}),
        ))

    await db.commit()
    return result


@router.get("/alerts", status_code=status.HTTP_200_OK)
async def list_alerts(current_user: CurrentUser, db: DbSession, limit: int = 50, brand: Optional[str] = None):
    """List brand protection alerts, optionally filtered by brand."""
    q = select(BrandAlert).order_by(desc(BrandAlert.created_at)).limit(limit)
    if brand:
        q = q.where(BrandAlert.brand.ilike(f"%{brand}%"))
    res = await db.execute(q)
    alerts = res.scalars().all()
    return [
        {
            "id": a.id, "brand": a.brand, "suspicious_domain": a.suspicious_domain,
            "alert_type": a.alert_type.value, "similarity_score": a.similarity_score,
            "status": a.status.value, "registrar": a.registrar, "ip_address": a.ip_address,
            "hosting_provider": a.hosting_provider, "created_at": a.created_at.isoformat(),
        }
        for a in alerts
    ]


@router.post("/takedown", status_code=status.HTTP_200_OK)
async def send_takedown(body: TakedownRequest, current_user: CurrentUser, db: DbSession):
    """Submit takedown reports to registrar, Cloudflare, Google SafeBrowsing, and Abuse.ch."""
    if not body.domain:
        raise HTTPException(status_code=400, detail="domain is required.")

    result = await svc.send_takedown(body.domain, body.evidence)

    # Update alert status if alert_id provided
    if body.alert_id:
        res = await db.execute(select(BrandAlert).where(BrandAlert.id == body.alert_id))
        alert = res.scalar_one_or_none()
        if alert:
            alert.status = BrandAlertStatus.REPORTED
            alert.takedown_sent_at = datetime.now(timezone.utc)
            await db.commit()

    return result


@router.patch("/alerts/{alert_id}/status", status_code=status.HTTP_200_OK)
async def update_alert_status(
    alert_id: str,
    current_user: CurrentUser,
    db: DbSession,
    new_status: str = "FALSE_POSITIVE",
):
    """Update alert status: OPEN | REPORTED | TAKEN_DOWN | FALSE_POSITIVE"""
    res = await db.execute(select(BrandAlert).where(BrandAlert.id == alert_id))
    alert = res.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    valid = {"OPEN", "REPORTED", "TAKEN_DOWN", "FALSE_POSITIVE"}
    if new_status not in valid:
        raise HTTPException(status_code=400, detail=f"Status must be one of {valid}")

    alert.status = BrandAlertStatus(new_status)
    await db.commit()
    return {"id": alert_id, "status": new_status, "updated_at": datetime.now(timezone.utc).isoformat()}


def _map_alert_type(s: str) -> BrandAlertType:
    return {
        "TYPOSQUATTING":  BrandAlertType.TYPOSQUATTING,
        "HOMOGLYPH":      BrandAlertType.HOMOGLYPH,
        "COMBOSQUATTING": BrandAlertType.COMBOSQUATTING,
        "PHISHING_PAGE":  BrandAlertType.PHISHING_PAGE,
        "AD_HIJACK":      BrandAlertType.AD_HIJACK,
        "FAKE_APP":       BrandAlertType.FAKE_APP,
    }.get(s, BrandAlertType.TYPOSQUATTING)
