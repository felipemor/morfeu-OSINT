"""EASM Router — External Attack Surface Management with dark web coverage."""
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, desc

from app.api.deps import CurrentUser, DbSession
from app.models import EASMScan, EASMScanStatus, EASMDarkWebHit, EASMThreatLevel
from app.services import easm_service as svc

router = APIRouter()


class ScanRequest(BaseModel):
    target: str
    scan_type: str = "FULL"


@router.post("/scan", status_code=status.HTTP_200_OK)
async def start_easm_scan(body: ScanRequest, current_user: CurrentUser, db: DbSession):
    """
    Initiates a full EASM scan — CT logs, Shodan, HIBP, GitHub secrets,
    exposed services and dark web data breach lookup.
    """
    if not body.target or len(body.target.strip()) < 3:
        raise HTTPException(status_code=400, detail="Target domain is required.")

    # Create DB record
    scan = EASMScan(
        target=body.target,
        scan_type=body.scan_type,
        status=EASMScanStatus.RUNNING,
        initiated_by=current_user.id,
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    try:
        result = await svc.run_full_easm_scan(body.target, body.scan_type)

        # Persist dark web hits
        for hit in result.get("dark_web_hits", []):
            db.add(EASMDarkWebHit(
                scan_id=scan.id,
                source=hit.get("source", "Unknown"),
                hit_type=hit.get("hit_type", "CREDENTIAL_BREACH"),
                data_summary=hit.get("data_summary", ""),
                raw_data=hit,
                severity=_map_sev(hit.get("severity", "HIGH")),
                url=hit.get("url"),
            ))

        # Update scan record
        scan.status = EASMScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = result.get("summary", {})
        scan.threat_score = result.get("threat_score", 0.0)
        scan.assets_found = result.get("summary", {}).get("subdomains_found", 0)
        scan.dark_web_hits = result.get("summary", {}).get("dark_web_hits", 0)

        await db.commit()
        result["scan_id"] = scan.id
        return result

    except Exception as exc:
        scan.status = EASMScanStatus.FAILED
        await db.commit()
        raise HTTPException(status_code=500, detail=f"EASM scan failed: {exc}") from exc


@router.get("/scans", status_code=status.HTTP_200_OK)
async def list_scans(current_user: CurrentUser, db: DbSession, limit: int = 20):
    """List recent EASM scans."""
    res = await db.execute(select(EASMScan).order_by(desc(EASMScan.created_at)).limit(limit))
    scans = res.scalars().all()
    return [
        {
            "id": s.id, "target": s.target, "status": s.status.value,
            "threat_score": s.threat_score, "assets_found": s.assets_found,
            "dark_web_hits": s.dark_web_hits, "created_at": s.created_at.isoformat(),
        }
        for s in scans
    ]


@router.get("/scans/{scan_id}", status_code=status.HTTP_200_OK)
async def get_scan(scan_id: str, current_user: CurrentUser, db: DbSession):
    """Get EASM scan details with dark web hits."""
    res = await db.execute(select(EASMScan).where(EASMScan.id == scan_id))
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    hits_res = await db.execute(
        select(EASMDarkWebHit).where(EASMDarkWebHit.scan_id == scan_id)
    )
    hits = hits_res.scalars().all()

    return {
        "id": scan.id,
        "target": scan.target,
        "status": scan.status.value,
        "threat_score": scan.threat_score,
        "summary": scan.summary,
        "assets_found": scan.assets_found,
        "dark_web_hits": [
            {"source": h.source, "hit_type": h.hit_type,
             "severity": h.severity.value, "data_summary": h.data_summary,
             "url": h.url, "discovered_at": h.discovered_at.isoformat()}
            for h in hits
        ],
        "created_at": scan.created_at.isoformat(),
    }


@router.get("/dark-web/hits", status_code=status.HTTP_200_OK)
async def list_dark_web_hits(current_user: CurrentUser, db: DbSession, limit: int = 50):
    """List all dark web hits across all EASM scans."""
    res = await db.execute(
        select(EASMDarkWebHit).order_by(desc(EASMDarkWebHit.discovered_at)).limit(limit)
    )
    hits = res.scalars().all()
    return [
        {"id": h.id, "scan_id": h.scan_id, "source": h.source,
         "hit_type": h.hit_type, "severity": h.severity.value,
         "data_summary": h.data_summary, "url": h.url,
         "discovered_at": h.discovered_at.isoformat()}
        for h in hits
    ]


def _map_sev(s: str) -> EASMThreatLevel:
    return {
        "CRITICAL": EASMThreatLevel.CRITICAL,
        "HIGH":     EASMThreatLevel.HIGH,
        "MEDIUM":   EASMThreatLevel.MEDIUM,
        "LOW":      EASMThreatLevel.LOW,
    }.get(s.upper(), EASMThreatLevel.HIGH)
