"""
OSINT API Router — Open Source Intelligence Reconnaissance Endpoints
"""
from typing import Optional
from fastapi import APIRouter, HTTPException, status, Request
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession
from app.services.osint_service import osint_service
from app.models import AuditLog, Finding, Severity, FindingStatus, Project, User, UserRole

router = APIRouter()


class OSINTScanRequest(BaseModel):
    target: str


async def _get_or_create_default_project(db: DbSession) -> Project:
    """Helper to retrieve an active project or auto-create a default project for findings."""
    res = await db.execute(select(Project).limit(1))
    proj = res.scalar_one_or_none()
    if not proj:
        user_res = await db.execute(select(User).limit(1))
        owner = user_res.scalar_one_or_none()
        if not owner:
            owner = User(
                id="user-001",
                email="felipe_c@myyahoo.com",
                full_name="Felipe Costa",
                hashed_password="transient_hash",
                role=UserRole.ADMIN,
                is_active=True
            )
            db.add(owner)
            await db.commit()
            await db.refresh(owner)

        proj = Project(
            name="Default Enterprise Pentest Scope",
            description="Auto-generated project for OSINT, Mobile and Security Controls Findings",
            owner_id=owner.id,
            status="SCANNING"
        )
        db.add(proj)
        await db.commit()
        await db.refresh(proj)
    return proj


@router.post("/scan", status_code=status.HTTP_200_OK)
async def run_osint_investigation(
    payload: OSINTScanRequest,
    current_user: CurrentUser,
    db: DbSession,
):
    """
    Executes a complete professional OSINT reconnaissance scan against the target domain,
    logging audit entries and registering discovered vulnerabilities in Findings.
    """
    if not payload.target or len(payload.target.strip()) < 3:
        raise HTTPException(status_code=400, detail="Target domain is required.")

    result = await osint_service.run_full_osint_investigation(payload.target)

    # 1. Log action to AuditLog
    try:
        user_id_val = getattr(current_user, "id", None)
        audit_entry = AuditLog(
            user_id=user_id_val,
            action="OSINT_RECONNAISSANCE_SCAN",
            resource_type="DOMAIN",
            resource_id=payload.target,
            details={
                "target": payload.target,
                "threat_exposure_score": result.get("threat_exposure_score"),
                "threat_level": result.get("threat_level"),
                "findings_count": len(result.get("discovered_findings", []))
            },
            result="SUCCESS"
        )
        db.add(audit_entry)
        await db.commit()
        result["audit_logged"] = True
        result["audit_id"] = audit_entry.id
    except Exception as e:
        await db.rollback()
        result["audit_logged"] = False

    # 2. Register Discovered Risks into Findings Governance
    registered_findings_count = 0
    try:
        proj = await _get_or_create_default_project(db)

        for f_dict in result.get("discovered_findings", []):
            raw_sev = str(f_dict.get("severity", "MEDIUM")).upper()
            sev_enum = Severity.HIGH if raw_sev == "HIGH" else Severity.CRITICAL if raw_sev == "CRITICAL" else Severity.MEDIUM
            
            # Check if finding title exists for this project
            res_ex = await db.execute(
                select(Finding).where(
                    Finding.project_id == proj.id,
                    Finding.title == f_dict.get("title")
                )
            )
            existing = res_ex.scalar_one_or_none()
            if not existing:
                new_finding = Finding(
                    project_id=proj.id,
                    title=f_dict.get("title"),
                    severity=sev_enum,
                    status=FindingStatus.OPEN,
                    owasp_category=f_dict.get("owasp_category", "OSINT_RECON"),
                    cwe_id=f_dict.get("cwe_id", "CWE-200"),
                    cvss_score=float(f_dict.get("cvss_score", 5.0)),
                    affected_asset=f_dict.get("affected_asset", payload.target),
                    description=f_dict.get("description", "Vulnerabilidade descoberta via varredura OSINT"),
                    recommendation=f_dict.get("recommendation", "Remediar exposição no DNS / Perímetro"),
                    discovered_by="OSINT Reconnaissance Engine"
                )
                db.add(new_finding)
                registered_findings_count += 1

        if registered_findings_count > 0:
            await db.commit()
    except Exception as e:
        await db.rollback()

    result["findings_registered_count"] = registered_findings_count

    return result


@router.post("/dns", status_code=status.HTTP_200_OK)
async def query_dns_intelligence(
    payload: OSINTScanRequest,
    current_user: CurrentUser,
):
    """Quick DNS zone records reconnaissance."""
    return await osint_service.get_dns_intelligence(payload.target)


@router.post("/certs", status_code=status.HTTP_200_OK)
async def query_certificate_transparency(
    payload: OSINTScanRequest,
    current_user: CurrentUser,
):
    """Certificate Transparency (CT Logs) & historical subdomains discovery."""
    return await osint_service.get_certificate_transparency(payload.target)


