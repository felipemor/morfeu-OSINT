from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, DbSession
from app.services.security_controls_service import security_controls_service

router = APIRouter()


class ControlTestRequest(BaseModel):
    control_id: str
    target_value: Optional[str] = None
    project_id: Optional[str] = None


class BatchControlTestRequest(BaseModel):
    category: Optional[str] = None
    target_value: Optional[str] = None
    project_id: Optional[str] = None


class SubdomainEnumRequest(BaseModel):
    domain: str


class LeakScanRequest(BaseModel):
    target_url: str


class AkamaiCheckRequest(BaseModel):
    target_url: str


class ReportPdfRequest(BaseModel):
    target_url: Optional[str] = "https://app.shieldsecurity.io"
    project_id: Optional[str] = None


@router.get("/overview", status_code=status.HTTP_200_OK)
async def get_controls_overview(
    current_user: CurrentUser,
    db: DbSession,
    project_id: Optional[str] = None,
    category: Optional[str] = None,
):
    """Retrieve external security controls and their validation states."""
    return await security_controls_service.get_controls_overview(
        db=db, project_id=project_id, category=category
    )


@router.post("/test", status_code=status.HTTP_200_OK)
async def test_security_control(
    payload: ControlTestRequest,
    current_user: CurrentUser,
    db: DbSession,
    request: Request,
):
    """Execute a real validation test for a specific external security control and write to AuditLog."""
    try:
        client_ip = request.client.host if request.client else "127.0.0.1"
        return await security_controls_service.execute_control_test(
            db=db,
            control_id=payload.control_id,
            target_value=payload.target_value,
            user_id=current_user.id,
            project_id=payload.project_id,
            ip_address=client_ip,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/test-all", status_code=status.HTTP_200_OK)
async def test_all_security_controls(
    payload: BatchControlTestRequest,
    current_user: CurrentUser,
    db: DbSession,
    request: Request,
):
    """Execute real validation tests across all external security controls and record audit trail."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    results = await security_controls_service.execute_all_controls_test(
        db=db,
        category=payload.category,
        target_value=payload.target_value,
        user_id=current_user.id,
        project_id=payload.project_id,
        ip_address=client_ip,
    )
    return {"results": results, "total_tested": len(results)}


@router.post("/subdomain-enum", status_code=status.HTTP_200_OK)
async def enumerate_subdomains_endpoint(
    payload: SubdomainEnumRequest,
    current_user: CurrentUser,
):
    """Enumerate subdomains and detect Akamai WAF presence on each discovered host."""
    return await security_controls_service.enumerate_subdomains(payload.domain)


@router.post("/leak-scan", status_code=status.HTTP_200_OK)
async def scan_sensitive_leaks_endpoint(
    payload: LeakScanRequest,
    current_user: CurrentUser,
):
    """Deep scan for sensitive leaked files, .git, dumps, and credentials exposure."""
    return await security_controls_service.scan_sensitive_leaks(payload.target_url)


@router.post("/akamai-check", status_code=status.HTTP_200_OK)
async def check_akamai_waf_endpoint(
    payload: AkamaiCheckRequest,
    current_user: CurrentUser,
):
    """Inspect and validate Akamai WAF headers, CNAME aliases, and edge protection."""
    return await security_controls_service.detect_akamai_waf(payload.target_url)


@router.post("/report/pdf")
async def generate_security_controls_pdf_report(
    payload: ReportPdfRequest,
    current_user: CurrentUser,
    db: DbSession,
):
    """
    Execute validation of all external security controls and return an executive
    & technical PDF validation report.
    """
    target_url = payload.target_url or "https://app.shieldsecurity.io"
    user_name = f"{current_user.name} ({current_user.email})" if hasattr(current_user, 'email') else "Security Auditor"

    pdf_bytes = await security_controls_service.generate_pdf_report(
        db=db,
        target_url=target_url,
        user_id=user_name,
        project_id=payload.project_id or "Corporate Perimeter",
    )

    filename = f"relatorio_validacao_controles_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


@router.get("/report/pdf")
async def download_security_controls_pdf_report_get(
    target_url: str = "https://app.shieldsecurity.io",
    current_user: CurrentUser = None,
    db: DbSession = None,
):
    """Direct GET download of the security controls PDF report."""
    user_name = current_user.name if current_user and hasattr(current_user, 'name') else "Security Auditor"
    pdf_bytes = await security_controls_service.generate_pdf_report(
        db=db,
        target_url=target_url,
        user_id=user_name,
    )
    filename = f"relatorio_validacao_controles_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )
