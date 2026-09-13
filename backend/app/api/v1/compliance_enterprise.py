"""
FastAPI Router — Enterprise GRC, Regulatory Frameworks (BACEN, PCI, CIS, NIST, ISO) & Audit Pack
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Dict, Any, List, Optional
from app.services.enterprise_compliance_service import EnterpriseComplianceService

router = APIRouter()


@router.get("/overview", summary="Get Compliance Overview & Framework Scores")
async def get_compliance_overview():
    """Returns compliance scores across BACEN Res. 4.893, PCI DSS v4, CIS Controls v8, NIST CSF 2.0, ISO 27001."""
    return EnterpriseComplianceService.get_compliance_overview()


@router.get("/controls", summary="List Master Security Controls Catalog")
async def list_controls():
    """Returns the central master security controls catalog (CTRL-*)."""
    overview = EnterpriseComplianceService.get_compliance_overview()
    return overview["controls_catalog"]


@router.post("/audit-pack/generate", summary="Generate Cryptographic Audit Pack")
async def generate_audit_pack(organization: Optional[str] = Query("Instituição Financeira S/A")):
    """Generates a complete, cryptographically verified Audit Pack data bundle for external auditors."""
    return EnterpriseComplianceService.generate_audit_pack(organization_name=organization)
