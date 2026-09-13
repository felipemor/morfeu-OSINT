"""
FastAPI Router — Multi-Plane Correlation, Business Risk Engine & Risk Acceptance
"""
from fastapi import APIRouter, HTTPException, Body
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from app.services.correlation_engine import EnterpriseCorrelationEngine

router = APIRouter()


class RiskCalculationRequest(BaseModel):
    severity: str
    cvss: float
    is_internet_facing: bool
    business_criticality: str
    is_production: bool = True
    has_compensating_control: bool = False
    sla_breached: bool = False


class RiskAcceptancePayload(BaseModel):
    finding_id: str
    title: str
    business_justification: str
    compensating_controls: str
    risk_level: str
    expiration_date: str


@router.get("/matrix", summary="Get Correlation Matrix & Active Chains")
async def get_correlation_matrix():
    """Returns multi-plane correlation map, entity links and active business risks."""
    return EnterpriseCorrelationEngine.get_correlation_matrix()


@router.post("/calculate-risk", summary="Calculate Dynamic Business Risk Score")
async def calculate_business_risk(payload: RiskCalculationRequest):
    """Calculates dynamic business risk score factoring technical severity, CVSS, exposure, criticality, and mitigations."""
    return EnterpriseCorrelationEngine.calculate_business_risk(
        severity=payload.severity,
        cvss=payload.cvss,
        is_internet_facing=payload.is_internet_facing,
        business_criticality=payload.business_criticality,
        is_production=payload.is_production,
        has_compensating_control=payload.has_compensating_control,
        sla_breached=payload.sla_breached
    )


@router.post("/risk-acceptance/request", summary="Submit Formal Risk Acceptance Request")
async def submit_risk_acceptance(payload: RiskAcceptancePayload):
    """Submits a formal risk acceptance request with justification, expiration, and compensating controls."""
    return {
        "acceptance_id": f"RA-2026-{payload.finding_id.replace('FND-', '')}",
        "status": "PENDING_APPROVAL",
        "message": "Solicitação formal de aceite de risco registrada e enviada para o Comitê de Segurança / CISO.",
        "payload": payload.model_dump(),
    }
