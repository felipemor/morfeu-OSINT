"""
FRAUDINTEL — FastAPI Router
REST APIs for Cases, Ingestion, Digital Asset Analyzer, Boleto, Fraud Graph, AI Investigator, Takedown & Reports.
"""

from fastapi import APIRouter, HTTPException, Depends, Body
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from .case_service import case_service
from .risk_engine import risk_engine
from .correlation_engine import correlation_engine
from .fraud_graph_service import fraud_graph_service
from .ai_investigator import ai_investigator
from .boleto_analyzer import boleto_analyzer
from .takedown_tracker import takedown_tracker
from .seed_data import DETECTION_RULES_CATALOG, WATCHLISTS_DATASET

router = APIRouter(prefix="/api/v1/fraudintel", tags=["Fraud Intelligence Platform (FRAUDINTEL)"])

# ── REQUEST SCHEMAS ──────────────────────────────────────────────────────────

class AnalyzeUrlRequest(BaseModel):
    url: str
    brand_victim: Optional[str] = "Marca Corporativa"
    auto_create_case: Optional[bool] = True

class AnalyzeBoletoRequest(BaseModel):
    linha_digitavel: Optional[str] = ""
    codigo_barras: Optional[str] = ""
    beneficiario_esperado: Optional[str] = "Empresa Credora S.A."
    beneficiario_declarado: Optional[str] = ""
    cnpj_declarado: Optional[str] = ""
    valor_declarado: Optional[float] = 1480.00

class TakedownDispatchRequest(BaseModel):
    target_url_or_domain: str
    case_id: Optional[str] = "FRD-2026-0001"
    evidence_bundle: Optional[Dict[str, Any]] = None

class UpdateCaseStatusRequest(BaseModel):
    status: str

# ── ENDPOINTS ────────────────────────────────────────────────────────────────

@router.get("/dashboard")
async def get_dashboard():
    """Returns Executive KPIs and summary metrics for the Fraud Intelligence Platform."""
    return case_service.get_dashboard_kpis()

@router.get("/cases")
async def list_cases(status: Optional[str] = None, severity: Optional[str] = None, query: Optional[str] = None):
    """Lists fraud investigation cases with optional filtering."""
    return case_service.list_cases(status=status, severity=severity, query=query)

@router.get("/cases/{case_id}")
async def get_case(case_id: str):
    """Fetches details, timeline, findings, hypotheses, and evidence for a specific case."""
    c = case_service.get_case_by_id(case_id)
    if not c:
        raise HTTPException(status_code=404, detail=f"Case #{case_id} not found.")
    return c

@router.post("/cases/{case_id}/status")
async def update_status(case_id: str, body: UpdateCaseStatusRequest):
    """Updates case status (NEW, TRIAGE, INVESTIGATING, ESCALATED, RESOLVED, CLOSED)."""
    c = case_service.update_case_status(case_id, body.status)
    if not c:
        raise HTTPException(status_code=404, detail=f"Case #{case_id} not found.")
    return c

@router.post("/analyze/url")
async def analyze_url(body: AnalyzeUrlRequest):
    """
    Ingests and analyzes a suspicious URL/domain.
    Extracts brand similarity, calculates explainable risk, correlates infrastructure, and generates AI insights.
    """
    new_case = await case_service.create_case_from_url(
        url=body.url,
        brand=body.brand_victim or "Marca Corporativa"
    )
    return new_case

@router.post("/analyze/boleto")
async def analyze_boleto(body: AnalyzeBoletoRequest):
    """
    Parses FEBRABAN barcode / linha digitável, detects beneficiary mismatch, and calculates fraud risk.
    """
    res = boleto_analyzer.analyze_boleto(
        linha_digitavel=body.linha_digitavel,
        codigo_barras=body.codigo_barras,
        beneficiario_esperado=body.beneficiario_esperado,
        beneficiario_declarado=body.beneficiario_declarado,
        cnpj_declarado=body.cnpj_declarado,
        valor_declarado=body.valor_declarado
    )
    return res

@router.get("/cases/{case_id}/graph")
async def get_fraud_graph(case_id: str):
    """Builds interactive Fraud Graph with typed nodes and edges for the specified case."""
    c = case_service.get_case_by_id(case_id)
    if not c:
        raise HTTPException(status_code=404, detail=f"Case #{case_id} not found.")
    return fraud_graph_service.build_case_graph(c)

@router.post("/cases/{case_id}/ai-investigate")
async def run_ai_investigation(case_id: str, custom_query: Optional[str] = Body(default="", embed=True)):
    """Runs the AI Investigator engine with strict anti-hallucination guardrails and evidence citation."""
    c = case_service.get_case_by_id(case_id)
    if not c:
        raise HTTPException(status_code=404, detail=f"Case #{case_id} not found.")
    res = await ai_investigator.analyze_case(c, custom_query=custom_query or "")
    return res

@router.post("/takedown/dispatch")
async def dispatch_takedown(body: TakedownDispatchRequest):
    """
    Dispatches multichannel takedown reports and activates the real-time SLA countdown stopwatch.
    """
    res = await takedown_tracker.dispatch_takedown(
        target_url_or_domain=body.target_url_or_domain,
        case_id=body.case_id or "FRD-2026-0001",
        evidence_bundle=body.evidence_bundle
    )
    # Update case takedown state if case exists
    c = case_service.get_case_by_id(body.case_id)
    if c:
        c["takedown"] = res
        c["status"] = "ESCALATED"
        c["timeline"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": f"Takedown despachado para {body.target_url_or_domain} com SLA de neutralização de 24h."
        })
    case_service.log_audit("TAKEDOWN_DISPATCHED", "Takedown", body.case_id or "UNKNOWN", {"target": body.target_url_or_domain})
    return res

@router.get("/takedown/probe-live")
async def probe_takedown(domain: str):
    """
    Real-time live probe to verify if the domain is still resolving or has been suspended (NXDOMAIN).
    """
    return await takedown_tracker.probe_takedown_live_status(domain)

@router.get("/rules")
async def list_rules():
    """Returns the catalog of active detection rules."""
    return DETECTION_RULES_CATALOG

@router.get("/watchlists")
async def list_watchlists():
    """Returns continuous monitoring watchlists."""
    return WATCHLISTS_DATASET

@router.get("/audit-logs")
async def get_audit_logs(limit: int = 100):
    """Returns append-only immutable audit trail for forensic compliance."""
    return case_service.get_audit_logs(limit=limit)
