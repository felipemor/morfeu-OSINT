"""Fiscal Forensic AI Router — Endpoints for datasets, audit execution, findings, graph, copilot, and reports."""
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, File, HTTPException, Response, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import desc, select

from app.api.deps import CurrentUser, DbSession
from app.models import FiscalCase, FiscalDataset, FiscalEvidence, FiscalFinding
from app.services.fiscal import (
    FiscalCopilotService,
    FiscalPipelineOrchestrator,
    FiscalReportGenerator,
    SyntheticFiscalDataGenerator,
)

router = APIRouter()

# In-memory cached active audit result for instant local access and demo
_ACTIVE_AUDIT_CACHE: Dict[str, Any] = {}


class SeedRequest(BaseModel):
    record_count: Optional[int] = 1000


class CopilotQueryRequest(BaseModel):
    query: str
    dataset_id: Optional[str] = None


class FindingReviewRequest(BaseModel):
    status: str  # CONFIRMED, FALSE_POSITIVE, UNDER_REVIEW, RESOLVED
    notes: Optional[str] = None


class CreateCaseRequest(BaseModel):
    title: str
    description: Optional[str] = None
    finding_ids: Optional[List[str]] = None
    priority: Optional[str] = "HIGH"


@router.post("/demo/seed", status_code=status.HTTP_200_OK)
async def seed_demo_audit(body: Optional[SeedRequest] = None):
    """
    Generates a realistic synthetic fiscal dataset with deliberate anomalies
    and executes the complete forensic audit pipeline.
    """
    count = body.record_count if body and body.record_count else 1000
    records, meta = SyntheticFiscalDataGenerator.generate_dataset(count=count)

    result = FiscalPipelineOrchestrator.execute_audit(
        raw_rows=records,
        dataset_name=meta.get("dataset_name", "Auditoria Fiscal Demo"),
        source_filename="relatorio_fiscal_sintetico.xlsx",
    )

    _ACTIVE_AUDIT_CACHE["latest"] = result
    _ACTIVE_AUDIT_CACHE[result["dataset_id"]] = result

    return result


@router.get("/latest", status_code=status.HTTP_200_OK)
async def get_latest_audit():
    """Returns the most recent audit results (or seeds one if empty)."""
    if "latest" not in _ACTIVE_AUDIT_CACHE:
        records, meta = SyntheticFiscalDataGenerator.generate_dataset(count=1000)
        result = FiscalPipelineOrchestrator.execute_audit(
            raw_rows=records,
            dataset_name=meta.get("dataset_name", "Auditoria Fiscal Demo"),
            source_filename="relatorio_fiscal_sintetico.xlsx",
        )
        _ACTIVE_AUDIT_CACHE["latest"] = result
        _ACTIVE_AUDIT_CACHE[result["dataset_id"]] = result

    return _ACTIVE_AUDIT_CACHE["latest"]


@router.post("/datasets/upload", status_code=status.HTTP_200_OK)
async def upload_dataset(file: UploadFile = File(...)):
    """Uploads a fiscal file (CSV, JSON, XLSX) and returns the smart schema preview."""
    content = await file.read()
    filename = file.filename or "uploaded_dataset.csv"

    raw_rows: List[Dict[str, Any]] = []
    if filename.endswith(".json"):
        try:
            data = json.loads(content.decode("utf-8"))
            raw_rows = data if isinstance(data, list) else data.get("records", [])
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"JSON inválido: {str(e)}")
    else:
        # Fallback CSV parsing
        try:
            import csv
            lines = content.decode("utf-8", errors="ignore").splitlines()
            reader = csv.DictReader(lines)
            raw_rows = [row for row in reader]
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Erro ao processar arquivo: {str(e)}")

    if not raw_rows:
        raise HTTPException(status_code=400, detail="Arquivo vazio ou formato não suportado.")

    result = FiscalPipelineOrchestrator.execute_audit(
        raw_rows=raw_rows,
        dataset_name=filename.split(".")[0],
        source_filename=filename,
    )
    _ACTIVE_AUDIT_CACHE["latest"] = result
    _ACTIVE_AUDIT_CACHE[result["dataset_id"]] = result

    return result


@router.get("/findings", status_code=status.HTTP_200_OK)
async def list_findings(severity: Optional[str] = None, category: Optional[str] = None):
    """Lists audit findings with optional severity and category filtering."""
    audit = _ACTIVE_AUDIT_CACHE.get("latest")
    if not audit:
        audit = await get_latest_audit()

    findings = audit.get("findings", [])
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if category:
        findings = [f for f in findings if f.get("category") == category]

    return findings


@router.get("/findings/{finding_id}", status_code=status.HTTP_200_OK)
async def get_finding(finding_id: str):
    """Returns details, explanation, and evidence for a specific finding."""
    audit = _ACTIVE_AUDIT_CACHE.get("latest")
    if not audit:
        audit = await get_latest_audit()

    for f in audit.get("findings", []):
        if f.get("id") == finding_id or f.get("rule_code") == finding_id:
            return f

    raise HTTPException(status_code=404, detail="Finding not found.")


@router.post("/findings/{finding_id}/review", status_code=status.HTTP_200_OK)
async def review_finding(finding_id: str, body: FindingReviewRequest):
    """Auditor reviews finding (Confirms, marks False Positive, or adds notes)."""
    audit = _ACTIVE_AUDIT_CACHE.get("latest")
    if not audit:
        audit = await get_latest_audit()

    for f in audit.get("findings", []):
        if f.get("id") == finding_id or f.get("rule_code") == finding_id:
            f["status"] = body.status
            if body.notes:
                f["auditor_notes"] = body.notes
            return f

    raise HTTPException(status_code=404, detail="Finding not found.")


@router.get("/entities/graph", status_code=status.HTTP_200_OK)
async def get_entity_graph():
    """Returns the forensic entity node-link graph for interactive visualization."""
    audit = _ACTIVE_AUDIT_CACHE.get("latest")
    if not audit:
        audit = await get_latest_audit()

    return audit.get("network_graph", {})


@router.get("/cases", status_code=status.HTTP_200_OK)
async def list_cases():
    """Lists forensic audit cases."""
    audit = _ACTIVE_AUDIT_CACHE.get("latest")
    if not audit:
        audit = await get_latest_audit()

    return audit.get("cases", [])


@router.post("/cases", status_code=status.HTTP_201_CREATED)
async def create_case(body: CreateCaseRequest):
    """Creates a new audit investigation case."""
    audit = _ACTIVE_AUDIT_CACHE.get("latest")
    if not audit:
        audit = await get_latest_audit()

    all_findings = audit.get("findings", [])
    selected = [f for f in all_findings if f.get("id") in (body.finding_ids or [])] if body.finding_ids else all_findings

    new_case = {
        "id": f"case-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "case_number": f"CASE-{datetime.now().year}-{datetime.now().strftime('%H%M%S')}",
        "title": body.title,
        "description": body.description or "",
        "status": "OPEN",
        "priority": body.priority or "HIGH",
        "financial_exposure": sum(f.get("financial_exposure", 0.0) for f in selected),
        "findings_count": len(selected),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    audit.setdefault("cases", []).append(new_case)
    return new_case


@router.post("/copilot/query", status_code=status.HTTP_200_OK)
async def query_copilot(body: CopilotQueryRequest):
    """Interactively queries the Fiscal Auditor Copilot."""
    audit = _ACTIVE_AUDIT_CACHE.get("latest")
    if not audit:
        audit = await get_latest_audit()

    return FiscalCopilotService.answer_query(
        query=body.query,
        dataset_meta={"name": audit.get("dataset_name")},
        findings=audit.get("findings", []),
        risk_profile=audit.get("risk_profile", {}),
        hhi_data=audit.get("hhi_data", {}),
        stats_summary=audit.get("stats_summary", {}),
    )


@router.get("/reports/pdf")
async def download_pdf_report():
    """Generates and downloads the official 18-section forensic PDF report."""
    audit = _ACTIVE_AUDIT_CACHE.get("latest")
    if not audit:
        audit = await get_latest_audit()

    pdf_bytes = FiscalReportGenerator.generate_pdf_report(
        dataset_meta={"name": audit.get("dataset_name")},
        quality_data=audit.get("quality_data", {}),
        risk_profile=audit.get("risk_profile", {}),
        hhi_data=audit.get("hhi_data", {}),
        findings=audit.get("findings", []),
        stats_summary=audit.get("stats_summary", {}),
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=laudo_auditoria_fiscal.pdf"},
    )
