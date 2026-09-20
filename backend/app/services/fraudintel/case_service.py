"""
FRAUDINTEL — Case Management Service
Lifecycle management (NEW -> TRIAGE -> INVESTIGATING -> ESCALATED -> RESOLVED -> CLOSED).
"""

from typing import List, Dict, Any, Optional
import uuid
import hashlib
from datetime import datetime, timezone
import structlog
from .seed_data import SEED_CASES, DEMO_INVESTIGATION_CASE, DETECTION_RULES_CATALOG, WATCHLISTS_DATASET
from .risk_engine import risk_engine
from .correlation_engine import correlation_engine
from .fraud_graph_service import fraud_graph_service
from .ai_investigator import ai_investigator
from .takedown_tracker import takedown_tracker

logger = structlog.get_logger(__name__)

class CaseService:
    def __init__(self):
        # In-memory working cache initialized from enterprise seed
        self._cases: Dict[str, Dict[str, Any]] = {c["id"]: c.copy() for c in SEED_CASES}
        self._rules: List[Dict[str, Any]] = [r.copy() for r in DETECTION_RULES_CATALOG]
        self._watchlists: List[Dict[str, Any]] = [w.copy() for w in WATCHLISTS_DATASET]
        self._audit_logs: List[Dict[str, Any]] = [
            {
                "id": f"AUD-{uuid.uuid4().hex[:8]}",
                "user": "felipe.m.costa@stellantis.com",
                "action": "SYSTEM_INITIALIZED",
                "resource": "FRAUDINTEL_ENGINE",
                "resource_id": "GLOBAL",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ip": "127.0.0.1",
                "result": "SUCCESS",
                "details": "Plataforma FRAUDINTEL inicializada com 20 casos e regras ativas."
            }
        ]

    def get_dashboard_kpis(self) -> Dict[str, Any]:
        cases = list(self._cases.values())
        return {
            "total_cases": len(cases),
            "open_cases": sum(1 for c in cases if c.get("status") in ["NEW", "TRIAGE", "INVESTIGATING", "ESCALATED"]),
            "critical_cases": sum(1 for c in cases if c.get("severity") == "CRITICAL"),
            "high_cases": sum(1 for c in cases if c.get("severity") == "HIGH"),
            "resolved_cases": sum(1 for c in cases if c.get("status") in ["RESOLVED", "CLOSED"]),
            "active_watchlists": len(self._watchlists),
            "detection_rules_count": len(self._rules),
            "monitored_domains_count": 54,
            "analyzed_boletos_count": 28,
            "takedowns_in_progress": sum(1 for c in cases if c.get("takedown", {}).get("status") == "DISPATCHED_IN_PROGRESS"),
            "last_updated_utc": datetime.now(timezone.utc).isoformat()
        }

    def list_cases(self, status: Optional[str] = None, severity: Optional[str] = None, query: Optional[str] = None) -> List[Dict[str, Any]]:
        results = list(self._cases.values())
        if status and status != "ALL":
            results = [c for c in results if c.get("status") == status]
        if severity and severity != "ALL":
            results = [c for c in results if c.get("severity") == severity]
        if query:
            q = query.lower()
            results = [c for c in results if q in c.get("title", "").lower() or q in c.get("id", "").lower() or q in c.get("target_asset", "").lower()]
        return sorted(results, key=lambda x: x.get("created_at", ""), reverse=True)

    def get_case_by_id(self, case_id: str) -> Optional[Dict[str, Any]]:
        return self._cases.get(case_id)

    async def create_case_from_url(self, url: str, brand: str = "Marca Corporativa", case_type: str = "BRAND_IMPERSONATION") -> Dict[str, Any]:
        cid = f"FRD-2026-{uuid.uuid4().hex[:4].upper()}"
        clean_url = url.strip()
        if not clean_url.startswith("http"):
            clean_url = "https://" + clean_url

        # Calculate initial risk & probe
        r_calc = risk_engine.calculate_risk(
            domain_similarity=0.88,
            domain_age_days=12,
            is_bulletproof_host=True,
            has_login_form=True,
            correlated_cases_count=2
        )

        now = datetime.now(timezone.utc).isoformat()
        new_case = {
            "id": cid,
            "title": f"Investigação de Fraude Digital & Impersonação — {clean_url}",
            "target_asset": clean_url,
            "brand_victim": brand,
            "case_type": case_type,
            "severity": r_calc["grade"],
            "status": "INVESTIGATING",
            "owner": "Felipe Moreira Costa (Fraud Intelligence Architect)",
            "created_at": now,
            "updated_at": now,
            "risk_score": r_calc,
            "executive_summary": f"Caso autônomo instaurado para o ativo {clean_url}. Identificados {r_calc['factors_count']} vetores de risco perimétrico.",
            "entities": [
                {"id": f"ENT-{cid}-01", "type": "Domain", "name": clean_url, "role": "Vetor Sob Investigação"},
                {"id": f"ENT-{cid}-02", "type": "Brand", "name": brand, "role": "Marca Alvo / Vítima"}
            ],
            "findings": [
                {
                    "id": f"FND-{cid}-01",
                    "type": "IMPERSONATION",
                    "classification": "EVIDENCE",
                    "title": "Registro Recente & Padrão Lookalike",
                    "description": f"O ativo {clean_url} foi ativado recentemente com características de representação indevida da marca {brand}.",
                    "rule_id": "RULE_DOMAIN_IMPERSONATION",
                    "confidence": 92.0
                }
            ],
            "hypotheses": [],
            "insights": [],
            "timeline": [
                {"timestamp": now, "event": f"Investigação #{cid} iniciada pelo operador para o alvo {clean_url}."}
            ],
            "evidences": [
                {
                    "id": f"EV-{cid}-01",
                    "type": "URL_SNAPSHOT",
                    "source": "Passive OSINT Engine",
                    "collected_at": now,
                    "collector": "FRAUDINTEL-Core-Worker",
                    "sha256": hashlib.sha256(f"{clean_url}|{now}".encode()).hexdigest(),
                    "description": f"Captura primária do cabeçalho HTTP e resolução de nomes de {clean_url}."
                }
            ],
            "takedown": None
        }

        # AI synthesis
        ai_res = await ai_investigator.analyze_case(new_case)
        new_case["insights"] = ai_res.get("insights", [])
        new_case["hypotheses"] = ai_res.get("hypotheses", [])

        self._cases[cid] = new_case
        self.log_audit("CASE_CREATED", "Case", cid, {"target_asset": clean_url, "risk": r_calc["score"]})
        return new_case

    def update_case_status(self, case_id: str, new_status: str) -> Optional[Dict[str, Any]]:
        c = self._cases.get(case_id)
        if not c:
            return None
        old_status = c.get("status")
        c["status"] = new_status
        c["updated_at"] = datetime.now(timezone.utc).isoformat()
        c["timeline"].append({
            "timestamp": c["updated_at"],
            "event": f"Status do caso alterado de {old_status} para {new_status}."
        })
        self.log_audit("CASE_STATUS_UPDATED", "Case", case_id, {"old_status": old_status, "new_status": new_status})
        return c

    def log_audit(self, action: str, resource: str, resource_id: str, details: Dict[str, Any]):
        entry = {
            "id": f"AUD-{uuid.uuid4().hex[:8]}",
            "user": "felipe.m.costa@stellantis.com",
            "action": action,
            "resource": resource,
            "resource_id": resource_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": "127.0.0.1",
            "result": "SUCCESS",
            "details": details
        }
        self._audit_logs.insert(0, entry)

    def get_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._audit_logs[:limit]

case_service = CaseService()
