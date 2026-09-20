"""Audit Case Management Service — Investigation tracking, workflows, and case lifecycle."""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class CaseManagementService:
    """Manages forensic audit cases, assignee workflows, and investigation notes."""

    @staticmethod
    def generate_case_number(year: Optional[int] = None) -> str:
        y = year or datetime.now(timezone.utc).year
        unique_suffix = uuid.uuid4().hex[:5].upper()
        return f"CASE-{y}-{unique_suffix}"

    @classmethod
    def create_case_from_findings(
        cls,
        title: str,
        description: str,
        findings: List[Dict[str, Any]],
        dataset_id: Optional[str] = None,
        assigned_auditor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Groups findings into a new investigative audit case."""
        case_number = cls.generate_case_number()
        total_exposure = sum(f.get("financial_exposure", 0.0) for f in findings)
        entities = list(set(
            ent for f in findings for ent in f.get("entities_involved", [])
        ))

        priority = "CRITICAL" if any(f.get("severity") == "CRITICAL" for f in findings) else \
                   "HIGH" if any(f.get("severity") == "HIGH" for f in findings) else "MEDIUM"

        return {
            "case_number": case_number,
            "title": title,
            "description": description,
            "status": "OPEN",
            "priority": priority,
            "dataset_id": dataset_id,
            "assigned_auditor_id": assigned_auditor,
            "financial_exposure": round(total_exposure, 2),
            "findings_count": len(findings),
            "findings_ids": [f.get("id") or f.get("rule_code") for f in findings],
            "entities_involved": entities[:20],
            "audit_notes": [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "author": assigned_auditor or "System",
                    "note": f"Caso instaurado automaticamente agrupando {len(findings)} apontamentos de risco com exposição de R$ {total_exposure:,.2f}.",
                }
            ],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
