"""Pipeline Orchestrator — End-to-end execution of the Fiscal Forensic AI analytical workflow."""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .schema_mapper import SmartSchemaMapper
from .data_quality_service import DataQualityEngine
from .rule_engine import FiscalRuleEngine
from .anomaly_engine import AnomalyDetectionEngine
from .entity_graph_service import EntityGraphEngine
from .risk_engine import ForensicRiskEngine
from .evidence_service import EvidenceVaultService
from .case_service import CaseManagementService


class FiscalPipelineOrchestrator:
    """Coordinates schema mapping, data quality, rules, statistics, graph, and risk scoring."""

    @classmethod
    def execute_audit(
        cls,
        raw_rows: List[Dict[str, Any]],
        dataset_name: str = "Dataset Fiscal",
        custom_mapping: Optional[Dict[str, Dict[str, Any]]] = None,
        source_filename: str = "relatorio_fiscal.xlsx",
    ) -> Dict[str, Any]:
        dataset_id = str(uuid.uuid4())
        headers = list(raw_rows[0].keys()) if raw_rows else []

        # 1. Smart Schema Mapping
        mapping = custom_mapping or SmartSchemaMapper.map_dataset_columns(headers, raw_rows)

        # 2. Normalization
        normalized_records = [
            SmartSchemaMapper.normalize_record(row, mapping)
            for row in raw_rows
        ]

        # 3. Data Quality Engine
        quality_data = DataQualityEngine.evaluate_dataset_quality(normalized_records)

        # 4. Fiscal Rule Engine
        rule_findings = FiscalRuleEngine.evaluate_rules(normalized_records)

        # 5. Statistical & Benford Anomaly Detection
        anomaly_findings, stats_summary = AnomalyDetectionEngine.evaluate_anomalies(normalized_records)
        stats_summary["data_quality_score"] = quality_data.get("data_quality_score", 0.0)

        # Combine findings
        all_raw_findings = rule_findings + anomaly_findings

        # 6. Entity Resolution & Graph Analytics & HHI
        entities = EntityGraphEngine.resolve_entities(normalized_records)
        hhi_data = EntityGraphEngine.calculate_hhi_concentration(entities, stats_summary.get("total_volume", 0.0))
        network_graph = EntityGraphEngine.build_network_graph(normalized_records)

        # 7. Risk Scoring & Multi-Agent Quality Gate
        risk_profile = ForensicRiskEngine.calculate_dataset_risk_profile(
            all_raw_findings,
            quality_data.get("data_quality_score", 100.0),
            hhi_data,
            stats_summary.get("total_volume", 0.0)
        )
        validated_findings = ForensicRiskEngine.audit_quality_gate(all_raw_findings)

        # 8. Evidence Vault (SHA-256 generation for sample evidence)
        evidence_list = []
        for f_idx, finding in enumerate(validated_findings):
            finding_id = f"fnd-fiscal-{f_idx+1}-{uuid.uuid4().hex[:4]}"
            finding["id"] = finding_id
            finding["dataset_id"] = dataset_id

            # Attach evidence records
            samples = finding.get("sample_records", [])
            evidence_ids = []
            for s_idx, sample in enumerate(samples):
                ev = EvidenceVaultService.create_evidence_entry(
                    dataset_id=dataset_id,
                    finding_id=finding_id,
                    row_number=s_idx + 1,
                    raw_row=sample,
                    normalized_row=sample,
                    source_file=source_filename,
                )
                ev["id"] = f"ev-{uuid.uuid4().hex[:6]}"
                evidence_list.append(ev)
                evidence_ids.append(ev["id"])
            finding["evidence_ids"] = evidence_ids

        # 9. Initial Audit Case
        initial_case = None
        if validated_findings:
            initial_case = CaseManagementService.create_case_from_findings(
                title=f"Auditoria Forense — {dataset_name}",
                description=f"Caso investigativo aberto automaticamente contendo {len(validated_findings)} apontamentos de auditoria.",
                findings=validated_findings,
                dataset_id=dataset_id,
                assigned_auditor="Auditor Responsável",
            )
            initial_case["id"] = f"case-{uuid.uuid4().hex[:6]}"

        return {
            "dataset_id": dataset_id,
            "dataset_name": dataset_name,
            "filename": source_filename,
            "total_rows": len(raw_rows),
            "schema_mapping": mapping,
            "quality_data": quality_data,
            "stats_summary": stats_summary,
            "risk_profile": risk_profile,
            "hhi_data": hhi_data,
            "network_graph": network_graph,
            "findings": validated_findings,
            "entities": list(entities.values())[:50],
            "evidences": evidence_list[:50],
            "cases": [initial_case] if initial_case else [],
            "audited_at": datetime.now(timezone.utc).isoformat(),
        }
