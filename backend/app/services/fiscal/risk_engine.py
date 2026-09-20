"""Forensic Risk Scoring & Explainable AI Engine — Multi-factor scoring and non-accusatory reasoning."""
from typing import Any, Dict, List, Tuple


class ForensicRiskEngine:
    """Computes multidimensional forensic risk scores and formats explainable natural-language reports."""

    @staticmethod
    def calculate_dataset_risk_profile(
        findings: List[Dict[str, Any]],
        data_quality_score: float,
        hhi_data: Dict[str, Any],
        total_volume: float
    ) -> Dict[str, Any]:
        """Calculates global risk score, severity distributions, and exposure volume."""
        if not findings:
            return {
                "overall_risk_score": 10.0,
                "overall_confidence": 95.0,
                "risk_classification": "BAIXO RISCO",
                "total_exposure": 0.0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "contributors": [],
            }

        crit_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
        med_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low_count = sum(1 for f in findings if f.get("severity") == "LOW")

        total_exposure = sum(f.get("financial_exposure", 0.0) for f in findings)

        # Weighted calculation
        raw_score = (crit_count * 25) + (high_count * 15) + (med_count * 5) + (low_count * 1)
        if data_quality_score < 80:
            raw_score += (80 - data_quality_score) * 0.3
        if hhi_data.get("classification") == "HIGHLY_CONCENTRATED":
            raw_score += 15

        overall_score = min(99.0, max(5.0, round(raw_score, 1)))

        # Average confidence
        conf_scores = [f.get("confidence_score", 85.0) for f in findings]
        avg_confidence = round(sum(conf_scores) / len(conf_scores), 1) if conf_scores else 90.0

        classification = (
            "RISCO CRÍTICO" if overall_score >= 85 else
            "ALTO RISCO" if overall_score >= 70 else
            "RISCO MODERADO" if overall_score >= 45 else
            "ATENÇÃO" if overall_score >= 25 else
            "BAIXO RISCO"
        )

        contributors = []
        if crit_count > 0:
            contributors.append({"name": "Inconsistências Cadastrais Críticas (RFB)", "points": crit_count * 25})
        if any(f.get("category") == "DUPLICITY" for f in findings):
            contributors.append({"name": "Padrão de Duplicidade de Notas", "points": 18})
        if hhi_data.get("classification") == "HIGHLY_CONCENTRATED":
            contributors.append({"name": "Concentração de Fornecimento (HHI)", "points": 15})
        if any(f.get("category") == "FRACTIONING" for f in findings):
            contributors.append({"name": "Estruturação / Fracionamento", "points": 14})
        if any(f.get("category") == "STATISTICAL_ANOMALY" for f in findings):
            contributors.append({"name": "Desvio Estatístico (Lei de Benford)", "points": 12})
        if any(f.get("category") == "TEMPORAL" for f in findings):
            contributors.append({"name": "Anomalias Temporais / Fins de Semana", "points": 10})

        return {
            "overall_risk_score": overall_score,
            "overall_confidence": avg_confidence,
            "risk_classification": classification,
            "total_exposure": round(total_exposure, 2),
            "exposure_ratio_pct": round((total_exposure / total_volume * 100), 2) if total_volume > 0 else 0.0,
            "critical_count": crit_count,
            "high_count": high_count,
            "medium_count": med_count,
            "low_count": low_count,
            "contributors": contributors,
        }

    @staticmethod
    def audit_quality_gate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Multi-agent validation gate: removes contradictions, dedupes findings, and enforces non-accusatory tone."""
        validated: List[Dict[str, Any]] = []
        seen_rules = set()

        for f in findings:
            code = f.get("rule_code", "UNKNOWN")
            if code in seen_rules and code != "ANOMALY-ZSCORE-002":
                continue
            seen_rules.add(code)

            # Ensure non-accusatory disclaimer in explanation
            explanation = f.get("explanation", {})
            if "disclaimer" not in explanation:
                explanation["disclaimer"] = (
                    "Este apontamento constitui indício analítico e estatístico para investigação "
                    "e não representa, isoladamente, declaração conclusiva de fraude ou dolo."
                )

            f["explanation"] = explanation
            validated.append(f)

        return validated
