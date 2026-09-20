"""Anomaly Detection Engine — Benford's Law, Statistical Outliers, and Temporal Anomaly Analytics."""
import math
from collections import defaultdict
from typing import Any, Dict, List, Tuple


class AnomalyDetectionEngine:
    """Executes multi-method statistical and mathematical anomaly detection on fiscal transactions."""

    BENFORD_FIRST_DIGIT_EXPECTED = {
        1: 30.1, 2: 17.6, 3: 12.5, 4: 9.7, 5: 7.9,
        6: 6.7, 7: 5.8, 8: 5.1, 9: 4.6
    }

    @classmethod
    def analyze_benford(cls, amounts: List[float]) -> Dict[str, Any]:
        """Calculates Benford's Law first-digit distribution, Chi-Square, and MAD."""
        valid_amounts = [a for a in amounts if a and a > 0]
        total = len(valid_amounts)
        if total < 50:
            return {
                "applicable": False,
                "reason": "Volume amostral insuficiente (mínimo 50 registros para Benford).",
                "digits": {},
                "mad": 0.0,
                "is_anomalous": False,
            }

        first_digit_counts = defaultdict(int)
        for a in valid_amounts:
            s = f"{a:.2f}".lstrip("0").replace(".", "").replace(",", "")
            if s and s[0].isdigit() and s[0] != "0":
                first_digit_counts[int(s[0])] += 1

        digits_data = {}
        total_mad_diff = 0.0
        chi_square = 0.0

        for d in range(1, 10):
            count = first_digit_counts.get(d, 0)
            observed_pct = round((count / total) * 100.0, 2)
            expected_pct = cls.BENFORD_FIRST_DIGIT_EXPECTED[d]
            diff = abs(observed_pct - expected_pct)
            total_mad_diff += diff
            expected_count = (expected_pct / 100.0) * total
            if expected_count > 0:
                chi_square += ((count - expected_count) ** 2) / expected_count

            digits_data[d] = {
                "digit": d,
                "count": count,
                "observed_pct": observed_pct,
                "expected_pct": expected_pct,
                "difference_pct": round(diff, 2),
            }

        mad = round(total_mad_diff / 9.0, 3)
        # Drake & Nigrini thresholds: MAD > 0.015 indicates non-conformity in forensic audit
        is_anomalous = mad > 2.5 or chi_square > 20.09  # 20.09 is chi2 critical value for df=8 at p=0.01

        return {
            "applicable": True,
            "total_analyzed": total,
            "mad": mad,
            "chi_square": round(chi_square, 2),
            "is_anomalous": is_anomalous,
            "conformity_level": "NON_CONFORMING" if mad > 3.0 else "MARGINAL" if mad > 2.0 else "CONFORMING",
            "digits": digits_data,
        }

    @staticmethod
    def calculate_outliers_iqr(amounts: List[float]) -> Tuple[List[float], float, float, float]:
        """Calculates Q1, Q3, IQR and identifies statistical outliers."""
        if len(amounts) < 4:
            return [], 0.0, 0.0, 0.0
        sorted_vals = sorted(amounts)
        n = len(sorted_vals)
        q1 = sorted_vals[int(n * 0.25)]
        median = sorted_vals[int(n * 0.50)]
        q3 = sorted_vals[int(n * 0.75)]
        iqr = q3 - q1
        upper_bound = q3 + (1.5 * iqr)
        lower_bound = max(0.0, q1 - (1.5 * iqr))

        outliers = [v for v in sorted_vals if v > upper_bound or (lower_bound > 0 and v < lower_bound)]
        return outliers, q1, q3, upper_bound

    @staticmethod
    def calculate_zscore_outliers(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identifies extreme value outliers using Z-score (Z > 3.0)."""
        valid_recs = [r for r in records if r.get("amount", 0) > 0]
        if len(valid_recs) < 10:
            return []

        amounts = [r["amount"] for r in valid_recs]
        mean = sum(amounts) / len(amounts)
        variance = sum((x - mean) ** 2 for x in amounts) / len(amounts)
        std_dev = math.sqrt(variance) if variance > 0 else 0.0

        if std_dev == 0:
            return []

        outliers = []
        for r in valid_recs:
            z = (r["amount"] - mean) / std_dev
            if z > 3.0:
                outliers.append({
                    **r,
                    "z_score": round(z, 2),
                    "mean_reference": round(mean, 2),
                })

        return outliers

    @classmethod
    def evaluate_anomalies(cls, records: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Runs the complete suite of statistical, Benford, and outlier detection models."""
        findings: List[Dict[str, Any]] = []
        if not records:
            return findings, {}

        amounts = [r.get("amount", 0.0) for r in records if r.get("amount", 0) > 0]

        # 1. Benford's Law
        benford_res = cls.analyze_benford(amounts)
        if benford_res.get("is_anomalous"):
            findings.append({
                "rule_code": "ANOMALY-BENFORD-001",
                "title": f"Desvio estatístico relevante na Lei de Benford (MAD: {benford_res['mad']}%)",
                "category": "STATISTICAL_ANOMALY",
                "subcategory": "BENFORD_DEVIATION",
                "severity": "HIGH",
                "risk_score": 75.0,
                "confidence_score": 88.0,
                "financial_exposure": sum(amounts) * 0.15,
                "affected_records_count": len(amounts),
                "entities_involved": [],
                "explanation": {
                    "what": f"A distribuição dos primeiros dígitos dos valores transacionados diverge significativamente da Lei de Benford (Chi-Quadrado: {benford_res['chi_square']}).",
                    "why": "Distribuições naturais de transações financeiras livres seguem o padrão logarítmico de Benford. Desvios indicam valores artificiais ou intervenção em thresholds.",
                    "evidence": f"Desvio Médio Absoluto (MAD) de {benford_res['mad']}%, classificado como {benford_res['conformity_level']}.",
                    "recommendation": "Cruzar com a análise de valores redondos e fracionamento para identificar as faixas artificiais.",
                },
                "alternative_hypotheses": [
                    "Base de dados concentrada em produtos com tabela de preço fixo pré-definida.",
                    "Transações com valores unitários tabelados por órgão regulador.",
                ],
                "sample_records": records[:5],
            })

        # 2. Extreme Z-score Outliers
        z_outliers = cls.calculate_zscore_outliers(records)
        if len(z_outliers) >= 1:
            z_exposure = sum(r.get("amount", 0) for r in z_outliers)
            findings.append({
                "rule_code": "ANOMALY-ZSCORE-002",
                "title": f"Detecção de {len(z_outliers)} transações atípicas de valor extremo (Z-Score > 3.0)",
                "category": "STATISTICAL_ANOMALY",
                "subcategory": "EXTREME_OUTLIER",
                "severity": "MEDIUM",
                "risk_score": 70.0,
                "confidence_score": 90.0,
                "financial_exposure": z_exposure,
                "affected_records_count": len(z_outliers),
                "entities_involved": list(set(r.get("supplier_tax_id") for r in z_outliers if r.get("supplier_tax_id")))[:10],
                "explanation": {
                    "what": f"Foram identificadas {len(z_outliers)} transações com valores posicionados a mais de 3 desvios padrão da média histórica.",
                    "why": "Valores estatisticamente isolados exigem comprovação de lastro documental específico e aprovação extraordinária.",
                    "evidence": f"Volume total de R$ {z_exposure:,.2f} em operações isoladas com Z-score médio de {round(sum(r['z_score'] for r in z_outliers)/len(z_outliers), 1)}.",
                    "recommendation": "Verificar se as operações correspondem a aquisição de ativo imobilizado (Capex) ou despesas extraordinárias.",
                },
                "alternative_hypotheses": [
                    "Compra anual consolidada de equipamentos de grande porte.",
                    "Operação de liquidação judicial ou acordo societário extraordinário.",
                ],
                "sample_records": z_outliers[:5],
            })

        stats_summary = {
            "total_records": len(records),
            "total_volume": sum(amounts),
            "average_amount": round(sum(amounts)/len(amounts), 2) if amounts else 0.0,
            "max_amount": max(amounts) if amounts else 0.0,
            "min_amount": min(amounts) if amounts else 0.0,
            "benford_results": benford_res,
            "outliers_count": len(z_outliers),
        }

        return findings, stats_summary
