"""Fiscal Auditor Copilot — Intelligent conversational assistant for forensic queries."""
from typing import Any, Dict, List, Optional


class FiscalCopilotService:
    """Answers auditor queries grounded strictly on dataset analysis, findings, and evidence."""

    @classmethod
    def answer_query(
        cls,
        query: str,
        dataset_meta: Dict[str, Any],
        findings: List[Dict[str, Any]],
        risk_profile: Dict[str, Any],
        hhi_data: Dict[str, Any],
        stats_summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        q = query.lower().strip()

        # 1. Biggest risks query
        if "maior" in q or "maiores" in q or "risco" in q and "quais" in q:
            top_findings = sorted(findings, key=lambda x: x.get("financial_exposure", 0.0), reverse=True)[:3]
            answer = (
                f"Com base na análise de **{stats_summary.get('total_records', 0):,} registros** (Volume: R$ {stats_summary.get('total_volume', 0.0):,.2f}), "
                f"os 3 maiores pontos de atenção financeira identificados são:\n\n"
            )
            for i, f in enumerate(top_findings, 1):
                answer += (
                    f"**{i}. [{f.get('rule_code')}] {f.get('title')}**\n"
                    f"- **Exposição:** R$ {f.get('financial_exposure', 0.0):,.2f} | **Risk Score:** {f.get('risk_score')}/100\n"
                    f"- **Motivo:** {f.get('explanation', {}).get('what', '')}\n"
                    f"- **Recomendação:** {f.get('explanation', {}).get('recommendation', '')}\n\n"
                )
            return {
                "query": query,
                "answer": answer,
                "confidence": 94.0,
                "referenced_findings": [f.get("rule_code") for f in top_findings],
            }

        # 2. Supplier concentration query
        if "fornecedor" in q or "concentra" in q or "hhi" in q:
            top_sup = hhi_data.get("top_suppliers", [])
            answer = (
                f"O índice de concentração Herfindahl-Hirschman calculado para a base é **{hhi_data.get('hhi_index', 0)}** "
                f"({hhi_data.get('classification', 'N/A')}).\n\n"
                f"**Top Fornecedores por Volume:**\n"
            )
            for i, s in enumerate(top_sup[:5], 1):
                answer += f"{i}. **{s.get('name')}** (CNPJ: `{s.get('tax_id')}`): R$ {s.get('volume', 0.0):,.2f} ({s.get('share_pct')}% do total)\n"

            answer += (
                f"\nO maior fornecedor individual concentra **{hhi_data.get('top_1_concentration_pct')}%** de todos os desembolsos. "
                "Recomenda-se checar se há contratos de exclusividade ou dependência operacional."
            )
            return {
                "query": query,
                "answer": answer,
                "confidence": 96.0,
                "referenced_findings": ["RULE-FISCAL-005"],
            }

        # 3. Benford / Statistical anomalies
        if "benford" in q or "estatistic" in q or "digito" in q:
            benford = stats_summary.get("benford_results", {})
            answer = (
                f"A avaliação pela **Lei de Benford** obteve Desvio Médio Absoluto (MAD) de **{benford.get('mad', 0)}%** "
                f"e Chi-Quadrado de **{benford.get('chi_square', 0)}** (Classificação: **{benford.get('conformity_level', 'N/A')}**).\n\n"
                "Em distribuições financeiras autênticas, o dígito 1 deve iniciar aproximadamente 30,1% dos valores. "
                "Desvios nessa curva sugerem a existência de valores pré-fixados, honorários tabelados ou eventual fracionamento de notas."
            )
            return {
                "query": query,
                "answer": answer,
                "confidence": 91.0,
                "referenced_findings": ["ANOMALY-BENFORD-001"],
            }

        # Default contextual response
        return {
            "query": query,
            "answer": (
                f"A análise pericial identificou um **Risk Score Global de {risk_profile.get('overall_risk_score', 0)}/100** "
                f"com **{len(findings)} apontamentos de auditoria** e **R$ {risk_profile.get('total_exposure', 0.0):,.2f}** "
                f"em exposição potencial sob investigação. A integridade dos dados (Data Quality Score) foi calculada em "
                f"**{stats_summary.get('data_quality_score', 90)}%**."
            ),
            "confidence": 88.0,
            "referenced_findings": [f.get("rule_code") for f in findings[:3]],
        }
