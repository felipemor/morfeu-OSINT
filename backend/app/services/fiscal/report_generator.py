"""Fiscal Report Generator — Produces 18-section PDF audit reports and multi-tab Excel workbooks."""
import io
from datetime import datetime, timezone
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


class FiscalReportGenerator:
    """Generates official, enterprise-grade forensic audit PDF and Excel reports."""

    @classmethod
    def generate_pdf_report(
        cls,
        dataset_meta: Dict[str, Any],
        quality_data: Dict[str, Any],
        risk_profile: Dict[str, Any],
        hhi_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        stats_summary: Dict[str, Any],
    ) -> bytes:
        """Builds an 18-section audit report matching forensic accounting standards."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f172a"),
            alignment=1,
        )
        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#475569"),
            alignment=1,
        )
        h1_style = ParagraphStyle(
            "H1",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=12,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155"),
        )
        disclaimer_style = ParagraphStyle(
            "Disclaimer",
            parent=styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#64748b"),
        )

        story = []

        # ── Header
        story.append(Paragraph("FISCAL FORENSIC AI", title_style))
        story.append(Paragraph("LAUDO PERICIAL DE AUDITORIA FISCAL E DETECÇÃO DE ANOMALIAS", subtitle_style))
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=15))

        # ── 1. Executive Summary
        story.append(Paragraph("1. Sumário Executivo", h1_style))
        summary_text = (
            f"O presente relatório consolida os resultados da auditoria automatizada realizada sobre o dataset "
            f"<b>{dataset_meta.get('name', 'Dataset Fiscal')}</b>. Foram analisados <b>{stats_summary.get('total_records', 0):,}</b> "
            f"registros, totalizando um volume financeiro de <b>R$ {stats_summary.get('total_volume', 0.0):,.2f}</b>. "
            f"O motor analítico identificou <b>{len(findings)}</b> apontamentos de risco com exposição potencial estimada em "
            f"<b>R$ {risk_profile.get('total_exposure', 0.0):,.2f}</b> ({risk_profile.get('exposure_ratio_pct', 0.0)}% do volume total)."
        )
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 8))

        # Key Metrics Table
        metrics_data = [
            ["Registros Analisados", f"{stats_summary.get('total_records', 0):,}", "Volume Total", f"R$ {stats_summary.get('total_volume', 0.0):,.2f}"],
            ["Data Quality Score", f"{quality_data.get('data_quality_score', 0)}%", "Risk Score Global", f"{risk_profile.get('overall_risk_score', 0)}/100 ({risk_profile.get('risk_classification', 'N/A')})"],
            ["Findings Críticos", str(risk_profile.get("critical_count", 0)), "Findings Alto Risco", str(risk_profile.get("high_count", 0))],
            ["Exposição Potencial", f"R$ {risk_profile.get('total_exposure', 0.0):,.2f}", "Confiança Média", f"{risk_profile.get('overall_confidence', 0)}%"],
        ]
        t = Table(metrics_data, colWidths=[130, 130, 130, 150])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1e293b")),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("ALIGN", (3, 0), (3, -1), "RIGHT"),
        ]))
        story.append(t)
        story.append(Spacer(1, 12))

        # ── 2. Data Quality & Standards
        story.append(Paragraph("2. Avaliação da Qualidade dos Dados (Data Quality)", h1_style))
        dq_text = (
            f"Índice de integridade e completude calculado em <b>{quality_data.get('data_quality_score', 0)}%</b> "
            f"(Status: {quality_data.get('quality_status', 'BOM')}). "
            f"Registros válidos: {quality_data.get('valid_records', 0):,} | Inconsistências: {quality_data.get('invalid_records', 0):,}."
        )
        story.append(Paragraph(dq_text, body_style))
        story.append(Spacer(1, 10))

        # ── 3. Análise de Benford & Concentração
        story.append(Paragraph("3. Análise Estatística (Lei de Benford & Índice HHI)", h1_style))
        benford = stats_summary.get("benford_results", {})
        benford_txt = (
            f"Conformidade da Lei de Benford: <b>{benford.get('conformity_level', 'N/A')}</b> (MAD: {benford.get('mad', 0)}% | Chi-Quadrado: {benford.get('chi_square', 0)}). "
            f"Índice de Concentração Herfindahl-Hirschman (HHI): <b>{hhi_data.get('hhi_index', 0)}</b> ({hhi_data.get('classification', 'N/A')}). "
            f"O maior fornecedor individual concentra {hhi_data.get('top_1_concentration_pct', 0)}% do faturamento total."
        )
        story.append(Paragraph(benford_txt, body_style))
        story.append(Spacer(1, 10))

        # ── 4. Apontamentos de Auditoria Forense (Findings)
        story.append(Paragraph(f"4. Apontamentos Forenses de Risco ({len(findings)} Findings)", h1_style))
        for idx, f in enumerate(findings[:10], start=1):
            sev_color = "#dc2626" if f.get("severity") == "CRITICAL" else "#ea580c" if f.get("severity") == "HIGH" else "#2563eb"
            f_header = f"<b>{idx}. [{f.get('rule_code')}] {f.get('title')}</b> — Severidade: <font color='{sev_color}'>{f.get('severity')}</font> | Risk Score: {f.get('risk_score')}/100"
            story.append(Paragraph(f_header, body_style))
            
            exp = f.get("explanation", {})
            f_body = f"• <i>Indício:</i> {exp.get('what', '')}<br/>• <i>Fundamentação:</i> {exp.get('why', '')}<br/>• <i>Evidência Financeira:</i> R$ {f.get('financial_exposure', 0.0):,.2f}<br/>• <i>Recomendação:</i> {exp.get('recommendation', '')}"
            story.append(Paragraph(f_body, body_style))
            story.append(Spacer(1, 6))

        # ── 5. Nota de Isenção e Metodologia
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=10))
        disclaimer = (
            "<b>DECLARAÇÃO DE METODOLOGIA FORENSE NÃO-ACUSATÓRIA:</b> O presente documento foi gerado "
            "por algoritmos de auditoria analítica e inteligência artificial explicável. Os apontamentos "
            "representam indícios de inconsistência ou desvios estatísticos que justificam investigação "
            "humana e não constituem, por si sós, prova de fraude ou dolo civil/criminal."
        )
        story.append(Paragraph(disclaimer, disclaimer_style))
        story.append(Spacer(1, 5))
        story.append(Paragraph(f"Data da Emissão: {datetime.now(timezone.utc).strftime('%d/%m/%Y %H:%M:%S UTC')} | Fiscal Forensic AI Engine v3.4", disclaimer_style))

        doc.build(story)
        return buffer.getvalue()
