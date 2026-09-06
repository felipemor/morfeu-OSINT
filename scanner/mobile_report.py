"""
Mobile Pentest PDF Report Generator — morfeusec OSINT
Generates Big-4 standard, high-impact cybersecurity reports for Mobile Applications (Android .apk & iOS .ipa).
Compliant with OWASP MASVS v2.0, OWASP Mobile Top 10, NIST SP 800-115, and CVSS v3.1.
"""
import io
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Dict, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.colors import HexColor, white, black

# ─── Color Palette (Cyber Dark Theme matching URL scan reports) ───────────────
C_BG        = HexColor("#080d1a")  # Deep Midnight Canvas
C_CARD      = HexColor("#101726")  # Premium Card Surface
C_CARD_ALT  = HexColor("#162032")  # Highlight Card
C_BORDER    = HexColor("#1e2d42")  # Structural Border
C_BORDER_HI = HexColor("#00d4ff")  # Electric Cyan Border
C_CYAN      = HexColor("#00d4ff")  # Accent Cyan
C_PURPLE    = HexColor("#a855f7")  # Cyber Purple
C_TEXT      = HexColor("#e2e8f0")  # Slate 200 Primary Text
C_TEXT_DIM  = HexColor("#94a3b8")  # Slate 400 Secondary
C_MUTED     = HexColor("#64748b")  # Slate 500 Subtitle

# Severity Colors
C_CRITICAL  = HexColor("#ef4444")  # Red
C_HIGH      = HexColor("#f97316")  # Orange
C_MEDIUM    = HexColor("#eab308")  # Yellow
C_LOW       = HexColor("#10b981")  # Emerald/Green
C_INFO      = HexColor("#06b6d4")  # Cyan
C_WHITE     = white
C_BLACK     = black

SEV_COLORS = {
    "CRITICAL": C_CRITICAL,
    "HIGH": C_HIGH,
    "MEDIUM": C_MEDIUM,
    "LOW": C_LOW,
    "INFO": C_INFO,
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

BACEN_SLAS = {
    "CRITICAL": "24 a 48 Horas (Urgência Imediata)",
    "HIGH": "Até 7 Dias Corridos",
    "MEDIUM": "Até 30 Dias Corridos",
    "LOW": "Até 60 Dias / Próximo Ciclo",
    "INFO": "Planejamento Arquitetural",
}


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", fontSize=22, textColor=C_CYAN, spaceAfter=6, fontName="Helvetica-Bold", alignment=TA_CENTER, leading=26),
        "subtitle": ParagraphStyle("subtitle", fontSize=10.5, textColor=C_TEXT_DIM, spaceAfter=14, fontName="Helvetica", alignment=TA_CENTER, leading=14),
        "h1": ParagraphStyle("h1", fontSize=16, textColor=C_WHITE, spaceAfter=8, spaceBefore=14, fontName="Helvetica-Bold", leading=20),
        "h2": ParagraphStyle("h2", fontSize=12, textColor=C_CYAN, spaceAfter=6, spaceBefore=10, fontName="Helvetica-Bold", leading=15),
        "h3": ParagraphStyle("h3", fontSize=10, textColor=C_WHITE, spaceAfter=4, spaceBefore=6, fontName="Helvetica-Bold", leading=12),
        "body": ParagraphStyle("body", fontSize=8.5, textColor=C_TEXT, leading=12, fontName="Helvetica", spaceAfter=3),
        "body_justify": ParagraphStyle("body_justify", fontSize=8.5, textColor=C_TEXT, leading=12, fontName="Helvetica", alignment=TA_JUSTIFY, spaceAfter=4),
        "body_dim": ParagraphStyle("body_dim", fontSize=8, textColor=C_TEXT_DIM, leading=11, fontName="Helvetica"),
        "mono": ParagraphStyle("mono", fontSize=7.5, textColor=HexColor("#38bdf8"), leading=9.5, fontName="Courier", backColor=C_CARD),
        "mono_code": ParagraphStyle("mono_code", fontSize=7.5, textColor=HexColor("#4ade80"), leading=9.5, fontName="Courier", backColor=HexColor("#060a12")),
        "label": ParagraphStyle("label", fontSize=7.5, textColor=C_MUTED, fontName="Helvetica-Bold"),
        "center": ParagraphStyle("center", fontSize=8.5, textColor=C_TEXT, alignment=TA_CENTER, fontName="Helvetica"),
        "footer": ParagraphStyle("footer", fontSize=7, textColor=C_MUTED, alignment=TA_CENTER, fontName="Helvetica"),
    }


class MobilePentestReportPDF:
    def __init__(self, output_path: str):
        self.output_path = output_path
        self.s = _styles()
        self.story = []
        self.language = "pt"

    def build(
        self,
        scan_result: Dict[str, Any],
        operator: str = "Felipe Costa - fsec.costa@gmail.com",
        language: str = "pt",
    ) -> str:
        self.language = language
        is_pt = self.language.lower() == "pt"

        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=A4,
            leftMargin=1.6*cm, rightMargin=1.6*cm,
            topMargin=1.6*cm, bottomMargin=1.6*cm,
        )

        findings = scan_result.get("findings", [])
        order_map = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        sorted_findings = sorted(
            findings,
            key=lambda f: (order_map.get(str(f.get("severity", "INFO")).upper(), 99), -float(f.get("cvss_score", 0.0) or 0.0))
        )

        sev_counts = {s: sum(1 for f in sorted_findings if str(f.get("severity", "")).upper() == s) for s in SEVERITY_ORDER}
        risk_score = scan_result.get("risk_score", 0)

        # 1. Cover Page
        self._cover_page(scan_result, operator, len(sorted_findings), risk_score)
        self.story.append(PageBreak())

        # 2. Executive Summary
        self._exec_summary(scan_result, sorted_findings, sev_counts, risk_score)
        self.story.append(Spacer(1, 8))

        # 3. OWASP MASVS v2.0 Architecture Matrix
        self._masvs_architecture_matrix(scan_result)
        self.story.append(PageBreak())

        # 4. Dangerous Permissions Matrix & Attack Surfaces
        self._permissions_and_secrets_section(scan_result)
        self.story.append(Spacer(1, 8))

        # 5. Consolidated Risk Matrix & SLAs
        self._findings_summary_table(sorted_findings)
        self.story.append(PageBreak())

        # 6. Detailed Technical Dossier (OWASP MASVS SAST/DAST)
        self._detailed_findings(sorted_findings)

        # 7. Strategic Remediation Roadmap
        self._remediation_roadmap(sev_counts)

        # 8. Formal Conclusion & Audit Sign-off
        self._disclaimer_and_signoff()

        doc.build(
            self.story,
            onFirstPage=self._page_template,
            onLaterPages=self._page_template,
        )
        return self.output_path

    # ─── 1. Cover Page ────────────────────────────────────────────────────────

    def _cover_page(self, scan_result, operator, total, risk):
        s = self.s
        is_pt = self.language == "pt"

        risk_label = "CRÍTICO" if risk >= 75 else "ALTO" if risk >= 50 else "MÉDIO" if risk >= 25 else "BAIXO"
        risk_color = C_CRITICAL if risk >= 75 else C_HIGH if risk >= 50 else C_MEDIUM if risk >= 25 else C_LOW

        pkg = scan_result.get("package_name", "com.application.mobile")
        platform = scan_result.get("platform", "Android / iOS")
        filename = scan_result.get("filename", "app-release.apk")
        version = scan_result.get("app_version", "1.0.0")

        self.story += [
            Spacer(1, 0.8*cm),
            # Formal Compliance Header
            Table([[
                Paragraph("🏛️ RELATÓRIO OFICIAL DE AUDITORIA DE SEGURANÇA EM APLICATIVOS MÓVEIS (OWASP MASVS v2.0)<br/>"
                          "<font size=7 color='#94a3b8'>Conforme OWASP Mobile Security Testing Guide (MASTG) e Diretrizes NIST SP 800-115</font>" if is_pt else
                          "🏛️ OFFICIAL MOBILE APPLICATION SECURITY AUDIT & PENETRATION TEST REPORT (OWASP MASVS v2.0)<br/>"
                          "<font size=7 color='#94a3b8'>In accordance with OWASP MASTG and NIST SP 800-115 Guidelines</font>",
                          ParagraphStyle("hd_badge", fontSize=8.5, textColor=C_CYAN, fontName="Helvetica-Bold", alignment=TA_CENTER, leading=12))
            ]], colWidths=[17.5*cm], style=[
                ("BACKGROUND", (0,0), (-1,-1), C_CARD),
                ("BOX", (0,0), (-1,-1), 1, C_BORDER_HI),
                ("TOPPADDING", (0,0), (-1,-1), 7),
                ("BOTTOMPADDING", (0,0), (-1,-1), 7),
            ]),
            Spacer(1, 0.8*cm),

            # Document Title
            Paragraph("RELATÓRIO DE PENTEST MOBILE (SAST & DAST)", s["title"]) if is_pt else
            Paragraph("MOBILE APPLICATION PENETRATION TEST REPORT", s["title"]),
            Paragraph("Auditoria Automatizada de Bytecode, Descompilação, Criptografia e Armazenamento Local", s["subtitle"]) if is_pt else
            Paragraph("Automated Bytecode Analysis, Decompilation, Cryptography & Local Storage Audit", s["subtitle"]),
            Spacer(1, 0.6*cm),

            # Document Control & Scope Table
            Table([
                [
                    Paragraph("<b>Pacote / Package Name:</b>", s["label"]),
                    Paragraph(f"<b>{pkg}</b>", ParagraphStyle("tv", fontSize=9, textColor=C_CYAN, fontName="Helvetica-Bold"))
                ],
                [
                    Paragraph("<b>Arquivo / Binário Auditado:</b>", s["label"]),
                    Paragraph(f"{filename} (Versão: {version})", s["body"])
                ],
                [
                    Paragraph("<b>Plataforma & Target SDK:</b>", s["label"]),
                    Paragraph(f"{platform} — Target SDK: {scan_result.get('target_sdk', 'Android 34 / iOS 17')}", s["body"])
                ],
                [
                    Paragraph("<b>Auditor / Autor:</b>", s["label"]),
                    Paragraph("Felipe Costa - fsec.costa@gmail.com", s["body"])
                ],
                [
                    Paragraph("<b>Padrão de Referência:</b>", s["label"]),
                    Paragraph("OWASP MASVS v2.0 (L1 + L2 + Resilience) | CWE | CVSS v3.1", s["body"])
                ],
                [
                    Paragraph("<b>Metodologia de Análise:</b>", s["label"]),
                    Paragraph("Static Application Security Testing (SAST) & Reverse Engineering", s["body"])
                ],
                [
                    Paragraph("<b>Data da Avaliação:</b>", s["label"]),
                    Paragraph(datetime.now(timezone.utc).strftime("%d/%m/%Y às %H:%M UTC"), s["body"])
                ],
                [
                    Paragraph("<b>Total de Achados Auditados:</b>", s["label"]),
                    Paragraph(f"<b>{total} vulnerabilidades identificadas</b>", ParagraphStyle("tot", fontSize=9, textColor=C_CYAN, fontName="Helvetica-Bold"))
                ],
                [
                    Paragraph("<b>Índice de Risco do Aplicativo:</b>", s["label"]),
                    Paragraph(f"<b>{risk}/100 — CLASSIFICAÇÃO {risk_label} ({scan_result.get('risk_grade', 'N/A')})</b>", ParagraphStyle("rk", fontSize=9, textColor=risk_color, fontName="Helvetica-Bold"))
                ],
            ], colWidths=[6.2*cm, 11*cm], style=[
                ("BACKGROUND", (0,0), (-1,-1), C_CARD),
                ("BOX", (0,0), (-1,-1), 1, C_BORDER),
                ("INNERGRID", (0,0), (-1,-1), 0.5, C_BORDER),
                ("TOPPADDING", (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LEFTPADDING", (0,0), (-1,-1), 10),
            ]),

            Spacer(1, 1.2*cm),
            HRFlowable(width="90%", thickness=1, color=C_BORDER, spaceAfter=10),
            Paragraph("<b>CLASSIFICAÇÃO DE SEGURANÇA: ESTRITAMENTE CONFIDENCIAL</b><br/>"
                      "Documento restrito à Diretoria de Engenharia de Software, Segurança da Informação e Auditoria.",
                      ParagraphStyle("conf", fontSize=7.5, textColor=C_MUTED, alignment=TA_CENTER, leading=10)),
        ]

    # ─── 2. Executive Summary ─────────────────────────────────────────────────

    def _exec_summary(self, scan_result, findings, sev_counts, risk):
        s = self.s
        is_pt = self.language == "pt"

        self.story.append(Paragraph("1. Sumário Executivo & Diagnóstico do Aplicativo", s["h1"]) if is_pt else Paragraph("1. Executive Summary & Application Diagnosis", s["h1"]))
        self.story.append(HRFlowable(width="100%", thickness=1.5, color=C_CYAN, spaceAfter=8))

        risk_label = "CRÍTICO" if risk >= 75 else "ALTO" if risk >= 50 else "MÉDIO" if risk >= 25 else "BAIXO"
        risk_color = C_CRITICAL if risk >= 75 else C_HIGH if risk >= 50 else C_MEDIUM if risk >= 25 else C_LOW

        pkg = scan_result.get("package_name", "App")

        intro_text = (
            f"O presente relatório consolida os resultados da auditoria de segurança estática (SAST) e avaliação de resiliência "
            f"executada sobre o pacote móvel <b>{pkg}</b>. O exame compreendeu a descompilação de bytecode, análise de arquivos de manifesto, "
            f"rastreamento de credenciais estáticas (*Hardcoded Secrets*), validação de cifras criptográficas e mecanismos de defesa contra engenharia reversa."
            if is_pt else
            f"This report consolidates the results of the static application security testing (SAST) and resilience assessment "
            f"performed on the mobile package <b>{pkg}</b>. The evaluation covered bytecode decompilation, manifest configuration audits, "
            f"hardcoded secret extraction, cryptographic cipher verification, and reverse-engineering anti-tamper mechanisms."
        )
        self.story.append(Paragraph(intro_text, s["body_justify"]))
        self.story.append(Spacer(1, 6))

        # KPI Metric Cards Table
        kpi_data = [
            [
                Paragraph("<b>SCORE DE RISCO</b>", ParagraphStyle("k1", fontSize=7.5, textColor=C_MUTED, alignment=TA_CENTER)),
                Paragraph("<b>CRÍTICO</b>", ParagraphStyle("k2", fontSize=7.5, textColor=C_CRITICAL, alignment=TA_CENTER)),
                Paragraph("<b>ALTO</b>", ParagraphStyle("k3", fontSize=7.5, textColor=C_HIGH, alignment=TA_CENTER)),
                Paragraph("<b>MÉDIO</b>", ParagraphStyle("k4", fontSize=7.5, textColor=C_MEDIUM, alignment=TA_CENTER)),
                Paragraph("<b>STATUS GERAL</b>", ParagraphStyle("k5", fontSize=7.5, textColor=C_CYAN, alignment=TA_CENTER)),
            ],
            [
                Paragraph(f"<b><font size=14 color='{risk_color.hexval()}'>{risk}/100</font></b>", ParagraphStyle("v1", alignment=TA_CENTER)),
                Paragraph(f"<b><font size=14 color='#ef4444'>{sev_counts.get('CRITICAL', 0)}</font></b>", ParagraphStyle("v2", alignment=TA_CENTER)),
                Paragraph(f"<b><font size=14 color='#f97316'>{sev_counts.get('HIGH', 0)}</font></b>", ParagraphStyle("v3", alignment=TA_CENTER)),
                Paragraph(f"<b><font size=14 color='#eab308'>{sev_counts.get('MEDIUM', 0)}</font></b>", ParagraphStyle("v4", alignment=TA_CENTER)),
                Paragraph(f"<b><font size=9.5 color='{risk_color.hexval()}'>{risk_label}</font></b>", ParagraphStyle("v5", alignment=TA_CENTER)),
            ]
        ]
        t_kpi = Table(kpi_data, colWidths=[3.5*cm, 3.5*cm, 3.5*cm, 3.5*cm, 3.5*cm], style=[
            ("BACKGROUND", (0,0), (-1,-1), C_CARD),
            ("BOX", (0,0), (-1,-1), 1, C_BORDER),
            ("INNERGRID", (0,0), (-1,-1), 0.5, C_BORDER),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ])
        self.story.append(t_kpi)

    # ─── 3. OWASP MASVS v2.0 Architecture Matrix ──────────────────────────────

    def _masvs_architecture_matrix(self, scan_result):
        s = self.s
        is_pt = self.language == "pt"

        self.story.append(Paragraph("2. Conformidade com a Matriz OWASP MASVS v2.0", s["h1"]) if is_pt else Paragraph("2. OWASP MASVS v2.0 Compliance Matrix", s["h1"]))
        self.story.append(HRFlowable(width="100%", thickness=1.5, color=C_CYAN, spaceAfter=8))

        scores = scan_result.get("owasp_masvs_scores", {
            "MASVS-STORAGE": 40,
            "MASVS-CRYPTO": 45,
            "MASVS-AUTH": 85,
            "MASVS-NETWORK": 50,
            "MASVS-PLATFORM": 55,
            "MASVS-CODE": 65,
            "MASVS-RESILIENCE": 25,
        })

        table_rows = [
            [
                Paragraph("<b>Domínio OWASP MASVS</b>", s["label"]),
                Paragraph("<b>Descrição do Controle</b>", s["label"]),
                Paragraph("<b>Aderência (%)</b>", s["label"]),
                Paragraph("<b>Avaliação Técnica</b>", s["label"]),
            ]
        ]

        masvs_meta = [
            ("MASVS-STORAGE", "Armazenamento Seguro de Dados & SharedPreferences", scores.get("MASVS-STORAGE", 50)),
            ("MASVS-CRYPTO", "Criptografia Forte (AES-GCM, Keystore/Keychain)", scores.get("MASVS-CRYPTO", 50)),
            ("MASVS-AUTH", "Autenticação e Gestão de Sessão no Cliente", scores.get("MASVS-AUTH", 85)),
            ("MASVS-NETWORK", "Comunicação Segura & SSL Certificate Pinning", scores.get("MASVS-NETWORK", 50)),
            ("MASVS-PLATFORM", "Interação com o SO, IPC e Permissões de Overlay", scores.get("MASVS-PLATFORM", 55)),
            ("MASVS-CODE", "Qualidade do Código e Compilação Hardened", scores.get("MASVS-CODE", 65)),
            ("MASVS-RESILIENCE", "Anti-Tamper, Anti-Root/Jailbreak e Detecção Frida", scores.get("MASVS-RESILIENCE", 25)),
        ]

        for code, desc, sc in masvs_meta:
            stat_color = "#ef4444" if sc < 50 else ("#f97316" if sc < 70 else "#10b981")
            status_txt = "NÃO CONFORME" if sc < 50 else ("PARCIAL" if sc < 70 else "CONFORME")
            table_rows.append([
                Paragraph(f"<b>{code}</b>", s["body"]),
                Paragraph(desc, s["body"]),
                Paragraph(f"<b><font color='{stat_color}'>{sc}%</font></b>", s["body"]),
                Paragraph(f"<b><font color='{stat_color}'>{status_txt}</font></b>", s["body"]),
            ])

        t_masvs = Table(table_rows, colWidths=[4*cm, 7.5*cm, 2.8*cm, 3.2*cm], style=[
            ("BACKGROUND", (0,0), (-1,0), C_CARD),
            ("BACKGROUND", (0,1), (-1,-1), HexColor("#0a1120")),
            ("BOX", (0,0), (-1,-1), 1, C_BORDER),
            ("INNERGRID", (0,0), (-1,-1), 0.5, C_BORDER),
            ("TOPPADDING", (0,0), (-1,-1), 4.5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4.5),
        ])
        self.story.append(t_masvs)

    # ─── 4. Dangerous Permissions & Hardcoded Secrets ─────────────────────────

    def _permissions_and_secrets_section(self, scan_result):
        s = self.s
        is_pt = self.language == "pt"

        self.story.append(Paragraph("3. Permissões Críticas & Extração de Chaves Hardcoded", s["h1"]) if is_pt else Paragraph("3. Critical Permissions & Hardcoded Secrets Extraction", s["h1"]))
        self.story.append(HRFlowable(width="100%", thickness=1.5, color=C_CYAN, spaceAfter=8))

        # Permissions Table
        perms = scan_result.get("permissions", [])
        if perms:
            self.story.append(Paragraph("<b>Permissões Declaradas no Pacote:</b>", s["h2"]))
            p_rows = [
                [
                    Paragraph("<b>Permissão</b>", s["label"]),
                    Paragraph("<b>Severidade</b>", s["label"]),
                    Paragraph("<b>Vetor de Ataque / Impacto de Risco</b>", s["label"]),
                ]
            ]
            for p in perms[:6]:
                sev = p.get("severity", "INFO")
                scolor = SEV_COLORS.get(sev, C_INFO).hexval()
                p_rows.append([
                    Paragraph(f"<b>{p.get('permission')}</b>", s["mono"]),
                    Paragraph(f"<b><font color='{scolor}'>{sev}</font></b>", s["body"]),
                    Paragraph(p.get("security_impact", p.get("description", "")), s["body"]),
                ])

            t_p = Table(p_rows, colWidths=[6.5*cm, 2.5*cm, 8.5*cm], style=[
                ("BACKGROUND", (0,0), (-1,0), C_CARD),
                ("BACKGROUND", (0,1), (-1,-1), HexColor("#0a1120")),
                ("BOX", (0,0), (-1,-1), 1, C_BORDER),
                ("INNERGRID", (0,0), (-1,-1), 0.5, C_BORDER),
                ("TOPPADDING", (0,0), (-1,-1), 4),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ])
            self.story.append(t_p)
            self.story.append(Spacer(1, 8))

        # Secrets Table
        secrets = scan_result.get("hardcoded_secrets", [])
        if secrets:
            self.story.append(Paragraph("<b>Credenciais e Chaves Extraídas no Bytecode:</b>", s["h2"]))
            sec_rows = [
                [
                    Paragraph("<b>Tipo de Credencial</b>", s["label"]),
                    Paragraph("<b>Severidade</b>", s["label"]),
                    Paragraph("<b>Valor Mascarado Extraído</b>", s["label"]),
                    Paragraph("<b>CWE</b>", s["label"]),
                ]
            ]
            for sec in secrets:
                sev = sec.get("severity", "HIGH")
                scolor = SEV_COLORS.get(sev, C_HIGH).hexval()
                sec_rows.append([
                    Paragraph(f"<b>{sec.get('secret_type')}</b>", s["body"]),
                    Paragraph(f"<b><font color='{scolor}'>{sev}</font></b>", s["body"]),
                    Paragraph(sec.get("masked_value", ""), s["mono_code"]),
                    Paragraph(sec.get("cwe_id", "CWE-798"), s["body_dim"]),
                ])

            t_sec = Table(sec_rows, colWidths=[4.5*cm, 2.5*cm, 7*cm, 3.5*cm], style=[
                ("BACKGROUND", (0,0), (-1,0), C_CARD),
                ("BACKGROUND", (0,1), (-1,-1), HexColor("#0a1120")),
                ("BOX", (0,0), (-1,-1), 1, C_BORDER),
                ("INNERGRID", (0,0), (-1,-1), 0.5, C_BORDER),
                ("TOPPADDING", (0,0), (-1,-1), 4),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ])
            self.story.append(t_sec)

    # ─── 5. Consolidated Risk Matrix ──────────────────────────────────────────

    def _findings_summary_table(self, findings):
        s = self.s
        is_pt = self.language == "pt"

        self.story.append(Paragraph("4. Matriz Consolidada de Vulnerabilidades & SLAs", s["h1"]) if is_pt else Paragraph("4. Consolidated Vulnerability Matrix & SLAs", s["h1"]))
        self.story.append(HRFlowable(width="100%", thickness=1.5, color=C_CYAN, spaceAfter=8))

        headers = [
            Paragraph("<b>ID</b>", s["label"]),
            Paragraph("<b>Severidade</b>", s["label"]),
            Paragraph("<b>CVSS</b>", s["label"]),
            Paragraph("<b>MASVS / CWE</b>", s["label"]),
            Paragraph("<b>Título da Vulnerabilidade</b>", s["label"]),
            Paragraph("<b>SLA de Correção</b>", s["label"]),
        ]
        rows = [headers]

        for f in findings:
            sev = str(f.get("severity", "INFO")).upper()
            scolor = SEV_COLORS.get(sev, C_INFO).hexval()
            sla = BACEN_SLAS.get(sev, "30 Dias")
            masvs_ref = f.get("masvs_id", f.get("cwe_id", "MASVS"))

            rows.append([
                Paragraph(f"<b>{f.get('id', 'VULN')}</b>", s["mono"]),
                Paragraph(f"<b><font color='{scolor}'>{sev}</font></b>", s["body"]),
                Paragraph(f"<b>{f.get('cvss_score', 0.0)}</b>", s["body"]),
                Paragraph(str(masvs_ref), s["body_dim"]),
                Paragraph(str(f.get("title", "")), s["body"]),
                Paragraph(sla, s["body_dim"]),
            ])

        t = Table(rows, colWidths=[2.6*cm, 2.2*cm, 1.4*cm, 3.2*cm, 5.1*cm, 3.0*cm], style=[
            ("BACKGROUND", (0,0), (-1,0), C_CARD),
            ("BACKGROUND", (0,1), (-1,-1), HexColor("#0a1120")),
            ("BOX", (0,0), (-1,-1), 1, C_BORDER),
            ("INNERGRID", (0,0), (-1,-1), 0.5, C_BORDER),
            ("TOPPADDING", (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ])
        self.story.append(t)

    # ─── 6. Detailed Technical Dossier ────────────────────────────────────────

    def _detailed_findings(self, findings):
        s = self.s
        is_pt = self.language == "pt"

        self.story.append(Paragraph("5. Dossiê Técnico Detalhado de Vulnerabilidades", s["h1"]) if is_pt else Paragraph("5. Detailed Technical Vulnerability Dossier", s["h1"]))
        self.story.append(HRFlowable(width="100%", thickness=1.5, color=C_CYAN, spaceAfter=8))

        for idx, f in enumerate(findings, 1):
            sev = str(f.get("severity", "INFO")).upper()
            scolor = SEV_COLORS.get(sev, C_INFO).hexval()
            masvs_ref = f.get("masvs_id", "OWASP MASVS")
            cwe = f.get("cwe_id", "CWE-General")
            cvss = f.get("cvss_score", 0.0)

            card_content = [
                [
                    Paragraph(f"<b>#{idx} — {f.get('title', 'Vulnerabilidade')}</b>", ParagraphStyle("fh", fontSize=10, textColor=C_WHITE, fontName="Helvetica-Bold")),
                    Paragraph(f"<b><font color='{scolor}'>{sev}</font> | CVSS {cvss}</b>", ParagraphStyle("fs", fontSize=9, textColor=C_WHITE, alignment=TA_RIGHT, fontName="Helvetica-Bold"))
                ],
                [
                    Paragraph(f"<b>Padrão MASVS:</b> {masvs_ref}  |  <b>CWE:</b> {cwe}", s["mono"]),
                    Paragraph("", s["body"])
                ],
                [
                    Paragraph(f"<b>Descrição Técnica & Vetor de Exploração:</b><br/>{f.get('description', 'Sem descrição.')}", s["body_justify"]),
                    Paragraph("", s["body"])
                ],
                [
                    Paragraph(f"<b>Plano de Remediação & Código Recomendado:</b><br/>{f.get('recommendation', 'Aplicar hardening de segurança no código-fonte.')}", s["body_justify"]),
                    Paragraph("", s["body"])
                ],
            ]

            t_card = Table(card_content, colWidths=[12.5*cm, 5.0*cm], style=[
                ("SPAN", (0,1), (1,1)),
                ("SPAN", (0,2), (1,2)),
                ("SPAN", (0,3), (1,3)),
                ("BACKGROUND", (0,0), (-1,-1), C_CARD),
                ("BOX", (0,0), (-1,-1), 1, C_BORDER),
                ("LINEBELOW", (0,0), (-1,0), 1, HexColor(scolor)),
                ("TOPPADDING", (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LEFTPADDING", (0,0), (-1,-1), 8),
                ("RIGHTPADDING", (0,0), (-1,-1), 8),
            ])

            self.story.append(KeepTogether([t_card, Spacer(1, 8)]))

    # ─── 7. Remediation Roadmap ───────────────────────────────────────────────

    def _remediation_roadmap(self, sev_counts):
        s = self.s
        is_pt = self.language == "pt"

        self.story.append(PageBreak())
        self.story.append(Paragraph("6. Roadmap Estratégico de Remediação em 3 Fases", s["h1"]) if is_pt else Paragraph("6. Strategic 3-Phase Remediation Roadmap", s["h1"]))
        self.story.append(HRFlowable(width="100%", thickness=1.5, color=C_CYAN, spaceAfter=8))

        phases = [
            ("FASE 1 — RESPOSTA IMEDIATA (24 a 48 HORAS)", C_CRITICAL, [
                "Revogar e rotacionar todas as chaves de API e credenciais AWS/GCP extraídas no APK/IPA.",
                "Publicar hotfix emergencial desabilitando flags inseguras (ex: android:allowBackup='false').",
                "Remover permissões críticas de Overlay (SYSTEM_ALERT_WINDOW) para anular vetores de Tapjacking."
            ]),
            ("FASE 2 — HARDENING CRIPTOGRÁFICO & REDE (ATÉ 7 DIAS)", C_HIGH, [
                "Implementar SSL Certificate Pinning estrito com suporte a backup pin no Network Security Config.",
                "Migrar cifras inseguras (AES/ECB, MD5) para AES-256-GCM com chaves no Android Keystore / iOS Keychain.",
                "Bloquear tráfego HTTP em texto claro através de usesCleartextTraffic='false'."
            ]),
            ("FASE 3 — RESILIÊNCIA E BLINDAGEM CONTRA ENGENHARIA REVERSA (ATÉ 30 DIAS)", C_CYAN, [
                "Integrar verificações ativas de Root/Jailbreak e detecção de hooks Frida/Xposed.",
                "Ativar regras avançadas de ofuscação com ProGuard/R8 e verificação de assinatura no runtime.",
                "Implementar pipeline de DevSecOps com validação contínua OWASP MASVS no CI/CD."
            ])
        ]

        for ptitle, pcolor, actions in phases:
            phase_items = "<br/>".join([f"• {a}" for a in actions])
            p_data = [
                [Paragraph(f"<b>{ptitle}</b>", ParagraphStyle("ph", fontSize=9, textColor=pcolor, fontName="Helvetica-Bold"))],
                [Paragraph(phase_items, s["body"])]
            ]
            t_phase = Table(p_data, colWidths=[17.5*cm], style=[
                ("BACKGROUND", (0,0), (-1,-1), C_CARD),
                ("BOX", (0,0), (-1,-1), 1, C_BORDER),
                ("LINEBELOW", (0,0), (-1,0), 1, pcolor),
                ("TOPPADDING", (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LEFTPADDING", (0,0), (-1,-1), 8),
            ])
            self.story.append(t_phase)
            self.story.append(Spacer(1, 6))

    # ─── 8. Auditor Sign-off ──────────────────────────────────────────────────

    def _disclaimer_and_signoff(self):
        s = self.s
        self.story.append(Spacer(1, 10))
        sig_data = [
            [
                Paragraph("<b>Auditor Responsável / Lead Auditor:</b><br/>Felipe Costa<br/><font size=7 color='#94a3b8'>Cybersecurity Architect & Offensive Security Specialist</font>", s["body"]),
                Paragraph("<b>Canal de Contato Institucional:</b><br/>fsec.costa@gmail.com<br/><font size=7 color='#94a3b8'>morfeusec OSINT Platform Lead</font>", s["body"]),
            ]
        ]
        t_sig = Table(sig_data, colWidths=[8.5*cm, 8.5*cm], style=[
            ("LINEABOVE", (0,0), (0,0), 1, C_MUTED),
            ("LINEABOVE", (1,0), (1,0), 1, C_MUTED),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ])
        self.story.append(t_sig)
        self.story.append(Spacer(1, 6))
        self.story.append(Paragraph("morfeusec OSINT — Escrito por Felipe Costa - fsec.costa@gmail.com", s["footer"]))

    # ─── Background Template ──────────────────────────────────────────────────

    @staticmethod
    def _page_template(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_MUTED)
        canvas.setFont("Helvetica", 7)
        canvas.drawCentredString(A4[0]/2, 1.1*cm, f"morfeusec OSINT — Escrito por Felipe Costa - fsec.costa@gmail.com — Página {doc.page}")
        canvas.restoreState()


def generate_mobile_pdf(
    output_path: str,
    scan_result: Dict[str, Any],
    operator: str = "Felipe Costa - fsec.costa@gmail.com",
    language: str = "pt",
) -> str:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    report = MobilePentestReportPDF(output_path)
    return report.build(
        scan_result=scan_result,
        operator=operator,
        language=language,
    )


def generate_mobile_pdf_bytes(
    scan_result: Dict[str, Any],
    operator: str = "Felipe Costa - fsec.costa@gmail.com",
    language: str = "pt",
) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=1.6*cm, rightMargin=1.6*cm,
        topMargin=1.6*cm, bottomMargin=1.6*cm,
    )
    report = MobilePentestReportPDF("")
    report.language = language

    findings = scan_result.get("findings", [])
    order_map = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    sorted_findings = sorted(
        findings,
        key=lambda f: (order_map.get(str(f.get("severity", "INFO")).upper(), 99), -float(f.get("cvss_score", 0.0) or 0.0))
    )
    sev_counts = {s: sum(1 for f in sorted_findings if str(f.get("severity", "")).upper() == s) for s in SEVERITY_ORDER}
    risk_score = scan_result.get("risk_score", 0)

    report._cover_page(scan_result, operator, len(sorted_findings), risk_score)
    report.story.append(PageBreak())
    report._exec_summary(scan_result, sorted_findings, sev_counts, risk_score)
    report.story.append(Spacer(1, 8))
    report._masvs_architecture_matrix(scan_result)
    report.story.append(PageBreak())
    report._permissions_and_secrets_section(scan_result)
    report.story.append(Spacer(1, 8))
    report._findings_summary_table(sorted_findings)
    report.story.append(PageBreak())
    report._detailed_findings(sorted_findings)
    report._remediation_roadmap(sev_counts)
    report._disclaimer_and_signoff()

    doc.build(
        report.story,
        onFirstPage=report._page_template,
        onLaterPages=report._page_template,
    )
    return buffer.getvalue()


def generate_mobile_xlsx(scan_result: Dict[str, Any]) -> bytes:
    import openpyxl
    from openpyxl.styles import Font, PatternFill

    wb = openpyxl.Workbook()
    header_fill = PatternFill(start_color="0D1B2A", end_color="0D1B2A", fill_type="solid")
    white_bold = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    title_font = Font(name="Calibri", size=14, bold=True, color="00D4FF")

    # Sheet 1: Executive Summary
    ws1 = wb.active
    ws1.title = "Executive Summary"
    ws1.views.sheetView[0].showGridLines = True
    ws1["A1"] = "morfeusec OSINT — Mobile Application Penetration Test Report"
    ws1["A1"].font = title_font
    ws1["A2"] = f"Audit Date: {scan_result.get('scanned_at')} | Target: {scan_result.get('package_name')}"
    ws1["A2"].font = Font(name="Calibri", size=10, italic=True, color="555555")

    ws1.append([])
    ws1.append(["Attribute", "Assessment Detail"])
    for col in [1, 2]:
        cell = ws1.cell(row=4, column=col)
        cell.fill = header_fill
        cell.font = white_bold

    summary_rows = [
        ("Application Package Name", scan_result.get("package_name")),
        ("Package File Name", scan_result.get("filename")),
        ("Platform Target", scan_result.get("platform")),
        ("Application Version", scan_result.get("app_version")),
        ("Target SDK / Platform Version", scan_result.get("target_sdk")),
        ("Overall Risk Score (0-100)", f"{scan_result.get('risk_score')} / 100"),
        ("OWASP MASVS Security Grade", scan_result.get("risk_grade")),
        ("Author / Auditor", "Escrito por Felipe Costa - fsec.costa@gmail.com"),
        ("Total Vulnerabilities Identified", scan_result.get("findings_summary", {}).get("total", len(scan_result.get("findings", [])))),
        ("Critical Severity Findings", scan_result.get("findings_summary", {}).get("critical", 0)),
        ("High Severity Findings", scan_result.get("findings_summary", {}).get("high", 0)),
        ("Medium Severity Findings", scan_result.get("findings_summary", {}).get("medium", 0)),
        ("Low Severity Findings", scan_result.get("findings_summary", {}).get("low", 0)),
    ]
    for row in summary_rows:
        ws1.append(list(row))
    ws1.column_dimensions["A"].width = 35
    ws1.column_dimensions["B"].width = 60

    # Sheet 2: Vulnerabilities
    ws2 = wb.create_sheet(title="Vulnerabilities & CWE")
    ws2.views.sheetView[0].showGridLines = True
    v_headers = ["ID", "Severity", "CVSS", "OWASP MASVS", "CWE", "Vulnerability Title", "Remediation Guidance"]
    ws2.append(v_headers)
    for col in range(1, len(v_headers) + 1):
        cell = ws2.cell(row=1, column=col)
        cell.fill = header_fill
        cell.font = white_bold
    for f in scan_result.get("findings", []):
        ws2.append([
            f.get("id"),
            f.get("severity"),
            f.get("cvss_score"),
            f.get("masvs_id"),
            f.get("cwe_id"),
            f.get("title"),
            f.get("recommendation"),
        ])
    ws2.column_dimensions["A"].width = 15
    ws2.column_dimensions["B"].width = 14
    ws2.column_dimensions["C"].width = 10
    ws2.column_dimensions["D"].width = 18
    ws2.column_dimensions["E"].width = 25
    ws2.column_dimensions["F"].width = 45
    ws2.column_dimensions["G"].width = 60

    # Sheet 3: Permissions
    ws3 = wb.create_sheet(title="Permissions Matrix")
    ws3.views.sheetView[0].showGridLines = True
    p_headers = ["Android Permission", "Severity", "Purpose / Description", "Security Risk Impact"]
    ws3.append(p_headers)
    for col in range(1, len(p_headers) + 1):
        cell = ws3.cell(row=1, column=col)
        cell.fill = header_fill
        cell.font = white_bold
    for p in scan_result.get("permissions", []):
        ws3.append([
            p.get("permission"),
            p.get("severity"),
            p.get("description"),
            p.get("security_impact"),
        ])
    ws3.column_dimensions["A"].width = 40
    ws3.column_dimensions["B"].width = 14
    ws3.column_dimensions["C"].width = 30
    ws3.column_dimensions["D"].width = 50

    output = io.BytesIO()
    wb.save(output)
    return output.getvalue()

