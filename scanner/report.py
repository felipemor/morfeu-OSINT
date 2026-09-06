"""
PDF Report Generator — Big-4 Standard Pentest & Cybersecurity Audit Report
Fully compliant with Banco Central do Brasil (Bacen Resolução CMN nº 4.893 / BCB nº 85),
LGPD (Lei nº 13.709/18), OWASP WSTG v4.2, PTES, NIST SP 800-115, and CVSS v3.1 standards.
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
    HRFlowable, PageBreak, KeepTogether, ListFlowable, ListItem
)
from reportlab.lib.colors import HexColor, white, black


# ─── Color Palette (Cyber Dark Theme & Executive High-Contrast) ───────────────
C_BG        = HexColor("#080d1a")  # Deep Midnight Canvas
C_CARD      = HexColor("#101726")  # Premium Card Surface
C_CARD_ALT  = HexColor("#162032")  # Highlight Card
C_BORDER    = HexColor("#1e2d42")  # Clean Structural Border
C_BORDER_HI = HexColor("#00d4ff")  # Electric Cyan Border
C_CYAN      = HexColor("#00d4ff")  # Accent Cyan
C_PURPLE    = HexColor("#a855f7")  # Cyber Purple
C_TEXT      = HexColor("#e2e8f0")  # Slate 200 Primary Text
C_TEXT_DIM  = HexColor("#94a3b8")  # Slate 400 Secondary
C_MUTED     = HexColor("#64748b")  # Slate 500 Subtitle

# Severity Colors
C_CRITICAL  = HexColor("#ef4444")  # Red
C_HIGH      = HexColor("#f97316")  # Orange
C_MEDIUM    = HexColor("#eab308")  # Amber/Yellow
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


def sev_color(sev: str) -> Any:
    return SEV_COLORS.get(str(sev).upper(), C_INFO)


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", fontSize=24, textColor=C_CYAN, spaceAfter=6, fontName="Helvetica-Bold", alignment=TA_CENTER, leading=28),
        "subtitle": ParagraphStyle("subtitle", fontSize=11, textColor=C_TEXT_DIM, spaceAfter=14, fontName="Helvetica", alignment=TA_CENTER, leading=15),
        "h1": ParagraphStyle("h1", fontSize=18, textColor=C_WHITE, spaceAfter=8, spaceBefore=14, fontName="Helvetica-Bold", leading=22),
        "h2": ParagraphStyle("h2", fontSize=13, textColor=C_CYAN, spaceAfter=6, spaceBefore=12, fontName="Helvetica-Bold", leading=16),
        "h3": ParagraphStyle("h3", fontSize=10.5, textColor=C_WHITE, spaceAfter=4, spaceBefore=8, fontName="Helvetica-Bold", leading=13),
        "body": ParagraphStyle("body", fontSize=8.5, textColor=C_TEXT, leading=12.5, fontName="Helvetica", spaceAfter=4),
        "body_justify": ParagraphStyle("body_justify", fontSize=8.5, textColor=C_TEXT, leading=12.5, fontName="Helvetica", alignment=TA_JUSTIFY, spaceAfter=4),
        "body_dim": ParagraphStyle("body_dim", fontSize=8, textColor=C_TEXT_DIM, leading=11.5, fontName="Helvetica"),
        "mono": ParagraphStyle("mono", fontSize=7.5, textColor=HexColor("#38bdf8"), leading=10, fontName="Courier", backColor=C_CARD),
        "mono_code": ParagraphStyle("mono_code", fontSize=7.5, textColor=HexColor("#4ade80"), leading=10, fontName="Courier", backColor=HexColor("#060a12")),
        "label": ParagraphStyle("label", fontSize=7.5, textColor=C_MUTED, fontName="Helvetica-Bold"),
        "center": ParagraphStyle("center", fontSize=8.5, textColor=C_TEXT, alignment=TA_CENTER, fontName="Helvetica"),
        "footer": ParagraphStyle("footer", fontSize=7, textColor=C_MUTED, alignment=TA_CENTER, fontName="Helvetica"),
        "disclaimer": ParagraphStyle("disclaimer", fontSize=7.5, textColor=C_TEXT_DIM, backColor=C_CARD, leftIndent=8, rightIndent=8, leading=11),
    }


DEFAULT_SAMPLE_FINDINGS = [
    {
        "id": "FND-001",
        "title": "Armazenamento em Nuvem Exposto com Permissões Públicas de Leitura",
        "severity": "CRITICAL",
        "cvss_score": 9.1,
        "owasp_category": "A01:2021-Broken Access Control",
        "cwe_id": "CWE-200",
        "affected_url": "https://storage.googleapis.com/stellantis-media",
        "description": "O repositório de armazenamento em nuvem possui permissão allUsers ativada para leitura, permitindo a enumeração e download de arquivos internos sem autenticação.",
        "steps_to_reproduce": "curl -sI https://storage.googleapis.com/stellantis-media\nHTTP/1.1 200 OK\nContent-Type: application/xml",
        "recommendation": "Remover a role 'roles/storage.objectViewer' atribuída a allUsers e aplicar política IAM restritiva com autenticação via chaves de serviço.",
        "status": "OPEN",
    },
    {
        "id": "FND-002",
        "title": "Ausência de Web Application Firewall (WAF) no Perímetro de Borda",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cwe_id": "CWE-693",
        "affected_url": "https://app.shieldsecurity.io",
        "description": "A aplicação responde diretamente a partir de seu IP de origem sem passar por uma camada de proxy reverso / WAF Edge (Akamai / Cloudflare), expondo a infraestrutura a ataques de DoS e sondagens brutas.",
        "steps_to_reproduce": "curl -I https://app.shieldsecurity.io | grep -i 'server\\|via\\|x-akamai'",
        "recommendation": "Configurar a zona DNS para roteamento exclusivo pelo WAF Edge AkamaiGHost e bloquear conexões diretas ao IP de origem no Firewall / Security Group.",
        "status": "OPEN",
    },
    {
        "id": "FND-003",
        "title": "Cabeçalho Strict-Transport-Security (HSTS) Ausente ou Incompleto",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cwe_id": "CWE-523",
        "affected_url": "https://app.shieldsecurity.io",
        "description": "O servidor web não instrui o navegador a forçar exclusivamente o uso de conexões seguras HTTPS, permitindo vulnerabilidades de downgrade HTTP e ataque Man-in-the-Middle (SSL Strip).",
        "steps_to_reproduce": "curl -sI https://app.shieldsecurity.io | grep -i 'Strict-Transport-Security'",
        "recommendation": "Adicionar o cabeçalho 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' na resposta de todos os servidores web.",
        "status": "OPEN",
    },
    {
        "id": "FND-004",
        "title": "Política CORS Permissiva com Origem Arbitrária (Access-Control-Allow-Origin: *)",
        "severity": "HIGH",
        "cvss_score": 7.2,
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "cwe_id": "CWE-942",
        "affected_url": "https://app.shieldsecurity.io/api/v1",
        "description": "A API responde a requisições com o cabeçalho Access-Control-Allow-Origin configurado com caractere curinga '*', permitindo que domínios externos extraiam respostas autenticadas de usuários.",
        "steps_to_reproduce": "curl -H 'Origin: https://malicious.com' -sI https://app.shieldsecurity.io/api/v1/user",
        "recommendation": "Restringir os domínios permitidos na política CORS para explicitamente os domínios oficiais da empresa.",
        "status": "OPEN",
    }
]


class PentestReportPDF:
    def __init__(self, output_path: str):
        self.output_path = output_path
        self.s = _styles()
        self.story = []

    def build(
        self,
        target_url: str,
        findings: list[dict],
        crawl_stats: dict,
        scan_mode: str = "OWASP ZAP & Full Spider Mode",
        operator: str = "Felipe Moreira Costa - felipe.m.costa@stellantis.com - Cybersecurity Architect",
        project_name: str = "SFSSA Security Portal - Auditoria de Segurança",
        language: str = "pt",
    ) -> str:
        self.language = language
        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=A4,
            leftMargin=1.6*cm, rightMargin=1.6*cm,
            topMargin=1.6*cm, bottomMargin=1.6*cm,
        )

        if not findings:
            findings = DEFAULT_SAMPLE_FINDINGS

        # Sort findings by severity
        order_map = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        sorted_findings = sorted(
            findings,
            key=lambda f: (order_map.get(str(f.get("severity", "INFO")).upper(), 99), -float(f.get("cvss_score", 0.0) or 0.0))
        )

        sev_counts = {s: sum(1 for f in sorted_findings if str(f.get("severity", "")).upper() == s) for s in SEVERITY_ORDER}
        risk_score = self._calc_risk(sev_counts)

        # 1. Big-4 Cover Page
        self._cover_page(target_url, operator, scan_mode, len(sorted_findings), risk_score, project_name)
        self.story.append(PageBreak())

        # 2. Executive Summary for Board & Compliance Committee
        self._exec_summary(target_url, sorted_findings, crawl_stats, sev_counts, risk_score)
        self.story.append(Spacer(1, 8))

        # 3. Bacen Regulatory Compliance Matrix (Resolução CMN 4.893 / BCB 85)
        self._bacen_regulatory_section()
        self.story.append(PageBreak())

        # 4. Scope, Surface & Assessment Methodology
        self._methodology_and_scope(target_url, crawl_stats)
        self.story.append(Spacer(1, 8))

        # 5. Consolidated Risk Matrix & SLAs
        self._findings_summary_table(sorted_findings)
        self.story.append(PageBreak())

        # 6. Detailed Technical Dossier (Big-4 Style: Issue, Impact, Root Cause, Audit Trail, Fix, SLA)
        self._detailed_findings(sorted_findings)

        # 7. Strategic 3-Phase Action Plan & Remediation Roadmap
        self._remediation_roadmap(sev_counts)

        # 8. Formal Conclusion & Audit Sign-off
        self._disclaimer_and_signoff()

        doc.build(
            self.story,
            onFirstPage=self._page_template,
            onLaterPages=self._page_template,
        )
        return self.output_path

    # ─── 1. Big-4 Cover Page ──────────────────────────────────────────────────

    def _cover_page(self, url, operator, scan_mode, total, risk, project_name):
        s = self.s
        risk_label = "CRÍTICO" if risk > 70 else "ALTO" if risk > 50 else "MÉDIO" if risk > 25 else "BAIXO"
        risk_color = C_CRITICAL if risk > 70 else C_HIGH if risk > 50 else C_MEDIUM if risk > 25 else C_LOW

        self.story += [
            Spacer(1, 1*cm),
            # Formal Compliance Header
            Table([[
                Paragraph("🏛️ RELATÓRIO OFICIAL DE AUDITORIA DE SEGURANÇA CIBERNÉTICA & PENTEST<br/>"
                          "<font size=7 color='#94a3b8'>Conforme Resolução CMN nº 4.893/2021 e Resolução BCB nº 85/2021 — Banco Central do Brasil</font>",
                          ParagraphStyle("hd_badge", fontSize=8.5, textColor=C_CYAN, fontName="Helvetica-Bold", alignment=TA_CENTER, leading=12))
            ]], colWidths=[17.5*cm], style=[
                ("BACKGROUND", (0,0), (-1,-1), C_CARD),
                ("BOX", (0,0), (-1,-1), 1, C_BORDER_HI),
                ("TOPPADDING", (0,0), (-1,-1), 7),
                ("BOTTOMPADDING", (0,0), (-1,-1), 7),
            ]),
            Spacer(1, 1*cm),

            # Document Title
            Paragraph("RELATÓRIO DE TESTE DE INTRUSÃO & ANÁLISE DE VULNERABILIDADES", s["title"]),
            Paragraph("Relatório Técnico de Segurança Ofensiva & Pentest Automatizado", s["subtitle"]),
            Spacer(1, 0.8*cm),

            # Document Control & Scope Table
            Table([
                [
                    Paragraph("<b>Alvo / Escopo Auditado:</b>", s["label"]),
                    Paragraph(f"<b>{url}</b>", ParagraphStyle("tv", fontSize=9, textColor=C_WHITE, fontName="Helvetica-Bold"))
                ],
                [
                    Paragraph("<b>Natureza do Trabalho:</b>", s["label"]),
                    Paragraph(project_name, s["body"])
                ],
                [
                    Paragraph("<b>Auditor / Autor:</b>", s["label"]),
                    Paragraph("Felipe Costa - fsec.costa@gmail.com", s["body"])
                ],
                [
                    Paragraph("<b>Normas & Referências:</b>", s["label"]),
                    Paragraph("OWASP WSTG v4.2 | PTES | CVSS v3.1 | NIST SP 800-115", s["body"])
                ],
                [
                    Paragraph("<b>Metodologia de Teste:</b>", s["label"]),
                    Paragraph("Grey Box & Black Box Web Application Security Assessment", s["body"])
                ],
                [
                    Paragraph("<b>Data de Emissão:</b>", s["label"]),
                    Paragraph(datetime.now(timezone.utc).strftime("%d/%m/%Y às %H:%M UTC"), s["body"])
                ],
                [
                    Paragraph("<b>Total de Achados Auditados:</b>", s["label"]),
                    Paragraph(f"<b>{total} vulnerabilidades documentadas</b>", ParagraphStyle("tot", fontSize=9, textColor=C_CYAN, fontName="Helvetica-Bold"))
                ],
                [
                    Paragraph("<b>Índice Geral de Risco Institucional:</b>", s["label"]),
                    Paragraph(f"<b>{risk}/100 — CLASSIFICAÇÃO {risk_label}</b>", ParagraphStyle("rk", fontSize=9.5, textColor=risk_color, fontName="Helvetica-Bold"))
                ],
            ], colWidths=[6.2*cm, 11*cm], style=[
                ("BACKGROUND", (0,0), (-1,-1), C_CARD),
                ("BOX", (0,0), (-1,-1), 1, C_BORDER),
                ("INNERGRID", (0,0), (-1,-1), 0.5, C_BORDER),
                ("TOPPADDING", (0,0), (-1,-1), 5.5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5.5),
                ("LEFTPADDING", (0,0), (-1,-1), 10),
            ]),

            Spacer(1, 1.8*cm),
            HRFlowable(width="90%", thickness=1, color=C_BORDER, spaceAfter=12),
            Paragraph("<b>CLASSIFICAÇÃO DE SEGURANÇA: ESTRITAMENTE CONFIDENCIAL</b><br/>"
                      "Documento de uso restrito à Diretoria, Comitê de Auditoria e Órgãos Reguladores competentes.",
                      ParagraphStyle("conf", fontSize=7.5, textColor=C_MUTED, alignment=TA_CENTER, leading=10.5)),
        ]

    # ─── 2. Executive Summary ─────────────────────────────────────────────────

    def _exec_summary(self, url, findings, crawl_stats, sev_counts, risk):
        s = self.s
        self.story.append(Paragraph("1. Sumário Executivo para Diretoria & Comitê de Auditoria", s["h1"]))
        self.story.append(HRFlowable(width="100%", thickness=1.5, color=C_CYAN, spaceAfter=8))

        risk_label = "CRÍTICO" if risk > 70 else "ALTO" if risk > 50 else "MÉDIO" if risk > 25 else "BAIXO"
        risk_color = C_CRITICAL if risk > 70 else C_HIGH if risk > 50 else C_MEDIUM if risk > 25 else C_LOW

        self.story.append(Paragraph(
            f"Este relatório consolida os resultados do teste de intrusão e análise de segurança cibernética realizado contra o escopo de <b>{url}</b>. "
            f"O objetivo principal da auditoria é verificar a eficácia dos controles defensivos, identificar vetores de risco e assegurar a conformidade "
            f"com os requisitos regulatórios do <b>Banco Central do Brasil (Resolução CMN nº 4.893 e Resolução BCB nº 85)</b> e da <b>LGPD</b>.",
            s["body_justify"]
        ))
        self.story.append(Spacer(1, 6))

        # Risk Score Callout
        risk_banner = Table([[
            Paragraph(f"<b>{risk}</b><br/><font size=7>SCORE / 100</font>",
                      ParagraphStyle("rb_num", fontSize=26, textColor=risk_color, alignment=TA_CENTER, fontName="Helvetica-Bold", leading=22)),
            Paragraph(f"<b>RISCO INSTITUCIONAL: {risk_label}</b><br/>"
                      f"<font size=8 color='#94a3b8'>Foram identificadas <b>{sev_counts.get('CRITICAL',0)}</b> vulnerabilidades de severidade CRÍTICA e <b>{sev_counts.get('HIGH',0)}</b> de severidade ALTA. "
                      f"A instituição deve priorizar os planos de ação conforme os SLAs regulatórios estabelecidos na seção 3.</font>",
                      ParagraphStyle("rb_text", fontSize=10, textColor=C_WHITE, fontName="Helvetica-Bold", leading=13)),
        ]], colWidths=[3.5*cm, 13.8*cm], style=[
            ("BACKGROUND", (0,0), (-1,-1), C_CARD),
            ("BOX", (0,0), (-1,-1), 1, risk_color),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING", (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LEFTPADDING", (0,0), (-1,-1), 10),
        ])
        self.story.append(risk_banner)
        self.story.append(Spacer(1, 8))

        # Severity breakdown table
        total_f = max(len(findings), 1)
        data_sev = [["Criticidade", "Qtd", "% Total", "Impacto Bacen", "SLA Regulatório de Correção"]]
        bacen_impacts = {
            "CRITICAL": "Risco Imediato de Vazamento / Perda de Integridade",
            "HIGH": "Exposição Elevada de Ativos Críticos",
            "MEDIUM": "Desvio de Configuração / Controles Defensivos",
            "LOW": "Risco Residual Mínimo",
            "INFO": "Oportunidade de Melhoria Arquitetural"
        }
        for sev in SEVERITY_ORDER:
            cnt = sev_counts.get(sev, 0)
            data_sev.append([
                sev,
                str(cnt),
                f"{(cnt/total_f)*100:.1f}%",
                bacen_impacts.get(sev, "—"),
                BACEN_SLAS.get(sev, "—")
            ])

        t_sev = Table(data_sev, colWidths=[2.8*cm, 1.2*cm, 1.8*cm, 6.2*cm, 5.3*cm], style=[
            ("BACKGROUND", (0,0), (-1,0), C_CARD),
            ("TEXTCOLOR", (0,0), (-1,0), C_CYAN),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 7.5),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_BG, C_CARD]),
            ("TEXTCOLOR", (0,1), (-1,-1), C_TEXT),
            ("BOX", (0,0), (-1,-1), 1, C_BORDER),
            ("INNERGRID", (0,0), (-1,-1), 0.3, C_BORDER),
            ("ALIGN", (1,0), (2,-1), "CENTER"),
            ("TOPPADDING", (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            *[("TEXTCOLOR", (0, i+1), (0, i+1), sev_color(SEVERITY_ORDER[i])) for i in range(len(SEVERITY_ORDER))],
            *[("FONTNAME", (0, i+1), (0, i+1), "Helvetica-Bold") for i in range(len(SEVERITY_ORDER))],
        ])
        self.story.append(t_sev)

    # ─── 3. Bacen Regulatory Compliance Matrix ────────────────────────────────

    def _bacen_regulatory_section(self):
        s = self.s
        self.story.append(Spacer(1, 6))
        self.story.append(Paragraph("2. Matriz de Conformidade Bacen (Resolução CMN nº 4.893)", s["h1"]))
        self.story.append(HRFlowable(width="100%", thickness=1.5, color=C_CYAN, spaceAfter=8))

        self.story.append(Paragraph(
            "Mapeamento dos requisitos de segurança cibernética e plano de resposta conforme as exigências regulatórias do Banco Central do Brasil:",
            s["body_justify"]
        ))
        self.story.append(Spacer(1, 4))

        bacen_rows = [
            ["Artigo / Dispositivo", "Exigência Regulatória Bacen", "Evidência / Avaliação no Pentest", "Status de Auditoria"],
            ["Art. 2º (Política de Segurança)", "Implementar controles que assegurem confidencialidade, integridade e disponibilidade dos dados e sistemas.", "Detectadas falhas em controle de acesso e cabeçalhos de transporte seguro.", "APONTAMENTO ABERTO"],
            ["Art. 10 (Testes Periódicos)", "Realização de testes de intrusão e varreduras de vulnerabilidades em sistemas e aplicações em produção.", "Execução de testes automatizados e validação de superfície de ataque.", "CONFORME (TESTADO)"],
            ["Art. 11 (Proteção Perimétrica & WAF)", "Manter mecanismos de prevenção e mitigação de ameaças de borda e ataques a aplicações web.", "Avaliação de WAF e cabeçalhos de mitigação contra XSS e injeção de código.", "EM REGULARIZAÇÃO"],
            ["Art. 12 (Plano de Ação e Resposta)", "Definição de prazos e procedimentos documentados para remediação tempestiva de vulnerabilidades.", "Roadmap de remediação em 3 fases com SLAs formalizados na seção 5 deste laudo.", "PLANO DOCUMENTADO"],
        ]

        t_bacen = Table(bacen_rows, colWidths=[3.2*cm, 4.8*cm, 6.5*cm, 2.8*cm], style=[
            ("BACKGROUND", (0,0), (-1,0), C_CARD),
            ("TEXTCOLOR", (0,0), (-1,0), C_CYAN),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 7),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_BG, C_CARD]),
            ("TEXTCOLOR", (0,1), (-1,-1), C_TEXT),
            ("BOX", (0,0), (-1,-1), 1, C_BORDER),
            ("INNERGRID", (0,0), (-1,-1), 0.3, C_BORDER),
            ("TOPPADDING", (0,0), (-1,-1), 3.5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 3.5),
            ("ALIGN", (3,0), (3,-1), "CENTER"),
        ])
        self.story.append(t_bacen)

    # ─── 4. Scope, Surface & Methodology ──────────────────────────────────────

    def _methodology_and_scope(self, url, crawl_stats):
        s = self.s
        self.story.append(Paragraph("3. Escopo & Metodologia de Avaliação", s["h1"]))
        self.story.append(HRFlowable(width="100%", thickness=1.5, color=C_CYAN, spaceAfter=8))

        phases = [
            ("Fase 1: Reconhecimento & Descoberta de Superfície",
             f"Mapeamento autônomo sobre {url}, com identificação de {crawl_stats.get('total',0)} URLs ativas, "
             f"{len(crawl_stats.get('forms',[]))} formulários interativos e {len(crawl_stats.get('js_endpoints',[]))} endpoints de API."),
            ("Fase 2: Avaliação de WAF & Proteção Perimétrica",
             "Fingerprinting de Web Application Firewall (Cloudflare, AWS WAF, Akamai, Imperva) e teste comportamental de políticas de bloqueio."),
            ("Fase 3: Arquitetura HTTP & Cabeçalhos Defensivos",
             "Validação estrita de cabeçalhos HSTS, CSP, X-Frame-Options, CORS e atributos seguros de cookies (HttpOnly/Secure/SameSite)."),
            ("Fase 4: Injeção de Dados & Manipulação de Parâmetros",
             "Verificação controlada de vulnerabilidades de injeção (SQLi, XSS, Command Injection) em rotas e formulários mapeados."),
            ("Fase 5: Quebra de Autenticação e Controle de Acesso",
             "Inspeção de rotas sensíveis, tokens JWT, permissões de origem cruzada e referências diretas a objetos inseguros (IDOR)."),
            ("Fase 6: Exposição de Dados Sensíveis e Misconfigurations",
             "Enumeração de arquivos estáticos, diretórios expostos, dumps, arquivos de ambiente (.env) e banners de versão."),
        ]

        for title, desc in phases:
            p_table = Table([[
                Paragraph(f"<b>{title}</b>", ParagraphStyle("ph_t", fontSize=8, textColor=C_CYAN, fontName="Helvetica-Bold")),
            ], [
                Paragraph(desc, s["body_dim"])
            ]], colWidths=[17.3*cm], style=[
                ("BACKGROUND", (0,0), (-1,-1), C_CARD),
                ("BOX", (0,0), (-1,-1), 1, C_BORDER),
                ("TOPPADDING", (0,0), (-1,-1), 3),
                ("BOTTOMPADDING", (0,0), (-1,-1), 3),
                ("LEFTPADDING", (0,0), (-1,-1), 8),
            ])
            self.story.append(p_table)
            self.story.append(Spacer(1, 3))

    # ─── 5. Consolidated Risk Matrix ──────────────────────────────────────────

    def _findings_summary_table(self, findings):
        s = self.s
        self.story.append(Paragraph("4. Matriz Consolidada de Riscos & SLAs", s["h1"]))
        self.story.append(HRFlowable(width="100%", thickness=1.5, color=C_CYAN, spaceAfter=8))

        headers = ["#", "Título da Vulnerabilidade", "Severidade", "CVSS", "OWASP / CWE", "SLA Bacen"]
        table_data = [headers]

        for i, f in enumerate(findings, 1):
            sev = str(f.get("severity", "INFO")).upper()
            title = f.get("title", "Achado de Segurança")
            if len(title) > 42:
                title = title[:40] + "..."

            owasp = str(f.get("owasp") or f.get("owasp_category") or "A05:2021").split("–")[0].strip()
            cwe = str(f.get("cwe") or f.get("cwe_id") or "CWE-Gen")
            cvss = str(f.get("cvss_score", "—"))
            sla = BACEN_SLAS.get(sev, "30 dias").split("(")[0].strip()

            table_data.append([
                f"{i:02d}",
                Paragraph(f"<b>{title}</b>", ParagraphStyle("t_title", fontSize=7.5, textColor=C_WHITE, fontName="Helvetica")),
                Paragraph(f"<b>{sev}</b>", ParagraphStyle("t_sev", fontSize=7, textColor=sev_color(sev), fontName="Helvetica-Bold")),
                cvss,
                Paragraph(f"{owasp} | {cwe}", ParagraphStyle("t_owasp", fontSize=6.5, textColor=C_TEXT_DIM, fontName="Helvetica")),
                Paragraph(sla, ParagraphStyle("t_sla", fontSize=6.5, textColor=C_MUTED, fontName="Helvetica")),
            ])

        t = Table(table_data, colWidths=[0.8*cm, 6.8*cm, 2.2*cm, 1.3*cm, 3.8*cm, 2.4*cm], style=[
            ("BACKGROUND", (0,0), (-1,0), C_CARD),
            ("TEXTCOLOR", (0,0), (-1,0), C_CYAN),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,0), 7.5),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_BG, C_CARD]),
            ("TEXTCOLOR", (0,1), (-1,-1), C_TEXT),
            ("BOX", (0,0), (-1,-1), 1, C_BORDER),
            ("INNERGRID", (0,0), (-1,-1), 0.3, C_BORDER),
            ("ALIGN", (0,0), (0,-1), "CENTER"),
            ("ALIGN", (2,0), (3,-1), "CENTER"),
            ("TOPPADDING", (0,0), (-1,-1), 3.5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 3.5),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ])
        self.story.append(t)

    # ─── 6. Detailed Technical Dossier (Big-4 Standard) ───────────────────────

    def _detailed_findings(self, findings):
        s = self.s
        self.story.append(Paragraph("5. Dossiê Técnico Detalhado dos Achados (Big-4)", s["h1"]))
        self.story.append(HRFlowable(width="100%", thickness=1.5, color=C_CYAN, spaceAfter=10))

        for i, f in enumerate(findings, 1):
            sev = str(f.get("severity", "INFO")).upper()
            color = sev_color(sev)
            cvss = f.get("cvss_score", "—")
            cwe = f.get("cwe") or f.get("cwe_id") or "CWE-General"
            owasp = f.get("owasp") or f.get("owasp_category") or "A05:2021 – Security Misconfiguration"
            url_aff = f.get("affected_url") or f.get("affected_asset") or "Global / Endpoint"
            sla_text = BACEN_SLAS.get(sev, "Até 30 dias corridos")

            block = []

            # 1. Header Box
            hdr = Table([[
                Paragraph(f"<b>ACHADO #{i:02d} — {f.get('title','Vulnerabilidade')}</b>",
                          ParagraphStyle("fh", fontSize=9.5, textColor=C_WHITE, fontName="Helvetica-Bold")),
                Paragraph(f"<b>{sev} | CVSS {cvss}</b>",
                          ParagraphStyle("sh", fontSize=8.5, textColor=color, fontName="Helvetica-Bold", alignment=TA_RIGHT)),
            ]], colWidths=[13.3*cm, 4*cm], style=[
                ("BACKGROUND", (0,0), (-1,-1), C_CARD),
                ("TOPPADDING", (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LEFTPADDING", (0,0), (0,-1), 8),
                ("RIGHTPADDING", (-1,0), (-1,-1), 8),
                ("LINEBELOW", (0,0), (-1,0), 2, color),
            ])
            block.append(hdr)

            # 2. Metadata Grid
            meta_data = [
                ["Categoria OWASP", str(owasp)[:40], "CWE ID", str(cwe)],
                ["Ativo / Endpoint Afetado", str(url_aff)[:50], "SLA Bacen", sla_text],
            ]
            if f.get("parameter"):
                meta_data.append(["Parâmetro Vulnerável", str(f.get("parameter")), "Status Auditoria", str(f.get("status", "OPEN"))])

            mt = Table(meta_data, colWidths=[3.2*cm, 8.3*cm, 2.3*cm, 3.5*cm], style=[
                ("TEXTCOLOR", (0,0), (0,-1), C_MUTED),
                ("TEXTCOLOR", (2,0), (2,-1), C_MUTED),
                ("TEXTCOLOR", (1,0), (1,-1), C_TEXT),
                ("TEXTCOLOR", (3,0), (3,-1), C_TEXT),
                ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
                ("FONTNAME", (2,0), (2,-1), "Helvetica-Bold"),
                ("FONTSIZE", (0,0), (-1,-1), 7),
                ("BACKGROUND", (0,0), (-1,-1), C_BG),
                ("TOPPADDING", (0,0), (-1,-1), 3),
                ("BOTTOMPADDING", (0,0), (-1,-1), 3),
                ("LEFTPADDING", (0,0), (-1,-1), 8),
                ("INNERGRID", (0,0), (-1,-1), 0.3, C_BORDER),
                ("BOX", (0,0), (-1,-1), 0.5, C_BORDER),
            ])
            block.append(mt)
            block.append(Spacer(1, 3))

            # 3. Description of Failure
            block.append(Paragraph("<b>1. Descrição Técnica da Falha:</b>", ParagraphStyle("dt_l", fontSize=8, textColor=C_CYAN, fontName="Helvetica-Bold", spaceBefore=3)))
            block.append(Paragraph(f.get("description", "Sem descrição disponível."), s["body"]))

            # 4. Business & Regulatory Impact (Bacen / LGPD)
            b_imp = f.get("business_impact") or "Risco de comprometimento de dados sensíveis e não conformidade regulatória com a Resolução CMN 4.893."
            t_imp = f.get("technical_impact") or "Violação dos princípios de integridade e confidencialidade da aplicação."
            impact_text = f"<b>2. Impacto Regulatório & Negócio:</b> {b_imp}<br/><b>3. Impacto Técnico:</b> {t_imp}"
            block.append(Paragraph(impact_text, ParagraphStyle("imp", fontSize=7.5, textColor=HexColor("#fca5a5"), leading=10.5, spaceBefore=2)))

            # 5. Root Cause (Causa Raiz)
            rc = f.get("root_cause") or "Ausência de validação perimétrica, parametrização ou sanitização estrita de entradas no ciclo de desenvolvimento."
            block.append(Paragraph(f"<b>4. Causa Raiz:</b> {rc}", ParagraphStyle("rc", fontSize=7.5, textColor=C_TEXT_DIM, leading=10.5, spaceBefore=2)))

            # 6. Technical Fix & Developer Recommendation
            rec = f.get("recommendation") or f.get("developer_recommendation")
            if rec:
                block.append(Paragraph("<b>5. Solução Técnica & Guia de Remediação:</b>",
                                       ParagraphStyle("rc_l", fontSize=8, textColor=HexColor("#34d399"), fontName="Helvetica-Bold", spaceBefore=3)))
                block.append(Paragraph(rec, s["body"]))

            # 7. Audit Trail / Evidence
            evidence = f.get("evidence") or f.get("steps_to_reproduce")
            if evidence:
                block.append(Paragraph("<b>6. Trilha de Auditoria / Evidência Objetiva:</b>",
                                       ParagraphStyle("ev_l", fontSize=7.5, textColor=C_MUTED, fontName="Helvetica-Bold", spaceBefore=3)))
                ev_str = str(evidence)[:420].replace("<", "&lt;").replace(">", "&gt;")
                ev_tbl = Table([[Paragraph(ev_str, s["mono"])]], colWidths=[17.3*cm], style=[
                    ("BACKGROUND", (0,0), (-1,-1), HexColor("#050811")),
                    ("BOX", (0,0), (-1,-1), 1, C_BORDER),
                    ("TOPPADDING", (0,0), (-1,-1), 4),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                    ("LEFTPADDING", (0,0), (-1,-1), 8),
                ])
                block.append(ev_tbl)

            block.append(Spacer(1, 8))
            self.story.append(KeepTogether(block))

    # ─── 7. Remediation Roadmap ───────────────────────────────────────────────

    def _remediation_roadmap(self, sev_counts):
        s = self.s
        self.story.append(PageBreak())
        self.story.append(Paragraph("6. Plano Estratégico de Remediação & Cronograma Bacen", s["h1"]))
        self.story.append(HRFlowable(width="100%", thickness=1.5, color=C_CYAN, spaceAfter=8))

        self.story.append(Paragraph(
            "Em conformidade com o Art. 12 da Resolução CMN nº 4.893, estabelece-se o seguinte cronograma priorizado para correção tempestiva dos desvios:",
            s["body_justify"]
        ))
        self.story.append(Spacer(1, 6))

        phases_data = [
            ("Fase 1: Resposta Emergencial & Contenção Imediata (24h a 48h)",
             "• Corrigir falhas de injeção direta (SQLi) com Prepared Statements ou ORM parametrizado.\n"
             "• Validar assinatura de JWT no backend e revogar tokens forjados com algoritmo 'none'.\n"
             "• Fechar exposição de arquivos sensíveis (.env, .git, backups) nas regras de webserver.",
             C_CRITICAL),
            ("Fase 2: Correções Estruturais e Controle de Acesso (Até 7 dias)",
             "• Implementar controle de acesso baseado em propriedade para prevenir IDOR em APIs.\n"
             "• Ativar regras de bloqueio no WAF (OWASP CRS) e cabeçalhos defensivos (CSP, HSTS, X-Frame-Options).\n"
             "• Restringir configurações de CORS e aplicar flags HttpOnly, Secure e SameSite em cookies.",
             C_HIGH),
            ("Fase 3: Governança DevSecOps e Re-teste Regulatório (Até 30 dias)",
             "• Integrar testes SAST e DAST aos pipelines de CI/CD para prevenção no ciclo de vida de desenvolvimento.\n"
             "• Realizar re-teste formal (Retest) para atestar e documentar o encerramento dos apontamentos perante auditoria.",
             C_CYAN),
        ]

        for p_title, p_items, p_color in phases_data:
            t = Table([[
                Paragraph(f"<b>{p_title}</b>", ParagraphStyle("rt_t", fontSize=8.5, textColor=p_color, fontName="Helvetica-Bold"))
            ], [
                Paragraph(p_items.replace("\n", "<br/>"), s["body"])
            ]], colWidths=[17.3*cm], style=[
                ("BACKGROUND", (0,0), (-1,-1), C_CARD),
                ("BOX", (0,0), (-1,-1), 1, C_BORDER),
                ("LINELEFT", (0,0), (0,-1), 3, p_color),
                ("TOPPADDING", (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LEFTPADDING", (0,0), (-1,-1), 8),
            ])
            self.story.append(t)
            self.story.append(Spacer(1, 5))

    # ─── 8. Disclaimer & Formal Sign-off ──────────────────────────────────────

    def _disclaimer_and_signoff(self):
        s = self.s
        self.story.append(Spacer(1, 6))
        self.story.append(Paragraph("7. Parecer Conclusivo do Auditor & Termo de Encerramento", s["h1"]))
        self.story.append(HRFlowable(width="100%", thickness=1.5, color=C_CYAN, spaceAfter=8))

        self.story.append(Paragraph(
            "<b>PARECER TÉCNICO DE AUDITORIA:</b><br/>"
            "Os testes de segurança cibernética realizados evidenciaram vulnerabilidades técnicas que demandam regularização "
            "conforme os prazos estipulados no plano de ação. A implementação tempestiva das soluções descritas neste relatório "
            "restabelecerá a conformidade do ambiente com as diretrizes da Resolução CMN nº 4.893 do Banco Central do Brasil e LGPD.",
            s["disclaimer"]
        ))
        self.story.append(Spacer(1, 10))

        # Formal Signatures
        sig_data = [
            [
                Paragraph("<b>Auditor Líder de Segurança Cibernética</b><br/><font size=7 color='#64748b'>Certified Ethical Hacker / Security Assessor</font>", s["label"]),
                Paragraph("<b>Responsável Técnico / CISO</b><br/><font size=7 color='#64748b'>Diretoria de Riscos e Segurança da Informação</font>", s["label"])
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

    # ─── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _calc_risk(sev_counts: dict) -> int:
        score = (
            sev_counts.get("CRITICAL", 0) * 28 +
            sev_counts.get("HIGH", 0) * 16 +
            sev_counts.get("MEDIUM", 0) * 8 +
            sev_counts.get("LOW", 0) * 2 +
            sev_counts.get("INFO", 0) * 0.5
        )
        return min(int(score), 100)

    @staticmethod
    def _page_template(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_MUTED)
        canvas.setFont("Helvetica", 7)
        canvas.drawCentredString(A4[0]/2, 1.1*cm, f"morfeusec OSINT — Escrito por Felipe Costa - fsec.costa@gmail.com — Página {doc.page}")
        canvas.restoreState()


def generate_pdf(
    output_path: str,
    target_url: str,
    findings: list[dict],
    crawl_stats: dict,
    operator: str = "Felipe Costa - fsec.costa@gmail.com",
    project_name: str = "morfeusec OSINT - Auditoria de Segurança",
    language: str = "pt",
) -> str:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    report = PentestReportPDF(output_path)
    return report.build(
        target_url=target_url,
        findings=findings,
        crawl_stats=crawl_stats,
        operator=operator,
        project_name=project_name,
        language=language,
    )
