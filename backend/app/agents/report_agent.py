"""
Report Agent V2 — Generates Executive, Technical, and Audit reports with compliance mappings and evidence hashes
"""
import asyncio
import json
import os
from datetime import datetime, timezone
import structlog
from jinja2 import Environment, BaseLoader

from app.agents.celery_app import celery_app
from app.core.config import settings
from app.services.compliance import ComplianceService

logger = structlog.get_logger(__name__)

REPORT_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{{ title }}</title>
<style>
@page { size: A4; margin: 2cm; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #1e293b; line-height: 1.6; font-size: 10pt; }
h1 { color: #0f172a; border-bottom: 2px solid #ef4444; padding-bottom: 8px; font-size: 20pt; }
h2 { color: #1e293b; margin-top: 25px; font-size: 14pt; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; }
h3 { color: #334155; margin-top: 15px; font-size: 12pt; }
.cover { text-align: center; padding: 80px 0; page-break-after: always; }
.cover h1 { font-size: 28pt; border: none; color: #0f172a; }
.cover .subtitle { font-size: 14pt; color: #64748b; margin-top: 15px; }
.cover .meta { margin-top: 50px; font-size: 10pt; color: #475569; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 9pt; }
th { background: #0f172a; color: white; padding: 8px; text-align: left; }
td { padding: 6px 8px; border-bottom: 1px solid #e2e8f0; }
tr:nth-child(even) { background: #f8fafc; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 8pt; text-transform: uppercase; }
.severity-critical { color: #fff; background: #dc2626; }
.severity-high { color: #fff; background: #ea580c; }
.severity-medium { color: #000; background: #f59e0b; }
.severity-low { color: #fff; background: #16a34a; }
.severity-info { color: #fff; background: #0284c7; }
.finding-card { border: 1px solid #cbd5e1; border-radius: 6px; padding: 15px; margin: 15px 0; page-break-inside: avoid; }
.finding-card h3 { margin-top: 0; }
.evidence-block { background: #0f172a; color: #f8fafc; border-radius: 4px; padding: 10px; margin: 8px 0; font-family: monospace; font-size: 8pt; white-space: pre-wrap; word-break: break-all; }
.hash-tag { font-family: monospace; font-size: 8pt; color: #0284c7; }
.summary-grid { display: flex; gap: 15px; margin: 15px 0; flex-wrap: wrap; }
.summary-card { flex: 1; min-width: 100px; text-align: center; padding: 12px; border-radius: 6px; background: #f1f5f9; }
.summary-card .number { font-size: 22pt; font-weight: bold; color: #0f172a; }
.summary-card .label { font-size: 8pt; color: #64748b; text-transform: uppercase; }
.disclaimer { margin-top: 30px; padding: 12px; background: #fef3c7; border: 1px solid #f59e0b; border-radius: 4px; font-size: 8.5pt; }
.footer { text-align: center; color: #94a3b8; font-size: 8pt; margin-top: 30px; }
</style>
</head>
<body>

<!-- COVER PAGE -->
<div class="cover">
    <h1>🛡️ Autonomous Pentest Report</h1>
    <div class="subtitle">{{ title }}</div>
    <div class="meta">
        <p><strong>Project:</strong> {{ project_name }}</p>
        <p><strong>Client / BU:</strong> {{ client or 'N/A' }} / {{ business_unit or 'N/A' }}</p>
        <p><strong>Report Classification:</strong> CONFIDENTIAL (V2)</p>
        <p><strong>Report Type:</strong> {{ report_type }}</p>
        <p><strong>Generated At:</strong> {{ generated_at }}</p>
    </div>
</div>

<!-- EXECUTIVE / OVERALL RISK SUMMARY -->
<h1>Executive Overview</h1>
<p>This report documents the security posture discovered during the autonomous security reasoning and validation assessment. All tests were executed deterministically under authorized safety policies.</p>

<div class="summary-grid">
    <div class="summary-card"><div class="number">{{ total_assets }}</div><div class="label">Assets</div></div>
    <div class="summary-card"><div class="number">{{ total_endpoints }}</div><div class="label">Endpoints</div></div>
    <div class="summary-card"><div class="number">{{ total_findings }}</div><div class="label">Findings</div></div>
    <div class="summary-card"><div class="number" style="color:#dc2626">{{ critical_count }}</div><div class="label">Critical</div></div>
    <div class="summary-card"><div class="number" style="color:#ea580c">{{ high_count }}</div><div class="label">High</div></div>
    <div class="summary-card"><div class="number" style="color:#f59e0b">{{ medium_count }}</div><div class="label">Medium</div></div>
</div>

<!-- COMPLIANCE ALIGNMENT -->
<h2>Compliance Framework Alignment</h2>
<table>
    <tr><th>Framework</th><th>Violations</th><th>Impact Summary</th></tr>
    <tr><td><strong>OWASP Top 10</strong></td><td>{{ compliance.owasp.violations }}</td><td>{{ compliance.owasp.affected_categories|join(', ') or 'Compliant' }}</td></tr>
    <tr><td><strong>CIS Controls v8</strong></td><td>{{ compliance.cis_controls.violations }}</td><td>{{ compliance.cis_controls.affected_controls|join(', ') or 'Compliant' }}</td></tr>
    <tr><td><strong>NIST CSF 2.0</strong></td><td>{{ compliance.nist_csf.violations }}</td><td>{{ compliance.nist_csf.affected_clauses|join(', ') or 'Compliant' }}</td></tr>
    <tr><td><strong>ISO/IEC 27001</strong></td><td>{{ compliance.iso_27001.violations }}</td><td>{{ compliance.iso_27001.affected_controls|join(', ') or 'Compliant' }}</td></tr>
</table>

<!-- DETAILED FINDINGS & EVIDENCE INTEGRITY -->
<h2>Validated Findings & Cryptographic Evidence</h2>
{% for finding in findings %}
<div class="finding-card">
    <h3><span class="badge severity-{{ finding.severity|lower }}">{{ finding.severity }}</span> {{ finding.title }}</h3>
    <table>
        <tr>
            <td><strong>CWE</strong>: {{ finding.cwe_id or 'N/A' }}</td>
            <td><strong>OWASP</strong>: {{ finding.owasp_category or 'N/A' }}</td>
            <td><strong>CVSS</strong>: {{ finding.cvss_score or 'N/A' }}</td>
            <td><strong>Confidence</strong>: {{ finding.confidence }}%</td>
        </tr>
        <tr>
            <td colspan="4"><strong>Affected Target:</strong> {{ finding.affected_url or finding.affected_asset or 'N/A' }}</td>
        </tr>
    </table>

    <h4>Description</h4>
    <p>{{ finding.description }}</p>

    {% if finding.recommendation %}
    <h4>Remediation Recommendation</h4>
    <p>{{ finding.recommendation }}</p>
    {% endif %}

    {% if finding.evidence %}
    <h4>Cryptographic Evidence Chain</h4>
    {% for ev in finding.evidence %}
    <div class="evidence-block">
SHA-256: <span class="hash-tag">{{ ev.evidence_hash or 'UNHASHED' }}</span> (Integrity: {{ 'VERIFIED' if ev.integrity_verified else 'PENDING' }})
{{ ev.http_method or 'GET' }} {{ ev.url or '' }}
Status: {{ ev.response_status or 'N/A' }}

Headers:
{{ ev.request_headers or '' }}

Response Preview:
{{ ev.response_body[:500] if ev.response_body else '' }}
    </div>
    {% endfor %}
    {% endif %}
</div>
{% endfor %}

<div class="disclaimer">
    <strong>Auditor Notice:</strong> All tests were executed in compliance with organizational policies. Evidence data containing sensitive information is cryptographically hashed and masked.
</div>

<div class="footer">
    AI Autonomous Pentest Platform V2 | {{ generated_at }} | CONFIDENTIAL
</div>

</body>
</html>
"""


@celery_app.task(bind=True, name="app.agents.report_agent.generate_report_task")
def generate_report_task(self, report_id: str, project_id: str):
    """Celery task to generate a report."""
    asyncio.run(_generate_report_async(report_id, project_id))


async def _generate_report_async(report_id: str, project_id: str):
    from app.core.database import AsyncSessionLocal
    from app.models import Report, Project, Finding, Asset, Endpoint, Scope, RiskScore, Evidence
    from sqlalchemy import select, func

    try:
        async with AsyncSessionLocal() as db:
            # Load project data
            proj_result = await db.execute(select(Project).where(Project.id == project_id))
            project = proj_result.scalar_one_or_none()

            # Load scope
            scope_result = await db.execute(select(Scope).where(Scope.project_id == project_id))
            scope = scope_result.scalar_one_or_none()

            # Load findings
            findings_result = await db.execute(
                select(Finding).where(
                    Finding.project_id == project_id,
                    Finding.is_false_positive == False,
                )
            )
            findings = findings_result.scalars().all()

            # Load evidence
            evidence_result = await db.execute(select(Evidence))
            all_evidence = evidence_result.scalars().all()
            evidence_by_finding: dict[str, list] = {}
            for ev in all_evidence:
                evidence_by_finding.setdefault(ev.finding_id, []).append(ev)

            # Load assets and endpoints count
            asset_count_res = await db.execute(select(func.count(Asset.id)).where(Asset.project_id == project_id))
            total_assets = asset_count_res.scalar() or 0

            ep_count_res = await db.execute(select(func.count(Endpoint.id)).where(Endpoint.project_id == project_id))
            total_endpoints = ep_count_res.scalar() or 0

            # Compliance summary
            compliance_svc = ComplianceService(db)
            compliance_summary = await compliance_svc.get_project_compliance_summary(project_id)

            # Report record
            rep_result = await db.execute(select(Report).where(Report.id == report_id))
            report = rep_result.scalar_one_or_none()
            if not report:
                return

            findings_data = []
            for f in findings:
                findings_data.append({
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "cwe_id": f.cwe_id,
                    "owasp_category": f.owasp_category,
                    "cvss_score": f.cvss_score,
                    "confidence": f.confidence,
                    "affected_url": f.affected_url,
                    "affected_asset": f.affected_asset,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "evidence": evidence_by_finding.get(f.id, []),
                })

            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in findings:
                counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

            template_ctx = {
                "title": report.title,
                "project_name": project.name if project else "Pentest Project",
                "client": project.client if project else None,
                "business_unit": project.business_unit if project else None,
                "report_type": report.report_type.value,
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "total_assets": total_assets,
                "total_endpoints": total_endpoints,
                "total_findings": len(findings),
                "critical_count": counts["CRITICAL"],
                "high_count": counts["HIGH"],
                "medium_count": counts["MEDIUM"],
                "low_count": counts["LOW"],
                "compliance": compliance_summary,
                "findings": findings_data,
            }

            env = Environment(loader=BaseLoader())
            template = env.from_string(REPORT_HTML_TEMPLATE)
            rendered_html = template.render(**template_ctx)

            # Save report
            reports_dir = settings.REPORTS_DIR
            os.makedirs(reports_dir, exist_ok=True)
            report_filename = f"report_{report_id}.html"
            report_path = os.path.join(reports_dir, report_filename)

            with open(report_path, "w", encoding="utf-8") as f:
                f.write(rendered_html)

            report.file_path = report_path
            report.file_size = len(rendered_html.encode("utf-8"))
            report.status = "COMPLETED"
            report.finding_count = len(findings)
            report.completed_at = datetime.now(timezone.utc)
            await db.commit()

            logger.info("Report generated successfully", report_id=report_id, path=report_path)

    except Exception as e:
        logger.error("Report generation failed", report_id=report_id, error=str(e), exc_info=True)
        async with AsyncSessionLocal() as db:
            rep_res = await db.execute(select(Report).where(Report.id == report_id))
            rep = rep_res.scalar_one_or_none()
            if rep:
                rep.status = "FAILED"
                rep.error = str(e)
                await db.commit()
