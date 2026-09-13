from fastapi import APIRouter
from app.api.v1 import (
    auth, projects, scopes, scans, assets, findings, evidence,
    reports, audit, users, approvals, topology, nl_assistant, agents,
    security_controls, osint, mobile_pentest, felipinho, microsegmentation,
    morfeuxdr, grafana_analytics, powerbi,
    aspm, compliance_enterprise, correlation, integrations, copilot, datamart,
    schedule
)

router = APIRouter()

router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
router.include_router(users.router, prefix="/users", tags=["Users"])
router.include_router(projects.router, prefix="/projects", tags=["Projects"])
router.include_router(scopes.router, prefix="/projects", tags=["Scope"])
router.include_router(scans.router, prefix="/projects", tags=["Scans"])
router.include_router(assets.router, prefix="/projects", tags=["Assets"])
router.include_router(findings.router, prefix="/findings", tags=["Findings"])
router.include_router(evidence.router, prefix="/evidence", tags=["Evidence"])
router.include_router(reports.router, prefix="/projects", tags=["Reports"])
router.include_router(audit.router, prefix="/audit-logs", tags=["Audit"])
router.include_router(approvals.router, prefix="/approvals", tags=["Approvals"])
router.include_router(topology.router, prefix="/projects", tags=["Topology & AI Reasoning"])
router.include_router(nl_assistant.router, prefix="/projects", tags=["NL Security Assistant"])
router.include_router(agents.router, prefix="/agents", tags=["Endpoint Security Agents"])
router.include_router(security_controls.router, prefix="/security-controls", tags=["Security Controls Testing"])
router.include_router(osint.router, prefix="/osint", tags=["OSINT Reconnaissance"])
router.include_router(mobile_pentest.router, prefix="/mobile-pentest", tags=["Mobile Pentest (APK & iOS)"])
router.include_router(felipinho.router, prefix="/felipinho", tags=["Felipinho AI Assistant"])
router.include_router(microsegmentation.router, prefix="/microsegmentation", tags=["Hybrid Microsegmentation & Zero Trust"])
router.include_router(morfeuxdr.router, prefix="/morfeuxdr", tags=["MorfeuXDR SIEM & XDR Platform"])
router.include_router(grafana_analytics.router, prefix="/grafana-analytics", tags=["Grafana Security Operations & Honeypots"])
router.include_router(powerbi.router, prefix="/powerbi", tags=["PowerBI Analytics & REST APIs"])

# Enterprise Posture & Governance extensions
router.include_router(aspm.router, prefix="/aspm", tags=["AppSec & ASPM Posture"])
router.include_router(compliance_enterprise.router, prefix="/compliance", tags=["Regulatory Compliance & Controls"])
router.include_router(correlation.router, prefix="/correlation", tags=["Multi-Plane Correlation & Risk"])
router.include_router(integrations.router, prefix="/integrations", tags=["Enterprise Connectors Hub"])
router.include_router(copilot.router, prefix="/copilot", tags=["AI Security Copilot"])
router.include_router(datamart.router, prefix="/datamart", tags=["Executive Data Mart & Trends"])
router.include_router(schedule.router, prefix="/projects", tags=["Pentest Schedule & Gantt"])







