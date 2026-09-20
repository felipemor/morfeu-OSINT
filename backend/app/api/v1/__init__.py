import importlib
from fastapi import APIRouter

router = APIRouter()

ROUTERS_MAP = [
    ("auth", "/auth", ["Authentication"]),
    ("users", "/users", ["Users"]),
    ("projects", "/projects", ["Projects"]),
    ("scopes", "/projects", ["Scope"]),
    ("scans", "/projects", ["Scans"]),
    ("assets", "/projects", ["Assets"]),
    ("findings", "/findings", ["Findings"]),
    ("evidence", "/evidence", ["Evidence"]),
    ("reports", "/projects", ["Reports"]),
    ("audit", "/audit-logs", ["Audit"]),
    ("approvals", "/approvals", ["Approvals"]),
    ("topology", "/projects", ["Topology & AI Reasoning"]),
    ("nl_assistant", "/projects", ["NL Security Assistant"]),
    ("agents", "/agents", ["Endpoint Security Agents"]),
    ("security_controls", "/security-controls", ["Security Controls Testing"]),
    ("osint", "/osint", ["OSINT Reconnaissance"]),
    ("mobile_pentest", "/mobile-pentest", ["Mobile Pentest (APK & iOS)"]),
    ("felipinho", "/felipinho", ["Felipinho AI Assistant"]),
    ("microsegmentation", "/microsegmentation", ["Hybrid Microsegmentation & Zero Trust"]),
    ("morfeuxdr", "/morfeuxdr", ["MorfeuXDR SIEM & XDR Platform"]),
    ("grafana_analytics", "/grafana-analytics", ["Grafana Security Operations & Honeypots"]),
    ("powerbi", "/powerbi", ["PowerBI Analytics & REST APIs"]),
    ("aspm", "/aspm", ["AppSec & ASPM Posture"]),
    ("compliance_enterprise", "/compliance", ["Regulatory Compliance & Controls"]),
    ("correlation", "/correlation", ["Multi-Plane Correlation & Risk"]),
    ("integrations", "/integrations", ["Enterprise Connectors Hub"]),
    ("copilot", "/copilot", ["AI Security Copilot"]),
    ("datamart", "/datamart", ["Executive Data Mart & Trends"]),
    ("schedule", "/projects", ["Pentest Schedule & Gantt"]),
    ("pentest_hub", "/pentest-hub", ["Pentest Hub — Ecosystem Central"]),
    ("easm", "/easm", ["EASM & Dark Web Intelligence"]),
    ("aegis", "/aegis", ["AegisLattice Post-Quantum Cryptography & CBOM"]),
    ("brand_protection", "/brand", ["Brand Protection & Takedown Radar"]),
    ("boleto", "/boleto", ["Boleto Bancário Validator & Anti-Fraud"]),
    ("bin_monitor", "/bin-monitor", ["BIN Attack & Card-Testing Defense"]),
    ("fiscal", "/fiscal", ["Fiscal Forensic AI — Automated Audit & Fraud Analytics"]),
    ("code_humanizer", "", ["AI Code Humanizer"]),
    ("certificates", "/crypto/certificates", ["PKI & Certificate Management"]),
]

for mod_name, prefix, tags in ROUTERS_MAP:
    try:
        mod = importlib.import_module(f"app.api.v1.{mod_name}")
        if hasattr(mod, "router"):
            kwargs = {}
            if prefix:
                kwargs["prefix"] = prefix
            if tags:
                kwargs["tags"] = tags
            router.include_router(mod.router, **kwargs)
    except Exception as e:
        # Silently skip optional sub-routers when run in lightweight or standalone scanner mode
        pass
