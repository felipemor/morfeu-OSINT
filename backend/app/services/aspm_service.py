"""
ASPM & AppSec Service — Application Security Posture Management with Connectors Architecture
Supports Checkmarx, GitHub Advanced Security, Microsoft Defender for Cloud, Snyk, Veracode.
Computes Quality Gates, Software Composition, Secret Scanning, and AppSec Maturity Index.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ASPMService:
    """Enterprise ASPM Engine & Tool Orchestrator"""

    CONNECTORS_SPEC = [
        {
            "id": "conn-checkmarx",
            "name": "Checkmarx One (SAST/SCA/KICS)",
            "type": "CHECKMARX",
            "category": "SAST / SCA / IaC",
            "status": "CONNECTED",
            "endpoint": "https://ast.checkmarx.net",
            "auth_type": "OAuth2 / API Key",
            "last_sync": "8 minutes ago",
            "health": {"latency_ms": 142, "status": "HEALTHY", "rate_limit_remaining": 4920},
            "scanned_projects": 28,
            "findings_ingested": 142,
            "quality_gate": "ENFORCED",
        },
        {
            "id": "conn-github",
            "name": "GitHub Advanced Security (CodeQL + Secret Scanning + Dependabot)",
            "type": "GITHUB_ADVANCED_SECURITY",
            "category": "SAST / Secrets / SCA",
            "status": "CONNECTED",
            "endpoint": "https://api.github.com/orgs/enterprise-security",
            "auth_type": "GitHub App / Fine-Grained PAT",
            "last_sync": "12 minutes ago",
            "health": {"latency_ms": 98, "status": "HEALTHY", "rate_limit_remaining": 14850},
            "scanned_projects": 34,
            "findings_ingested": 89,
            "quality_gate": "ENFORCED",
        },
        {
            "id": "conn-ms-defender",
            "name": "Microsoft Defender for Cloud & DevOps",
            "type": "MICROSOFT_DEFENDER",
            "category": "Cloud Security / CSPM / CWPP",
            "status": "CONNECTED",
            "endpoint": "https://management.azure.com/providers/Microsoft.Security",
            "auth_type": "Azure Managed Identity / App Registration",
            "last_sync": "25 minutes ago",
            "health": {"latency_ms": 210, "status": "HEALTHY", "rate_limit_remaining": 9900},
            "scanned_projects": 19,
            "findings_ingested": 45,
            "quality_gate": "MONITORING",
        },
        {
            "id": "conn-snyk",
            "name": "Snyk Open Source & Container",
            "type": "SNYK",
            "category": "SCA / Container Security",
            "status": "CONNECTED",
            "endpoint": "https://api.snyk.io/v1",
            "auth_type": "Snyk API Token",
            "last_sync": "35 minutes ago",
            "health": {"latency_ms": 115, "status": "HEALTHY", "rate_limit_remaining": 2400},
            "scanned_projects": 22,
            "findings_ingested": 67,
            "quality_gate": "ENFORCED",
        },
        {
            "id": "conn-veracode",
            "name": "Veracode Static Analysis & Dynamic Analyzer",
            "type": "VERACODE",
            "category": "Enterprise SAST / DAST",
            "status": "NOT_CONFIGURED",
            "endpoint": "https://api.veracode.com/v1",
            "auth_type": "HMAC-SHA256 API Credentials",
            "last_sync": None,
            "health": {"latency_ms": 0, "status": "UNCONFIGURED", "rate_limit_remaining": 0},
            "scanned_projects": 0,
            "findings_ingested": 0,
            "quality_gate": "DISABLED",
        },
    ]

    APPLICATION_INVENTORY = [
        {
            "id": "app-pix-core",
            "name": "Pix Core Transaction Engine",
            "code": "PIX-CORE-API",
            "business_unit": "Retail Banking",
            "department": "Digital Payments",
            "squad": "Instant Payments Squad",
            "business_owner": "Carlos Mendonça (Superintendente Pix)",
            "tech_owner": "Felipe Costa (Tech Lead / SecOps)",
            "criticality": "CRITICAL",
            "environment": "Production",
            "internet_facing": True,
            "repositories": [
                {
                    "name": "retail-banking/pix-core-api",
                    "branch": "main",
                    "language": "Go / gRPC",
                    "quality_gate": "PASSED",
                    "sast": "Clean (Checkmarx)",
                    "secrets": "0 leaked (GitHub AS)",
                    "sca_critical": 0,
                    "last_scan": "2026-09-11 19:40 UTC",
                },
                {
                    "name": "retail-banking/pix-dict-consumer",
                    "branch": "main",
                    "language": "Java / Spring Boot",
                    "quality_gate": "PASSED",
                    "sast": "Clean",
                    "secrets": "0 leaked",
                    "sca_critical": 0,
                    "last_scan": "2026-09-11 18:20 UTC",
                }
            ],
            "appsec_score": 96.0,
            "quality_gate": "PASSED",
            "sla_compliance_pct": 100.0,
            "mttr_days": 1.8,
            "active_findings": {"critical": 0, "high": 1, "medium": 3, "low": 5},
            "production_assets": ["https://api-pix.banking.internal", "198.51.100.22"],
        },
        {
            "id": "app-internet-banking",
            "name": "Internet Banking Web & Microfrontends",
            "code": "IB-WEB-APP",
            "business_unit": "Digital Channels",
            "department": "Omnichannel Banking",
            "squad": "Web Experience Squad",
            "business_owner": "Renata Silveira (Head Digital Channels)",
            "tech_owner": "Rodrigo Alvarez (Staff Engineer)",
            "criticality": "CRITICAL",
            "environment": "Production",
            "internet_facing": True,
            "repositories": [
                {
                    "name": "digital-channels/ib-portal-frontend",
                    "branch": "main",
                    "language": "TypeScript / Next.js",
                    "quality_gate": "PASSED",
                    "sast": "Clean (CodeQL)",
                    "secrets": "0 leaked",
                    "sca_critical": 0,
                    "last_scan": "2026-09-11 19:15 UTC",
                },
                {
                    "name": "digital-channels/ib-bff-gateway",
                    "branch": "main",
                    "language": "Node.js / Express",
                    "quality_gate": "WARNING",
                    "sast": "1 High Warning",
                    "secrets": "0 leaked",
                    "sca_critical": 0,
                    "last_scan": "2026-09-11 16:50 UTC",
                }
            ],
            "appsec_score": 91.5,
            "quality_gate": "PASSED",
            "sla_compliance_pct": 98.2,
            "mttr_days": 3.4,
            "active_findings": {"critical": 0, "high": 2, "medium": 6, "low": 12},
            "production_assets": ["https://app.shieldsecurity.io", "https://ib.bancodigital.com.br"],
        },
        {
            "id": "app-credit-engine",
            "name": "Credit Decisioning & Loan Processing",
            "code": "CREDIT-DECISION-SVC",
            "business_unit": "Credit & Lending",
            "department": "Risk & Analytics",
            "squad": "Credit Score Squad",
            "business_owner": "Eduardo Prado (Diretor de Crédito)",
            "tech_owner": "Marcio Fernandes (Principal Architect)",
            "criticality": "HIGH",
            "environment": "Production",
            "internet_facing": False,
            "repositories": [
                {
                    "name": "credit/loan-origination-engine",
                    "branch": "main",
                    "language": "Python / FastAPI",
                    "quality_gate": "PASSED",
                    "sast": "Clean",
                    "secrets": "0 leaked",
                    "sca_critical": 0,
                    "last_scan": "2026-09-11 14:10 UTC",
                }
            ],
            "appsec_score": 93.0,
            "quality_gate": "PASSED",
            "sla_compliance_pct": 96.5,
            "mttr_days": 2.9,
            "active_findings": {"critical": 0, "high": 1, "medium": 4, "low": 8},
            "production_assets": ["https://credit-engine.corp.internal"],
        },
        {
            "id": "app-open-finance",
            "name": "Open Finance Regulatory APIs (BACEN)",
            "code": "OPEN-FINANCE-API",
            "business_unit": "Regulatory & Open Banking",
            "department": "Compliance & Interoperability",
            "squad": "Open Banking Squad",
            "business_owner": "Juliana Tavares (DPO & GRC Lead)",
            "tech_owner": "Gustavo Lima (Security Architect)",
            "criticality": "CRITICAL",
            "environment": "Production",
            "internet_facing": True,
            "repositories": [
                {
                    "name": "openbanking/fapi-auth-gateway",
                    "branch": "main",
                    "language": "Go / FAPI 1.0 Advanced",
                    "quality_gate": "PASSED",
                    "sast": "Clean (Checkmarx)",
                    "secrets": "0 leaked",
                    "sca_critical": 0,
                    "last_scan": "2026-09-11 18:45 UTC",
                }
            ],
            "appsec_score": 98.0,
            "quality_gate": "PASSED",
            "sla_compliance_pct": 100.0,
            "mttr_days": 1.1,
            "active_findings": {"critical": 0, "high": 0, "medium": 2, "low": 3},
            "production_assets": ["https://openbanking.bancodigital.com.br"],
        },
    ]

    @classmethod
    def get_aspm_dashboard_stats(cls) -> Dict[str, Any]:
        """Returns consolidated ASPM metrics for executive reporting."""
        total_apps = len(cls.APPLICATION_INVENTORY)
        total_repos = sum(len(app["repositories"]) for app in cls.APPLICATION_INVENTORY)
        monitored_repos = total_repos
        clean_repos = sum(1 for app in cls.APPLICATION_INVENTORY for r in app["repositories"] if r["quality_gate"] == "PASSED")
        
        return {
            "monitored_applications": total_apps,
            "monitored_repositories": total_repos,
            "scanning_coverage_pct": 100.0,
            "appsec_maturity_score": 93.8,
            "quality_gate_pass_rate": round((clean_repos / max(total_repos, 1)) * 100, 1),
            "sast_coverage_pct": 100.0,
            "sca_coverage_pct": 100.0,
            "secret_scanning_coverage_pct": 100.0,
            "dast_coverage_pct": 87.5,
            "open_critical_vulnerabilities": 0,
            "open_high_vulnerabilities": 4,
            "open_medium_vulnerabilities": 15,
            "open_low_vulnerabilities": 28,
            "sla_compliance_pct": 98.4,
            "average_mttr_days": 2.3,
            "connectors": cls.CONNECTORS_SPEC,
            "applications": cls.APPLICATION_INVENTORY,
            "monthly_appsec_trend": [
                {"month": "2025-10", "critical": 6, "high": 24, "medium": 65, "mttr_days": 12.4, "score": 76.2},
                {"month": "2025-11", "critical": 4, "high": 19, "medium": 58, "mttr_days": 9.8, "score": 80.5},
                {"month": "2025-12", "critical": 3, "high": 15, "medium": 49, "mttr_days": 8.1, "score": 83.9},
                {"month": "2026-01", "critical": 2, "high": 12, "medium": 42, "mttr_days": 6.7, "score": 86.4},
                {"month": "2026-02", "critical": 2, "high": 9, "medium": 36, "mttr_days": 5.2, "score": 88.7},
                {"month": "2026-03", "critical": 1, "high": 8, "medium": 31, "mttr_days": 4.5, "score": 89.9},
                {"month": "2026-04", "critical": 1, "high": 6, "medium": 27, "mttr_days": 3.9, "score": 91.2},
                {"month": "2026-05", "critical": 0, "high": 6, "medium": 24, "mttr_days": 3.4, "score": 92.1},
                {"month": "2026-06", "critical": 0, "high": 5, "medium": 21, "mttr_days": 2.9, "score": 92.8},
                {"month": "2026-07", "critical": 0, "high": 5, "medium": 19, "mttr_days": 2.7, "score": 93.1},
                {"month": "2026-08", "critical": 0, "high": 4, "medium": 17, "mttr_days": 2.5, "score": 93.4},
                {"month": "2026-09", "critical": 0, "high": 4, "medium": 15, "mttr_days": 2.3, "score": 93.8},
            ]
        }
