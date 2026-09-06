"""
Compliance Mapping Service — Maps security findings to standard compliance frameworks

Supported Frameworks:
- OWASP Top 10 (2021 & API 2023)
- CWE (Common Weakness Enumeration)
- CIS Controls v8
- NIST Cybersecurity Framework (CSF 2.0)
- ISO/IEC 27001:2022
"""
from dataclasses import dataclass, field
from typing import Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from app.models import Finding, Severity

logger = structlog.get_logger(__name__)

# CWE to Standard Framework Mappings
FRAMEWORK_MAPPINGS: dict[str, dict[str, str]] = {
    "CWE-79": {
        "owasp": "A03:2021-Injection",
        "cis_controls": "CIS 16.11 - Apply Context-Aware Output Encoding",
        "nist_csf": "PR.DS-1 - Data-at-rest and in-transit protection",
        "iso_27001": "A.8.28 - Secure Coding",
    },
    "CWE-89": {
        "owasp": "A03:2021-Injection",
        "cis_controls": "CIS 16.11 - Parameterized Queries",
        "nist_csf": "PR.IP-1 - Secure Configuration",
        "iso_27001": "A.8.28 - Secure Coding",
    },
    "CWE-693": {
        "owasp": "A05:2021-Security Misconfiguration",
        "cis_controls": "CIS 4.1 - Secure Configuration of Enterprise Assets",
        "nist_csf": "PR.PT-1 - Audit & Security Controls",
        "iso_27001": "A.8.9 - Configuration Management",
    },
    "CWE-942": {
        "owasp": "A05:2021-Security Misconfiguration",
        "cis_controls": "CIS 4.1 - Access Control Boundaries",
        "nist_csf": "PR.AC-4 - Network & Access Protection",
        "iso_27001": "A.8.20 - Network Security",
    },
    "CWE-614": {
        "owasp": "A05:2021-Security Misconfiguration",
        "cis_controls": "CIS 3.3 - Protect Sensitive Data in Transit",
        "nist_csf": "PR.DS-2 - Data-in-transit encryption",
        "iso_27001": "A.8.24 - Use of Cryptography",
    },
    "CWE-1004": {
        "owasp": "A05:2021-Security Misconfiguration",
        "cis_controls": "CIS 16.4 - Isolate Application Sessions",
        "nist_csf": "PR.AC-1 - Identity and Credential Management",
        "iso_27001": "A.5.15 - Access Control",
    },
    "CWE-285": {
        "owasp": "API1:2023-Broken Object Level Authorization",
        "cis_controls": "CIS 6.8 - Enforce Access Control Policies",
        "nist_csf": "PR.AC-4 - Access Enforcement",
        "iso_27001": "A.5.15 - Access Control",
    },
    "CWE-287": {
        "owasp": "API2:2023-Broken Authentication",
        "cis_controls": "CIS 6.1 - Robust Multi-Factor & Token Authentication",
        "nist_csf": "PR.AC-6 - Identity Verification",
        "iso_27001": "A.5.16 - Authentication Management",
    },
    "CWE-200": {
        "owasp": "API3:2023-Broken Object Property Level Authorization",
        "cis_controls": "CIS 3.1 - Data Classification and Handling",
        "nist_csf": "PR.DS-5 - Data Spill & Exposure Prevention",
        "iso_27001": "A.8.11 - Data Masking",
    },
    "CWE-209": {
        "owasp": "API8:2023-Security Misconfiguration",
        "cis_controls": "CIS 8.5 - Standardized Log & Error Generation",
        "nist_csf": "DE.AE-1 - Baseline Error Telemetry",
        "iso_27001": "A.8.15 - Logging & Monitoring",
    },
}

DEFAULT_MAPPING = {
    "owasp": "A05:2021-Security Misconfiguration",
    "cis_controls": "CIS 4.1 - Baseline Security Configuration",
    "nist_csf": "PR.IP-1 - Baseline Configuration Protection",
    "iso_27001": "A.8.9 - Configuration Management",
}


class ComplianceService:
    """Provides compliance framework mappings and audit metrics."""

    def __init__(self, db: AsyncSession):
        self.db = db

    @staticmethod
    def map_cwe_to_frameworks(cwe_id: Optional[str]) -> dict[str, str]:
        """Returns framework mappings for a given CWE identifier."""
        if not cwe_id:
            return DEFAULT_MAPPING
        cwe_clean = cwe_id.upper().strip()
        return FRAMEWORK_MAPPINGS.get(cwe_clean, DEFAULT_MAPPING)

    async def get_project_compliance_summary(self, project_id: str) -> dict[str, Any]:
        """
        Calculates compliance alignment percentages across frameworks for a project.
        """
        findings_res = await self.db.execute(
            select(Finding).where(
                Finding.project_id == project_id,
                Finding.is_false_positive == False,
            )
        )
        findings = findings_res.scalars().all()

        framework_counts = {
            "OWASP": {"violations": 0, "categories": set()},
            "CIS_CONTROLS": {"violations": 0, "controls": set()},
            "NIST_CSF": {"violations": 0, "clauses": set()},
            "ISO_27001": {"violations": 0, "controls": set()},
        }

        for f in findings:
            mapping = self.map_cwe_to_frameworks(f.cwe_id)
            framework_counts["OWASP"]["violations"] += 1
            framework_counts["OWASP"]["categories"].add(mapping.get("owasp", ""))

            framework_counts["CIS_CONTROLS"]["violations"] += 1
            framework_counts["CIS_CONTROLS"]["controls"].add(mapping.get("cis_controls", ""))

            framework_counts["NIST_CSF"]["violations"] += 1
            framework_counts["NIST_CSF"]["clauses"].add(mapping.get("nist_csf", ""))

            framework_counts["ISO_27001"]["violations"] += 1
            framework_counts["ISO_27001"]["controls"].add(mapping.get("iso_27001", ""))

        return {
            "project_id": project_id,
            "total_findings": len(findings),
            "owasp": {
                "violations": framework_counts["OWASP"]["violations"],
                "affected_categories": list(framework_counts["OWASP"]["categories"]),
            },
            "cis_controls": {
                "violations": framework_counts["CIS_CONTROLS"]["violations"],
                "affected_controls": list(framework_counts["CIS_CONTROLS"]["controls"]),
            },
            "nist_csf": {
                "violations": framework_counts["NIST_CSF"]["violations"],
                "affected_clauses": list(framework_counts["NIST_CSF"]["clauses"]),
            },
            "iso_27001": {
                "violations": framework_counts["ISO_27001"]["violations"],
                "affected_controls": list(framework_counts["ISO_27001"]["controls"]),
            },
        }
