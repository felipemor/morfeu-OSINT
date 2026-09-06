"""
Endpoint OS Hardening & Configuration Check
"""
from app.checks.endpoint.base import BaseEndpointCheck, EndpointCheckContext, EndpointCheckResult
from app.models import Severity


class OsAssessmentCheck(BaseEndpointCheck):
    id = "EP-OS-001"
    name = "OS Hardening & User Privilege Check"
    category = "OS"
    severity = Severity.MEDIUM
    cwe_id = "CWE-250"
    owasp_category = "A01:2021-Broken Access Control"

    async def evaluate(self, context: EndpointCheckContext) -> EndpointCheckResult:
        os_data = context.telemetry_data.get("os", {})
        uac_enabled = os_data.get("uac_enabled", True) if context.platform == "windows" else True
        root_login = os_data.get("permit_root_login", False) if context.platform == "linux" else False

        issues = []
        if context.platform == "windows" and not uac_enabled:
            issues.append("User Account Control (UAC) is disabled")
        if context.platform == "linux" and root_login:
            issues.append("Direct SSH root login is permitted")

        if issues:
            return EndpointCheckResult(
                check_id=self.id,
                agent_id=context.agent_id,
                asset_id=context.asset_id,
                status="FAIL",
                title=f"OS Hardening Weakness Detected on {context.hostname}",
                description=f"Identified configuration weakness: {'; '.join(issues)}.",
                severity=Severity.MEDIUM,
                cwe_id=self.cwe_id,
                owasp_category=self.owasp_category,
                remediation="Enable UAC on Windows or set PermitRootLogin no in sshd_config on Linux.",
                evidence={"os_info": os_data, "issues": issues},
            )

        return EndpointCheckResult(
            check_id=self.id,
            agent_id=context.agent_id,
            asset_id=context.asset_id,
            status="PASS",
            title=f"Baseline OS Hardening Verified on {context.hostname}",
            description="OS privilege separation controls are active.",
            severity=Severity.INFO,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            remediation="No action required.",
            evidence={"os_info": os_data},
        )
