"""
Endpoint Firewall Status Assessment Check
"""
from app.checks.endpoint.base import BaseEndpointCheck, EndpointCheckContext, EndpointCheckResult
from app.models import Severity


class FirewallAssessmentCheck(BaseEndpointCheck):
    id = "EP-FW-001"
    name = "Host Firewall Status Check"
    category = "FIREWALL"
    severity = Severity.HIGH
    cwe_id = "CWE-693"
    owasp_category = "A05:2021-Security Misconfiguration"

    async def evaluate(self, context: EndpointCheckContext) -> EndpointCheckResult:
        fw_data = context.telemetry_data.get("firewall", {})
        is_enabled = fw_data.get("enabled", True)
        profiles = fw_data.get("profiles", {})

        if not is_enabled:
            return EndpointCheckResult(
                check_id=self.id,
                agent_id=context.agent_id,
                asset_id=context.asset_id,
                status="FAIL",
                title=f"Host-based Firewall is Disabled on {context.hostname}",
                description=f"The endpoint firewall on {context.hostname} ({context.platform}) is currently turned off.",
                severity=Severity.HIGH,
                cwe_id=self.cwe_id,
                owasp_category=self.owasp_category,
                remediation="Enable the host firewall (e.g., Windows Defender Firewall or ufw/iptables on Linux).",
                evidence={"firewall_status": "DISABLED", "profiles": profiles},
            )

        return EndpointCheckResult(
            check_id=self.id,
            agent_id=context.agent_id,
            asset_id=context.asset_id,
            status="PASS",
            title=f"Host-based Firewall is Active on {context.hostname}",
            description="Firewall is active and enforcing rules.",
            severity=Severity.INFO,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            remediation="No action required.",
            evidence={"firewall_status": "ENABLED", "profiles": profiles},
        )
