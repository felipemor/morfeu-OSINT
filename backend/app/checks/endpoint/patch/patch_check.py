"""
Endpoint Patch Status Assessment Check
"""
from app.checks.endpoint.base import BaseEndpointCheck, EndpointCheckContext, EndpointCheckResult
from app.models import Severity


class PatchAssessmentCheck(BaseEndpointCheck):
    id = "EP-PATCH-001"
    name = "Missing Security Patches Check"
    category = "PATCH"
    severity = Severity.HIGH
    cwe_id = "CWE-1395"
    owasp_category = "A06:2021-Vulnerable and Outdated Components"

    async def evaluate(self, context: EndpointCheckContext) -> EndpointCheckResult:
        patch_data = context.telemetry_data.get("patches", {})
        missing_critical = patch_data.get("missing_critical_count", 0)
        days_since_update = patch_data.get("days_since_last_update", 10)

        if missing_critical > 0 or days_since_update > 60:
            return EndpointCheckResult(
                check_id=self.id,
                agent_id=context.agent_id,
                asset_id=context.asset_id,
                status="FAIL",
                title=f"Missing Critical Security Updates on {context.hostname}",
                description=f"Host is missing {missing_critical} critical updates ({days_since_update} days since last patch cycle).",
                severity=Severity.HIGH if missing_critical > 0 else Severity.MEDIUM,
                cwe_id=self.cwe_id,
                owasp_category=self.owasp_category,
                remediation="Apply pending security updates and establish automated monthly patch management.",
                evidence={"missing_critical": missing_critical, "days_since_update": days_since_update},
            )

        return EndpointCheckResult(
            check_id=self.id,
            agent_id=context.agent_id,
            asset_id=context.asset_id,
            status="PASS",
            title=f"Security Patch Status is Up to Date on {context.hostname}",
            description="System is running current vendor security updates.",
            severity=Severity.INFO,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            remediation="No action required.",
            evidence={"days_since_update": days_since_update},
        )
