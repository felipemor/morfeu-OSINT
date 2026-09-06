"""
Authentication & Authorization Security Checks
"""
from app.checks.base import BaseSecurityCheck, CheckContext, CheckResult
from app.models import Severity


class AuthSecurityCheck(BaseSecurityCheck):
    id = "AUTH_SECURITY"
    name = "Authentication Security Check"
    category = "AUTH"
    severity = Severity.HIGH
    cwe_id = "CWE-287"
    owasp_category = "API2:2023-Broken Authentication"

    async def run(self, context: CheckContext) -> list[CheckResult]:
        results = []
        # Check if protected endpoint returns 200 OK without token
        if context.extra.get("auth_required") and not context.auth_token:
            if context.response_status == 200:
                results.append(CheckResult(
                    check_id="AUTH_MISSING_ENFORCEMENT",
                    vulnerable=True,
                    title="Missing Authentication on Protected Endpoint",
                    description=f"Endpoint {context.target_url} declared as authenticated responded with HTTP 200 without credentials.",
                    severity=Severity.HIGH,
                    cwe_id="CWE-306",
                    owasp_category=self.owasp_category,
                    confidence=90,
                    impact="Unauthorized users can access protected business operations.",
                    remediation="Enforce authentication middleware on all private routes.",
                    affected_url=context.target_url,
                ))

        return results
