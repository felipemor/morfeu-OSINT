"""
CORS Configuration Checks
"""
from app.checks.base import BaseSecurityCheck, CheckContext, CheckResult
from app.models import Severity


class CorsMisconfigurationCheck(BaseSecurityCheck):
    id = "CORS_MISCONFIG"
    name = "CORS Misconfiguration Check"
    category = "CORS"
    severity = Severity.HIGH
    cwe_id = "CWE-942"
    owasp_category = "A05:2021-Security Misconfiguration"

    async def run(self, context: CheckContext) -> list[CheckResult]:
        results = []
        resp_headers_lower = {k.lower(): str(v) for k, v in context.response_headers.items()}
        allow_origin = resp_headers_lower.get("access-control-allow-origin", "")
        allow_creds = resp_headers_lower.get("access-control-allow-credentials", "").lower() == "true"

        # Wildcard Origin
        if allow_origin == "*":
            results.append(CheckResult(
                check_id="CORS_WILDCARD_ORIGIN",
                vulnerable=True,
                title="CORS Wildcard Access-Control-Allow-Origin",
                description=f"The endpoint {context.target_url} allows all origins with '*'.",
                severity=Severity.LOW,
                cwe_id=self.cwe_id,
                owasp_category=self.owasp_category,
                confidence=90,
                impact="Any website can read unauthenticated responses from this endpoint.",
                remediation="Restrict Access-Control-Allow-Origin to trusted domains only.",
                affected_url=context.target_url,
            ))
        elif allow_origin == "null" and allow_creds:
            results.append(CheckResult(
                check_id="CORS_NULL_ORIGIN_WITH_CREDENTIALS",
                vulnerable=True,
                title="CORS Insecure 'null' Origin with Credentials",
                description=f"The endpoint {context.target_url} trusts 'null' origin with Access-Control-Allow-Credentials: true.",
                severity=Severity.HIGH,
                cwe_id=self.cwe_id,
                owasp_category=self.owasp_category,
                confidence=95,
                impact="Sandboxed iframes and local file pages can execute cross-origin requests with user credentials.",
                remediation="Never trust origin 'null'. Enforce strict origin whitelist.",
                affected_url=context.target_url,
            ))

        return results
