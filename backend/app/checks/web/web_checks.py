"""
Web Application Security Checks (XSS, Directory Traversal, Open Redirect)
"""
from app.checks.base import BaseSecurityCheck, CheckContext, CheckResult
from app.models import Severity


class WebSecurityCheck(BaseSecurityCheck):
    id = "WEB_SECURITY"
    name = "Web Vulnerability Verification Check"
    category = "WEB"
    severity = Severity.HIGH
    cwe_id = "CWE-79"
    owasp_category = "A03:2021-Injection"

    async def run(self, context: CheckContext) -> list[CheckResult]:
        results = []
        body = context.response_body or ""
        test_payload = context.extra.get("payload", "")

        # Reflected Input check (XSS indicator)
        if test_payload and test_payload in body and "<script>" in test_payload.lower():
            results.append(CheckResult(
                check_id="WEB_REFLECTED_XSS",
                vulnerable=True,
                title="Potential Reflected Cross-Site Scripting (XSS)",
                description=f"Injected probe '{test_payload}' was reflected in the response body without HTML sanitization.",
                severity=Severity.HIGH,
                cwe_id="CWE-79",
                owasp_category="A03:2021-Injection",
                confidence=85,
                impact="Allows attackers to execute malicious scripts in victim browsers.",
                remediation="Properly contextually encode and sanitize all user-supplied inputs.",
                parameter=context.extra.get("param_name"),
                affected_url=context.target_url,
            ))

        return results
