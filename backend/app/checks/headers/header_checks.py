"""
Security Header Verification Checks
"""
from app.checks.base import BaseSecurityCheck, CheckContext, CheckResult
from app.models import Severity


class SecurityHeadersCheck(BaseSecurityCheck):
    id = "SEC_HEADERS"
    name = "Missing Security Headers Check"
    category = "HEADERS"
    severity = Severity.LOW
    cwe_id = "CWE-693"
    owasp_category = "A05:2021-Security Misconfiguration"

    CRITICAL_HEADERS = {
        "strict-transport-security": ("HSTS missing — enables SSL stripping attacks", Severity.MEDIUM),
        "content-security-policy": ("CSP missing — enables Cross-Site Scripting (XSS)", Severity.MEDIUM),
        "x-content-type-options": ("X-Content-Type-Options missing — allows MIME confusion", Severity.LOW),
        "x-frame-options": ("X-Frame-Options missing — allows Clickjacking attacks", Severity.MEDIUM),
        "referrer-policy": ("Referrer-Policy missing — may leak sensitive URLs", Severity.LOW),
        "permissions-policy": ("Permissions-Policy missing — browser features unrestricted", Severity.LOW),
    }

    async def run(self, context: CheckContext) -> list[CheckResult]:
        results = []
        resp_headers_lower = {k.lower(): v for k, v in context.response_headers.items()}

        for header_name, (desc, default_sev) in self.CRITICAL_HEADERS.items():
            if header_name not in resp_headers_lower:
                results.append(CheckResult(
                    check_id=f"MISSING_{header_name.upper().replace('-', '_')}",
                    vulnerable=True,
                    title=f"Missing Security Header: {header_name}",
                    description=f"The HTTP response from {context.target_url} lacks the '{header_name}' header. {desc}",
                    severity=default_sev,
                    cwe_id=self.cwe_id,
                    owasp_category=self.owasp_category,
                    confidence=95,
                    impact="Reduces browser defense-in-depth protection.",
                    remediation=f"Configure the web server or reverse proxy to include '{header_name}'.",
                    affected_url=context.target_url,
                ))

        return results
