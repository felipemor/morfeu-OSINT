"""
Cookie Security Flags Checks
"""
from app.checks.base import BaseSecurityCheck, CheckContext, CheckResult
from app.models import Severity


class CookieSecurityCheck(BaseSecurityCheck):
    id = "COOKIE_FLAGS"
    name = "Insecure Cookie Flags Check"
    category = "COOKIES"
    severity = Severity.MEDIUM
    cwe_id = "CWE-614"
    owasp_category = "A05:2021-Security Misconfiguration"

    async def run(self, context: CheckContext) -> list[CheckResult]:
        results = []
        # Check Set-Cookie headers in responses
        set_cookie = context.response_headers.get("Set-Cookie") or context.response_headers.get("set-cookie")
        if not set_cookie:
            return results

        cookies = [set_cookie] if isinstance(set_cookie, str) else list(set_cookie)
        for cookie_str in cookies:
            cookie_lower = cookie_str.lower()
            name = cookie_str.split("=")[0].strip()

            if "secure" not in cookie_lower:
                results.append(CheckResult(
                    check_id="COOKIE_MISSING_SECURE",
                    vulnerable=True,
                    title=f"Cookie Missing 'Secure' Flag: {name}",
                    description=f"Cookie '{name}' is transmitted over cleartext HTTP.",
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-614",
                    owasp_category=self.owasp_category,
                    confidence=95,
                    impact="Cookie can be intercepted by an on-path attacker.",
                    remediation="Set the 'Secure' attribute on all sensitive cookies.",
                    affected_url=context.target_url,
                ))

            if "httponly" not in cookie_lower:
                results.append(CheckResult(
                    check_id="COOKIE_MISSING_HTTPONLY",
                    vulnerable=True,
                    title=f"Cookie Missing 'HttpOnly' Flag: {name}",
                    description=f"Cookie '{name}' is accessible via JavaScript document.cookie.",
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-1004",
                    owasp_category=self.owasp_category,
                    confidence=95,
                    impact="Increases vulnerability to XSS token theft.",
                    remediation="Set 'HttpOnly' attribute on session cookies.",
                    affected_url=context.target_url,
                ))

            if "samesite" not in cookie_lower:
                results.append(CheckResult(
                    check_id="COOKIE_MISSING_SAMESITE",
                    vulnerable=True,
                    title=f"Cookie Missing 'SameSite' Flag: {name}",
                    description=f"Cookie '{name}' lacks SameSite attribute.",
                    severity=Severity.LOW,
                    cwe_id="CWE-1275",
                    owasp_category=self.owasp_category,
                    confidence=90,
                    impact="Increases risk of Cross-Site Request Forgery (CSRF).",
                    remediation="Set SameSite=Lax or SameSite=Strict on cookies.",
                    affected_url=context.target_url,
                ))

        return results
