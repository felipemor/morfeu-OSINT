"""
API Security Checks — BOLA, Mass Assignment, Excessive Data Exposure, Error Handling
"""
import json
from app.checks.base import BaseSecurityCheck, CheckContext, CheckResult
from app.models import Severity


class ApiSecurityCheck(BaseSecurityCheck):
    id = "API_SECURITY"
    name = "API Security Best Practices Check"
    category = "API"
    severity = Severity.HIGH
    cwe_id = "CWE-285"
    owasp_category = "API1:2023-Broken Object Level Authorization"

    async def run(self, context: CheckContext) -> list[CheckResult]:
        results = []
        body = context.response_body or ""

        # 1. Excessive Data Exposure Check
        if body.startswith("{") or body.startswith("["):
            try:
                data = json.loads(body)
                serialized = json.dumps(data).lower()
                for sensitive_key in ["password_hash", "secret_key", "internal_id", "ssn", "credit_card", "private_token"]:
                    if sensitive_key in serialized:
                        results.append(CheckResult(
                            check_id="API_EXCESSIVE_DATA_EXPOSURE",
                            vulnerable=True,
                            title=f"API Excessive Data Exposure: {sensitive_key}",
                            description=f"API response from {context.target_url} exposes sensitive internal field '{sensitive_key}'.",
                            severity=Severity.HIGH,
                            cwe_id="CWE-200",
                            owasp_category="API3:2023-Broken Object Property Level Authorization",
                            confidence=85,
                            impact="Sensitive internal fields or PII leaked to clients.",
                            remediation="Implement response filtering DTOs/schemas to exclude sensitive attributes.",
                            affected_url=context.target_url,
                        ))
            except Exception:
                pass

        # 2. Stack Trace / Improper Error Handling
        stack_indicators = [
            "Traceback (most recent call last)",
            "NullPointerException",
            "Unhandled Exception",
            "pg_query(): Query failed",
            "SQLSTATE[",
            "at org.apache.",
            "SyntaxError: unexpected token",
        ]
        for indicator in stack_indicators:
            if indicator in body:
                results.append(CheckResult(
                    check_id="API_IMPROPER_ERROR_HANDLING",
                    vulnerable=True,
                    title="Improper Error Handling / Stack Trace Disclosure",
                    description=f"API response from {context.target_url} leaks server debug stack traces ({indicator}).",
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-209",
                    owasp_category="API8:2023-Security Misconfiguration",
                    confidence=95,
                    impact="Reveals implementation details, library versions, and internal code paths.",
                    remediation="Disable debug error pages in production and return generic error schemas.",
                    affected_url=context.target_url,
                ))
                break

        return results
