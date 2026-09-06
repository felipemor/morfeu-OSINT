"""
Security Checks Registry — Dynamic discovery and execution of modular security checks
"""
from typing import Optional
from app.checks.base import BaseSecurityCheck, CheckContext, CheckResult
from app.checks.headers.header_checks import SecurityHeadersCheck
from app.checks.cors.cors_checks import CorsMisconfigurationCheck
from app.checks.cookies.cookie_checks import CookieSecurityCheck
from app.checks.api.api_checks import ApiSecurityCheck
from app.checks.auth.auth_checks import AuthSecurityCheck
from app.checks.web.web_checks import WebSecurityCheck


class CheckRegistry:
    """Registry holding all available security checks."""

    def __init__(self):
        self._checks: dict[str, BaseSecurityCheck] = {}
        self._register_default_checks()

    def _register_default_checks(self):
        self.register(SecurityHeadersCheck())
        self.register(CorsMisconfigurationCheck())
        self.register(CookieSecurityCheck())
        self.register(ApiSecurityCheck())
        self.register(AuthSecurityCheck())
        self.register(WebSecurityCheck())

    def register(self, check: BaseSecurityCheck):
        self._checks[check.id] = check

    def get_checks(self, category: Optional[str] = None) -> list[BaseSecurityCheck]:
        if category:
            return [c for c in self._checks.values() if c.category.upper() == category.upper()]
        return list(self._checks.values())

    async def run_all(self, context: CheckContext, category: Optional[str] = None) -> list[CheckResult]:
        """Runs all registered checks matching the specified category."""
        results = []
        checks = self.get_checks(category)
        for check in checks:
            try:
                res = await check.run(context)
                results.extend(res)
            except Exception as e:
                # Individual check failure must not crash the entire scan
                pass
        return results


# Global Registry Instance
registry = CheckRegistry()
