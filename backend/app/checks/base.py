"""
Security Checks Plugin Architecture — Base check interface and result models
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Any
from app.models import Severity


@dataclass
class CheckContext:
    target_url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    body: Optional[str] = None
    parameters: list = field(default_factory=list)
    auth_token: Optional[str] = None
    role: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: dict = field(default_factory=dict)
    response_body: Optional[str] = None
    extra: dict = field(default_factory=dict)


@dataclass
class CheckResult:
    check_id: str
    vulnerable: bool
    title: str
    description: str
    severity: Severity
    cwe_id: str
    owasp_category: str
    confidence: int = 80
    impact: str = "MEDIUM"
    remediation: str = ""
    evidence_request: Optional[str] = None
    evidence_response: Optional[str] = None
    parameter: Optional[str] = None
    affected_url: Optional[str] = None
    raw_data: dict = field(default_factory=dict)


class BaseSecurityCheck(ABC):
    """Abstract Base Class for all modular security checks."""

    id: str = "BASE_CHECK"
    name: str = "Base Security Check"
    category: str = "GENERAL"
    severity: Severity = Severity.MEDIUM
    cwe_id: str = "CWE-000"
    owasp_category: str = "A00:2021"

    @abstractmethod
    async def run(self, context: CheckContext) -> list[CheckResult]:
        """Execute check against the provided target context."""
        pass
