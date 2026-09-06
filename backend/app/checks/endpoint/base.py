"""
Endpoint Security Checks Base Interface & Result Contracts
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Any
from app.models import Severity


@dataclass
class EndpointCheckContext:
    agent_id: str
    asset_id: Optional[str]
    platform: str  # windows, linux, darwin
    hostname: str
    telemetry_data: dict = field(default_factory=dict)
    parameters: dict = field(default_factory=dict)


@dataclass
class EndpointCheckResult:
    check_id: str
    agent_id: str
    asset_id: Optional[str]
    status: str  # PASS, FAIL, ERROR
    title: str
    description: str
    severity: Severity
    cwe_id: str
    owasp_category: str
    remediation: str
    evidence: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class BaseEndpointCheck(ABC):
    """Abstract Base Class for all declarative endpoint security checks."""

    id: str = "BASE_ENDPOINT_CHECK"
    name: str = "Base Endpoint Check"
    category: str = "OS"
    severity: Severity = Severity.MEDIUM
    cwe_id: str = "CWE-000"
    owasp_category: str = "A05:2021-Security Misconfiguration"
    supported_platforms: list[str] = ["windows", "linux", "darwin"]

    @abstractmethod
    async def evaluate(self, context: EndpointCheckContext) -> EndpointCheckResult:
        """Evaluates telemetry data against security baseline."""
        pass
