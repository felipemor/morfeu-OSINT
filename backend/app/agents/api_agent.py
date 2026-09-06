"""
API Security Agent — Specialized scanner for REST, GraphQL, and OpenAPI/Swagger APIs
"""
import asyncio
import httpx
from typing import Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from app.checks.base import CheckContext
from app.checks.registry import registry
from app.core.database import AsyncSessionLocal
from app.core.scope_validator import ScopeValidator
from app.models import Endpoint, Finding, FindingStatus, Severity, AgentType, ScanMode
from app.security.policy_engine import PolicyEngine, PolicyConfig, PolicyDecision
from app.services.evidence_service import EvidenceService
from app.services.finding_pipeline import FindingPipelineService

logger = structlog.get_logger(__name__)

OPENAPI_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/api/swagger.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/graphql",
    "/api/graphql",
]


class ApiSecurityAgent:
    """Discovers API schemas, analyzes endpoints, and tests for API vulnerabilities within policy limits."""

    def __init__(self, scan_id: str, project_id: str, scope_data: dict):
        self.scan_id = scan_id
        self.project_id = project_id
        self.scope_data = scope_data
        self.scope_validator = ScopeValidator(
            allowed_domains=scope_data.get("domains"),
            allowed_ips=scope_data.get("ips"),
            allowed_cidrs=scope_data.get("cidrs"),
            excluded_domains=scope_data.get("excluded_domains"),
            excluded_ips=scope_data.get("excluded_ips"),
            excluded_paths=scope_data.get("excluded_paths"),
            allow_private_ips=scope_data.get("allow_private_ips", False),
        )
        self.policy_engine = PolicyEngine(
            scope_validator=self.scope_validator,
            config=PolicyConfig(
                environment=scope_data.get("environment", "development"),
                max_requests_per_minute=scope_data.get("max_requests_per_minute", 30),
            ),
        )

    async def run(self) -> int:
        """Runs API discovery and security checks on all discovered API endpoints."""
        logger.info("📡 Starting API Security Agent", scan_id=self.scan_id, project_id=self.project_id)
        findings_created = 0

        async with AsyncSessionLocal() as db:
            evidence_svc = EvidenceService(db)
            finding_svc = FindingPipelineService(db)

            # 1. Fetch all API endpoints for this project
            ep_res = await db.execute(
                select(Endpoint).where(
                    Endpoint.project_id == self.project_id,
                )
            )
            endpoints = ep_res.scalars().all()

            # 2. Check OpenAPI / Schema endpoints on root domains
            domains = self.scope_data.get("domains", [])
            for domain in domains:
                base_url = f"https://{domain}" if not domain.startswith("http") else domain
                for schema_path in OPENAPI_PATHS:
                    target = f"{base_url}{schema_path}"
                    policy_res = self.policy_engine.evaluate_request(
                        target_url=target,
                        method="GET",
                        test_type="API_DISCOVERY",
                        agent_type="API_AGENT",
                        project_id=self.project_id,
                    )
                    if not policy_res.allowed:
                        continue

                    try:
                        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
                            resp = await client.get(target, headers={"User-Agent": "Pentest-Agent/2.0"})
                            if resp.status_code == 200 and ("swagger" in resp.text.lower() or "openapi" in resp.text.lower()):
                                # Discovered OpenAPI document
                                finding = Finding(
                                    project_id=self.project_id,
                                    scan_id=self.scan_id,
                                    title=f"Exposed API Schema Documentation: {schema_path}",
                                    severity=Severity.INFO,
                                    status=FindingStatus.CONFIRMED,
                                    owasp_category="API9:2023-Improper Inventory Management",
                                    cwe_id="CWE-200",
                                    confidence=95,
                                    affected_url=target,
                                    description=f"Publicly accessible API schema documentation found at {target}.",
                                    recommendation="Restrict API documentation access to authorized internal networks or developers.",
                                    discovered_by="API_AGENT",
                                )
                                db.add(finding)
                                await db.commit()
                                await db.refresh(finding)

                                await evidence_svc.record_evidence(
                                    finding_id=finding.id,
                                    scan_id=self.scan_id,
                                    http_method="GET",
                                    url=target,
                                    response_status=resp.status_code,
                                    response_headers=str(dict(resp.headers)),
                                    response_body=resp.text[:2000],
                                    agent_type="API_AGENT",
                                    test_executed="OPENAPI_SCHEMA_DISCOVERY",
                                )
                                findings_created += 1
                                break
                    except Exception:
                        pass

            # 3. Run check plugins on existing endpoints
            for ep in endpoints:
                # Validate against policy before running check
                policy_res = self.policy_engine.evaluate_request(
                    target_url=ep.url,
                    method=ep.method,
                    test_type="API_TESTING",
                    agent_type="API_AGENT",
                    project_id=self.project_id,
                )
                if not policy_res.allowed:
                    continue

                try:
                    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
                        resp = await client.request(
                            method=ep.method,
                            url=ep.url,
                            headers={"User-Agent": "Pentest-Agent/2.0"},
                        )
                        ctx = CheckContext(
                            target_url=ep.url,
                            method=ep.method,
                            headers=dict(resp.headers),
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers),
                            response_body=resp.text,
                            parameters=ep.parameters,
                            extra={"auth_required": ep.auth_required},
                        )

                        check_results = await registry.run_all(ctx, category="API")
                        for cr in check_results:
                            if cr.vulnerable:
                                finding = Finding(
                                    project_id=self.project_id,
                                    scan_id=self.scan_id,
                                    endpoint_id=ep.id,
                                    title=cr.title,
                                    severity=cr.severity,
                                    status=FindingStatus.CONFIRMED,
                                    owasp_category=cr.owasp_category,
                                    cwe_id=cr.cwe_id,
                                    confidence=cr.confidence,
                                    affected_url=ep.url,
                                    description=cr.description,
                                    recommendation=cr.remediation,
                                    discovered_by="API_AGENT",
                                )
                                db.add(finding)
                                await db.commit()
                                await db.refresh(finding)

                                await evidence_svc.record_evidence(
                                    finding_id=finding.id,
                                    scan_id=self.scan_id,
                                    http_method=ep.method,
                                    url=ep.url,
                                    response_status=resp.status_code,
                                    response_headers=str(dict(resp.headers)),
                                    response_body=resp.text[:2000],
                                    agent_type="API_AGENT",
                                    test_executed=cr.check_id,
                                )
                                findings_created += 1
                except Exception as e:
                    logger.debug("API check probe failed", endpoint=ep.url, error=str(e))

        logger.info("✅ API Security Agent complete", findings_created=findings_created)
        return findings_created


def run_api_checks(scan_id: str, project_id: str, scope_data: dict) -> int:
    """Celery synchronous wrapper."""
    agent = ApiSecurityAgent(scan_id, project_id, scope_data)
    return asyncio.run(agent.run())
