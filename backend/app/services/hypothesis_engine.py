"""
AI Hypothesis Engine & Explainable AI Reasoning Service

Analyzes discovered attack surface and formulates structured security hypotheses
with explainable justifications ("Why was this test selected?").
"""
from datetime import datetime, timezone
from typing import Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from app.models import (
    Asset, Endpoint, SecurityHypothesis, HypothesisStatus,
    Severity, Finding
)

logger = structlog.get_logger(__name__)


class HypothesisEngine:
    """Generates structured hypotheses with explainable AI reasoning based on attack surface topology."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def generate_hypotheses_for_project(
        self,
        project_id: str,
        scan_id: Optional[str] = None,
    ) -> list[SecurityHypothesis]:
        """
        Analyzes discovered assets and endpoints to produce prioritized security hypotheses.
        """
        # 1. Fetch Endpoints and Assets
        ep_result = await self.db.execute(select(Endpoint).where(Endpoint.project_id == project_id))
        endpoints = ep_result.scalars().all()

        asset_result = await self.db.execute(select(Asset).where(Asset.project_id == project_id))
        assets = asset_result.scalars().all()

        hypotheses: list[SecurityHypothesis] = []
        counter = 1

        # Pattern 1: Endpoints accepting IDs or object references (BOLA/IDOR hypothesis)
        for ep in endpoints:
            has_id_param = any(
                p.get("name", "").lower() in ["id", "user_id", "account_id", "order_id", "uuid", "doc_id"]
                or "{" in ep.path
                for p in ep.parameters
            )
            if has_id_param or any(f"/{kw}/" in ep.path for kw in ["user", "account", "order", "document", "item"]):
                h = SecurityHypothesis(
                    project_id=project_id,
                    scan_id=scan_id,
                    hypothesis_code=f"H{counter:03d}",
                    target=ep.url,
                    title="Potential Broken Object Level Authorization (BOLA / IDOR)",
                    reasoning=[
                        f"Endpoint '{ep.method} {ep.path}' accepts object identifiers in URL path/parameters.",
                        "Observed parameter semantics match entity lookups.",
                        "Modern APIs often lack granular object-level ownership checks across different user roles.",
                    ],
                    confidence=85,
                    priority=Severity.HIGH,
                    status=HypothesisStatus.PROPOSED,
                    test_type="BOLA_VALIDATION",
                    suggested_actions=[
                        {"action": "HTTP_REQUEST", "method": ep.method, "url": ep.url, "role_context": "ROLE_B"},
                    ],
                )
                hypotheses.append(h)
                self.db.add(h)
                counter += 1

        # Pattern 2: API endpoints with authentication detected (Broken Auth / JWT / Key hypothesis)
        for ep in endpoints:
            if ep.is_api and ep.auth_required:
                h = SecurityHypothesis(
                    project_id=project_id,
                    scan_id=scan_id,
                    hypothesis_code=f"H{counter:03d}",
                    target=ep.url,
                    title="Potential API Authentication Bypass & Token Weakness",
                    reasoning=[
                        f"API Endpoint '{ep.path}' enforces authentication ({ep.auth_type or 'Bearer/Token'}).",
                        "Authentication headers and token verification procedures must be checked against signature stripping and algorithm confusion.",
                    ],
                    confidence=75,
                    priority=Severity.HIGH,
                    status=HypothesisStatus.PROPOSED,
                    test_type="AUTH_BYPASS_TEST",
                    suggested_actions=[
                        {"action": "TEST_UNAUTHENTICATED_ACCESS", "url": ep.url, "method": ep.method},
                        {"action": "TEST_TAMPERED_TOKEN", "url": ep.url, "method": ep.method},
                    ],
                )
                hypotheses.append(h)
                self.db.add(h)
                counter += 1

        # Pattern 3: Administrative or Management paths
        for ep in endpoints:
            if any(admin_kw in ep.path.lower() for admin_kw in ["admin", "manager", "dashboard", "internal", "config"]):
                h = SecurityHypothesis(
                    project_id=project_id,
                    scan_id=scan_id,
                    hypothesis_code=f"H{counter:03d}",
                    target=ep.url,
                    title="Potential Broken Function Level Authorization (BFLA)",
                    reasoning=[
                        f"Administrative path '{ep.path}' detected on exposed surface.",
                        "Privileged functionality might be accessible without proper role/privilege validation.",
                    ],
                    confidence=80,
                    priority=Severity.HIGH,
                    status=HypothesisStatus.PROPOSED,
                    test_type="BFLA_TEST",
                    suggested_actions=[
                        {"action": "TEST_LEAST_PRIVILEGE_ACCESS", "url": ep.url, "method": ep.method},
                    ],
                )
                hypotheses.append(h)
                self.db.add(h)
                counter += 1

        # Pattern 4: Technology-specific hypotheses from Assets
        for asset in assets:
            if asset.technologies:
                tech_str = ", ".join(asset.technologies)
                h = SecurityHypothesis(
                    project_id=project_id,
                    scan_id=scan_id,
                    hypothesis_code=f"H{counter:03d}",
                    target=asset.value,
                    title=f"Technology Stack Security Posture Analysis ({tech_str})",
                    reasoning=[
                        f"Target asset '{asset.value}' runs stack components: {tech_str}.",
                        "Specific framework default headers, debug endpoints, and configuration flags should be validated.",
                    ],
                    confidence=70,
                    priority=Severity.MEDIUM,
                    status=HypothesisStatus.PROPOSED,
                    test_type="CONFIG_FINGERPRINT_TEST",
                    suggested_actions=[
                        {"action": "INSPECT_SECURITY_HEADERS", "url": f"http://{asset.value}"},
                    ],
                )
                hypotheses.append(h)
                self.db.add(h)
                counter += 1

        await self.db.commit()

        logger.info(
            "Hypotheses formulated",
            project_id=project_id,
            count=len(hypotheses),
        )

        return hypotheses
