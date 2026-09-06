import uuid
from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
import structlog

from app.models import Asset, Finding, Severity, EndpointAgent

logger = structlog.get_logger(__name__)


class CrossPlaneCorrelationEngine:
    """
    Correlates findings and telemetry across the External Attack Surface (Recon/Web/API)
    and the Internal Endpoint Posture (Endpoint Agent checks, Baselines).
    """

    async def correlate_project_assets(
        self, db: AsyncSession, project_id: str
    ) -> List[Dict[str, Any]]:
        """
        Analyze all assets in a project, identifying cross-plane correlations where
        external exposures meet internal endpoint weaknesses.
        """
        # 1. Fetch all assets for the project
        asset_stmt = select(Asset).where(Asset.project_id == project_id)
        assets = (await db.execute(asset_stmt)).scalars().all()

        correlations = []

        for asset in assets:
            if not asset.agent_id:
                continue  # Only correlate assets that have an endpoint agent

            # 2. Fetch findings for this asset
            finding_stmt = select(Finding).where(
                and_(
                    Finding.project_id == project_id,
                    (Finding.affected_asset.like(f"%{asset.value}%")) | (Finding.asset_id == asset.id) | (Finding.agent_id == asset.agent_id),
                )
            )
            findings = (await db.execute(finding_stmt)).scalars().all()

            external_findings = []
            endpoint_findings = []

            for f in findings:
                if f.agent_id or "Endpoint" in f.title or "Baseline" in f.title:
                    endpoint_findings.append(f)
                else:
                    external_findings.append(f)

            if external_findings and endpoint_findings:
                # We have both external exposure & internal endpoint vulnerabilities on the same asset!
                correlation_summary = {
                    "asset_id": asset.id,
                    "hostname": asset.hostname or asset.value,
                    "agent_id": asset.agent_id,
                    "external_exposure_count": len(external_findings),
                    "endpoint_weakness_count": len(endpoint_findings),
                    "correlated_risk_level": "CRITICAL" if any(f.severity in [Severity.CRITICAL, Severity.HIGH] for f in findings) else "HIGH",
                    "attack_path": f"External exposure ({len(external_findings)} findings) directly paths to internal host with {len(endpoint_findings)} endpoint vulnerabilities",
                    "external_finding_titles": [f.title for f in external_findings[:3]],
                    "endpoint_finding_titles": [f.title for f in endpoint_findings[:3]],
                }
                correlations.append(correlation_summary)

        return correlations


cross_plane_correlation = CrossPlaneCorrelationEngine()
