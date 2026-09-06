import json
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, update
import structlog

from app.models import (
    EndpointAgent,
    EndpointBaseline,
    SecurityDriftEvent,
    Finding,
    Severity,
)
from app.services.evidence_service import EvidenceService

logger = structlog.get_logger(__name__)


class BaselineDriftService:
    """
    Manages endpoint security baselines and detects drift/configuration regressions.
    """

    async def capture_baseline(
        self,
        db: AsyncSession,
        agent_id: str,
        baseline_data: Dict[str, Any],
        created_by_id: Optional[str] = None,
    ) -> EndpointBaseline:
        """Capture or update the active baseline configuration for an endpoint."""
        agent_stmt = select(EndpointAgent).where(EndpointAgent.id == agent_id)
        agent = (await db.execute(agent_stmt)).scalars().first()
        if not agent:
            raise ValueError(f"Agent {agent_id} not found")

        # Deactivate previous active baselines
        deactivate_stmt = (
            update(EndpointBaseline)
            .where(
                and_(
                    EndpointBaseline.agent_id == agent_id,
                    EndpointBaseline.is_active == True,
                )
            )
            .values(is_active=False)
        )
        await db.execute(deactivate_stmt)

        # Get latest version number
        latest_stmt = (
            select(EndpointBaseline)
            .where(EndpointBaseline.agent_id == agent_id)
            .order_by(EndpointBaseline.version.desc())
        )
        latest = (await db.execute(latest_stmt)).scalars().first()
        next_version = (latest.version + 1) if latest else 1

        payload_bytes = json.dumps(baseline_data, sort_keys=True).encode()
        fingerprint = hashlib.sha256(payload_bytes).hexdigest()

        baseline = EndpointBaseline(
            id=str(uuid.uuid4()),
            agent_id=agent_id,
            version=next_version,
            data=baseline_data,
            fingerprint=fingerprint,
            is_active=True,
            created_by_id=created_by_id,
        )
        db.add(baseline)
        await db.commit()
        await db.refresh(baseline)

        logger.info(
            "Endpoint baseline captured",
            agent_id=agent_id,
            version=next_version,
            fingerprint=fingerprint,
        )
        return baseline

    async def detect_drift(
        self,
        db: AsyncSession,
        agent_id: str,
        current_data: Dict[str, Any],
    ) -> Optional[SecurityDriftEvent]:
        """
        Compare current endpoint state with the active baseline.
        If discrepancies are detected, generates a SecurityDriftEvent and a Finding.
        """
        agent_stmt = select(EndpointAgent).where(EndpointAgent.id == agent_id)
        agent = (await db.execute(agent_stmt)).scalars().first()
        if not agent:
            raise ValueError(f"Agent {agent_id} not found")

        baseline_stmt = select(EndpointBaseline).where(
            and_(
                EndpointBaseline.agent_id == agent_id,
                EndpointBaseline.is_active == True,
            )
        )
        baseline = (await db.execute(baseline_stmt)).scalars().first()
        if not baseline:
            # No baseline yet captured; capture this as baseline
            logger.info("No active baseline found, setting current state as v1 baseline", agent_id=agent_id)
            await self.capture_baseline(db, agent_id, current_data)
            return None

        # Compare baseline and current data
        diff, drift_types, max_severity = self._compute_diff(baseline.data, current_data)

        if not diff:
            return None

        primary_drift_type = drift_types[0] if drift_types else "CONFIG_DRIFT"

        drift_event = SecurityDriftEvent(
            id=str(uuid.uuid4()),
            agent_id=agent_id,
            baseline_id=baseline.id,
            drift_type=primary_drift_type,
            severity=max_severity,
            diff_data=diff,
            is_resolved=False,
        )
        db.add(drift_event)

        # Generate a Finding for visibility in Project
        if agent.project_id:
            finding = Finding(
                id=str(uuid.uuid4()),
                project_id=agent.project_id,
                title=f"Security Baseline Drift Detected on {agent.hostname} ({primary_drift_type})",
                description=f"Automated comparison identified unauthorized or unexpected modifications from baseline v{baseline.version}: {json.dumps(diff, indent=2)}",
                severity=max_severity,
                affected_asset=agent.hostname,
                cvss_score=7.5 if max_severity in [Severity.CRITICAL, Severity.HIGH] else 4.5,
                recommendation="Investigate recent configuration changes or unauthorized activity on the endpoint to restore baseline compliance.",
                agent_id=agent.id,
            )
            db.add(finding)

            # Record Evidence
            ev_svc = EvidenceService(db)
            await ev_svc.record_evidence(
                finding_id=finding.id,
                agent_id=agent.id,
                url=agent.hostname,
                agent_type="ENDPOINT_AGENT",
                additional_data={"baseline_id": baseline.id, "diff": diff},
                test_executed="BASELINE_DRIFT_DETECTOR",
            )

        await db.commit()
        await db.refresh(drift_event)

        logger.warning(
            "Security drift detected",
            agent_id=agent_id,
            drift_type=primary_drift_type,
            severity=str(max_severity),
        )
        return drift_event

    def _compute_diff(
        self, baseline_data: Dict[str, Any], current_data: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], List[str], Severity]:
        """Compute key differences and assess drift severity."""
        diff: Dict[str, Any] = {}
        drift_types: List[str] = []
        max_severity = Severity.LOW

        # 1. Firewall check
        b_fw = baseline_data.get("firewall_enabled")
        c_fw = current_data.get("firewall_enabled")
        if b_fw is True and c_fw is False:
            diff["firewall_disabled"] = {"expected": True, "actual": False}
            drift_types.append("FIREWALL_DISABLED")
            max_severity = Severity.HIGH

        # 2. Security Controls (EDR, BitLocker)
        b_edr = baseline_data.get("edr_active")
        c_edr = current_data.get("edr_active")
        if b_edr is True and c_edr is False:
            diff["edr_deactivated"] = {"expected": True, "actual": False}
            drift_types.append("EDR_DEACTIVATED")
            max_severity = Severity.CRITICAL

        # 3. New Listening Ports / Services
        b_services = set(baseline_data.get("open_ports", []))
        c_services = set(current_data.get("open_ports", []))
        new_ports = list(c_services - b_services)
        if new_ports:
            diff["new_listening_ports"] = new_ports
            drift_types.append("NEW_EXPOSED_SERVICE")
            if max_severity not in [Severity.CRITICAL, Severity.HIGH]:
                max_severity = Severity.MEDIUM

        # 4. OS Settings (e.g. UAC disabled or SSH root enabled)
        b_uac = baseline_data.get("uac_enabled")
        c_uac = current_data.get("uac_enabled")
        if b_uac is True and c_uac is False:
            diff["uac_disabled"] = {"expected": True, "actual": False}
            drift_types.append("SECURITY_SETTING_DOWNGRADE")
            if max_severity != Severity.CRITICAL:
                max_severity = Severity.HIGH

        return diff, drift_types, max_severity


baseline_drift_service = BaselineDriftService()
