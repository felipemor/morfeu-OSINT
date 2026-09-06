import secrets
import hashlib
import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_
import structlog

from app.models import (
    EndpointAgent,
    AgentEnrollmentToken,
    AgentTask,
    AgentTaskResult,
    AgentStatus,
    TaskStatus,
    TaskResultStatus,
    Asset,
    AssetType,
    Finding,
    Severity,
    AuditLog,
)
from app.core.policy_engine import policy_engine, ActionContext
from app.core.scope_validator import ScopeValidator
from app.services.kill_switch import is_action_killed_sync
from app.services.evidence_service import EvidenceService
from app.services.finding_pipeline import finding_pipeline
from app.checks.endpoint.registry import endpoint_check_registry
from app.checks.endpoint.base import EndpointCheckContext

logger = structlog.get_logger(__name__)


class AgentService:
    """
    Core management service for Endpoint Security Assessment Agents.
    Enforces pull-only architecture, policy evaluation, cryptographic integrity,
    and safe lifecycle management.
    """

    async def generate_enrollment_token(
        self,
        db: AsyncSession,
        org_id: str,
        created_by_id: str,
        project_id: Optional[str] = None,
        name: Optional[str] = "Default Enrollment Token",
        expires_in_hours: int = 24,
        max_uses: int = 1,
    ) -> AgentEnrollmentToken:
        """Generate a cryptographically random, time-bounded enrollment token."""
        raw_token = f"agt_{secrets.token_urlsafe(32)}"
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)

        token_record = AgentEnrollmentToken(
            id=str(uuid.uuid4()),
            token=raw_token,
            token_hash=token_hash,
            name=name,
            org_id=org_id,
            project_id=project_id,
            created_by_id=created_by_id,
            expires_at=expires_at,
            max_uses=max_uses,
            used_count=0,
            is_active=True,
        )
        db.add(token_record)
        await db.commit()
        await db.refresh(token_record)

        logger.info(
            "Agent enrollment token generated",
            token_id=token_record.id,
            org_id=org_id,
            expires_at=str(expires_at),
        )
        return token_record

    async def enroll_agent(
        self,
        db: AsyncSession,
        token_str: str,
        installation_id: str,
        hostname: str,
        platform_name: str,
        os_version: str = "",
        arch: str = "",
        ip_addresses: Optional[List[str]] = None,
        mac_addresses: Optional[List[str]] = None,
        public_key: Optional[str] = None,
        agent_version: str = "1.0.0",
        capabilities: Optional[List[str]] = None,
    ) -> EndpointAgent:
        """Enroll an endpoint agent using an active enrollment token."""
        # 1. Lookup and validate token
        stmt = select(AgentEnrollmentToken).where(
            and_(
                AgentEnrollmentToken.token == token_str,
                AgentEnrollmentToken.is_active == True,
            )
        )
        result = await db.execute(stmt)
        token_record = result.scalars().first()

        if not token_record:
            raise ValueError("Invalid or inactive enrollment token")

        now = datetime.now(timezone.utc)
        if token_record.expires_at and token_record.expires_at.replace(tzinfo=timezone.utc if token_record.expires_at.tzinfo is None else None) < now:
            token_record.is_active = False
            await db.commit()
            raise ValueError("Enrollment token has expired")

        if token_record.used_count >= token_record.max_uses:
            token_record.is_active = False
            await db.commit()
            raise ValueError("Enrollment token usage limit reached")

        # 2. Check if agent with this installation_id already exists in this Org
        agent_stmt = select(EndpointAgent).where(
            and_(
                EndpointAgent.installation_id == installation_id,
                EndpointAgent.org_id == token_record.org_id,
            )
        )
        existing_agent = (await db.execute(agent_stmt)).scalars().first()

        primary_ip = ip_addresses[0] if ip_addresses and len(ip_addresses) > 0 else "127.0.0.1"

        if existing_agent:
            # Re-enroll / update existing agent
            existing_agent.hostname = hostname
            existing_agent.platform = platform_name
            existing_agent.os_version = os_version
            existing_agent.arch = arch
            existing_agent.ip_addresses = ip_addresses or []
            existing_agent.mac_addresses = mac_addresses or []
            existing_agent.agent_version = agent_version
            existing_agent.capabilities = capabilities or []
            existing_agent.public_key = public_key
            existing_agent.status = AgentStatus.HEALTHY
            existing_agent.last_heartbeat_at = now
            agent = existing_agent
        else:
            # Create new agent
            agent = EndpointAgent(
                id=str(uuid.uuid4()),
                org_id=token_record.org_id,
                project_id=token_record.project_id,
                installation_id=installation_id,
                hostname=hostname,
                platform=platform_name,
                os_version=os_version,
                arch=arch,
                ip_addresses=ip_addresses or [],
                mac_addresses=mac_addresses or [],
                agent_version=agent_version,
                capabilities=capabilities or [],
                public_key=public_key,
                status=AgentStatus.HEALTHY,
                last_heartbeat_at=now,
            )
            db.add(agent)

        # 3. Create or associate Asset
        if token_record.project_id:
            asset_stmt = select(Asset).where(
                and_(
                    Asset.project_id == token_record.project_id,
                    Asset.value == hostname,
                )
            )
            existing_asset = (await db.execute(asset_stmt)).scalars().first()
            if not existing_asset:
                new_asset = Asset(
                    id=str(uuid.uuid4()),
                    project_id=token_record.project_id,
                    type=AssetType.HOST,
                    value=hostname,
                    environment="internal",
                    criticality="MEDIUM",
                    agent_id=agent.id,
                    hostname=hostname,
                    os_info=f"{platform_name} {os_version} ({arch})",
                )
                db.add(new_asset)
            else:
                existing_asset.agent_id = agent.id
                existing_asset.hostname = hostname
                existing_asset.os_info = f"{platform_name} {os_version} ({arch})"

        # 4. Increment token use
        token_record.used_count += 1
        if token_record.used_count >= token_record.max_uses:
            token_record.is_active = False

        await db.commit()
        await db.refresh(agent)

        logger.info(
            "Agent enrolled successfully",
            agent_id=agent.id,
            hostname=hostname,
            org_id=token_record.org_id,
        )
        return agent

    async def process_heartbeat(
        self,
        db: AsyncSession,
        agent_id: str,
        telemetry: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record heartbeat and evaluate kill-switch/revocation status."""
        stmt = select(EndpointAgent).where(EndpointAgent.id == agent_id)
        result = await db.execute(stmt)
        agent = result.scalars().first()

        if not agent:
            raise ValueError("Agent not found")

        if agent.status == AgentStatus.REVOKED:
            return {"status": "REVOKED", "action": "TERMINATE"}

        # Check hierarchical kill switch
        killed = is_action_killed_sync(
            project_id=agent.project_id,
            org_id=agent.org_id,
            agent_type="ENDPOINT_AGENT",
        )
        if killed:
            agent.status = AgentStatus.ISOLATED
            await db.commit()
            return {"status": "KILLED", "action": "HALT"}

        agent.last_heartbeat_at = datetime.now(timezone.utc)
        if telemetry:
            agent.telemetry_data = telemetry
        agent.status = AgentStatus.HEALTHY

        await db.commit()
        return {"status": "HEALTHY", "action": "POLL_TASKS"}

    async def create_task(
        self,
        db: AsyncSession,
        agent_id: str,
        check_id: str,
        parameters: Optional[Dict[str, Any]] = None,
        campaign_id: Optional[str] = None,
        created_by_id: Optional[str] = None,
    ) -> AgentTask:
        """Create a new validated endpoint assessment task."""
        # 1. Verify agent existence
        agent_stmt = select(EndpointAgent).where(EndpointAgent.id == agent_id)
        agent = (await db.execute(agent_stmt)).scalars().first()
        if not agent:
            raise ValueError("Agent not found")

        # 2. Check check registry
        check_def = endpoint_check_registry.get_check(check_id)
        if not check_def:
            raise ValueError(f"Unknown endpoint check: {check_id}")

        # 3. Scope validation
        if agent.project_id:
            # Check target hostname against scope
            scope_validator = ScopeValidator(db)
            is_in_scope = await scope_validator.is_in_scope(agent.hostname, agent.project_id)
            if not is_in_scope:
                raise ValueError(f"Agent hostname {agent.hostname} is outside authorized scope")

        # 4. Policy evaluation
        policy_eval = policy_engine.evaluate(
            ActionContext(
                action_type=check_id,
                target=agent.hostname,
                project_id=agent.project_id or "default",
                environment="internal",
                user_role="ADMIN",
                parameters=parameters or {},
            )
        )
        if not policy_eval.allowed:
            raise ValueError(f"Task blocked by policy engine: {policy_eval.reason}")

        # 5. Create AgentTask record
        task_id = str(uuid.uuid4())
        task_payload = {
            "task_id": task_id,
            "check_id": check_id,
            "agent_id": agent_id,
            "parameters": parameters or {},
            "target": agent.hostname,
            "timeout_seconds": 60,
        }
        # SHA-256 signature for payload verification
        task_signature = hashlib.sha256(json.dumps(task_payload, sort_keys=True).encode()).hexdigest()

        task = AgentTask(
            id=task_id,
            agent_id=agent_id,
            campaign_id=campaign_id,
            check_id=check_id,
            parameters=parameters or {},
            status=TaskStatus.PENDING,
            signature=task_signature,
            timeout_seconds=60,
        )
        db.add(task)
        await db.commit()
        await db.refresh(task)

        logger.info("Agent task created", task_id=task.id, check_id=check_id, agent_id=agent_id)
        return task

    async def fetch_pending_tasks(
        self,
        db: AsyncSession,
        agent_id: str,
    ) -> List[Dict[str, Any]]:
        """Fetch pending tasks for the polling agent."""
        agent_stmt = select(EndpointAgent).where(EndpointAgent.id == agent_id)
        agent = (await db.execute(agent_stmt)).scalars().first()
        if not agent or agent.status == AgentStatus.REVOKED:
            return []

        # Check kill switch
        if is_action_killed_sync(project_id=agent.project_id, org_id=agent.org_id, agent_type="ENDPOINT_AGENT"):
            return []

        stmt = select(AgentTask).where(
            and_(
                AgentTask.agent_id == agent_id,
                AgentTask.status == TaskStatus.PENDING,
            )
        ).order_by(AgentTask.created_at.asc())

        tasks = (await db.execute(stmt)).scalars().all()
        result_tasks = []

        now = datetime.now(timezone.utc)
        for t in tasks:
            t.status = TaskStatus.DISPATCHED
            t.dispatched_at = now
            result_tasks.append({
                "task_id": t.id,
                "check_id": t.check_id,
                "parameters": t.parameters,
                "signature": t.signature,
                "timeout_seconds": t.timeout_seconds,
            })

        await db.commit()
        return result_tasks

    async def submit_task_result(
        self,
        db: AsyncSession,
        agent_id: str,
        task_id: str,
        status: str,
        execution_time_ms: int = 0,
        findings_data: Optional[List[Dict[str, Any]]] = None,
        evidence_data: Optional[Dict[str, Any]] = None,
        raw_output: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> AgentTaskResult:
        """Process and record an endpoint task execution result."""
        # 1. Fetch task and agent
        task_stmt = select(AgentTask).where(AgentTask.id == task_id)
        task = (await db.execute(task_stmt)).scalars().first()
        if not task:
            raise ValueError("Task not found")

        agent_stmt = select(EndpointAgent).where(EndpointAgent.id == agent_id)
        agent = (await db.execute(agent_stmt)).scalars().first()
        if not agent:
            raise ValueError("Agent not found")

        now = datetime.now(timezone.utc)
        result_status = TaskResultStatus.SUCCESS if status.upper() in ["SUCCESS", "COMPLETED"] else TaskResultStatus.FAILED

        # 2. Create task result record
        task_result = AgentTaskResult(
            id=str(uuid.uuid4()),
            task_id=task_id,
            agent_id=agent_id,
            status=result_status,
            execution_time_ms=execution_time_ms,
            findings_data=findings_data or [],
            evidence_data=evidence_data or {},
            raw_output=raw_output,
            error_message=error_message,
        )
        db.add(task_result)

        # 3. Update task status
        task.status = TaskStatus.COMPLETED if result_status == TaskResultStatus.SUCCESS else TaskStatus.FAILED
        task.completed_at = now

        # 4. Ingest findings and evidence
        if agent.project_id and findings_data:
            for f in findings_data:
                # Severity mapping
                sev = Severity.INFO
                f_sev = f.get("severity", "INFO").upper()
                if f_sev in Severity.__members__:
                    sev = Severity[f_sev]

                finding = Finding(
                    id=str(uuid.uuid4()),
                    project_id=agent.project_id,
                    title=f.get("title", f"Endpoint Security Issue: {task.check_id}"),
                    description=f.get("description", "Discovered by Endpoint Security Agent"),
                    severity=sev,
                    affected_asset=agent.hostname,
                    cvss_score=float(f.get("cvss_score", 4.0)),
                    recommendation=f.get("remediation", "Apply security baseline remediation"),
                    agent_id=agent.id,
                )
                db.add(finding)

        # 5. Record Evidence via EvidenceService
        if agent.project_id and evidence_data:
            ev_svc = EvidenceService(db)
            await ev_svc.record_evidence(
                finding_id=finding.id if 'finding' in locals() else task.id,
                agent_id=agent.id,
                url=agent.hostname,
                agent_type="ENDPOINT_AGENT",
                additional_data=evidence_data,
                test_executed=task.check_id,
            )

        await db.commit()
        await db.refresh(task_result)

        logger.info(
            "Task result recorded",
            task_id=task_id,
            agent_id=agent_id,
            status=str(result_status),
            findings_count=len(findings_data or []),
        )
        return task_result

    async def revoke_agent(
        self,
        db: AsyncSession,
        agent_id: str,
        revoked_by_id: str,
        reason: str = "Administrative revocation",
    ) -> EndpointAgent:
        """Revoke an agent to immediately prevent further execution."""
        stmt = select(EndpointAgent).where(EndpointAgent.id == agent_id)
        agent = (await db.execute(stmt)).scalars().first()
        if not agent:
            raise ValueError("Agent not found")

        agent.status = AgentStatus.REVOKED
        
        audit = AuditLog(
            id=str(uuid.uuid4()),
            user_id=revoked_by_id,
            action="AGENT_REVOKE",
            resource="EndpointAgent",
            resource_id=agent_id,
            details=f"Reason: {reason}",
        )
        db.add(audit)
        await db.commit()
        await db.refresh(agent)

        logger.warning("Endpoint agent revoked", agent_id=agent_id, by=revoked_by_id, reason=reason)
        return agent


agent_service = AgentService()
