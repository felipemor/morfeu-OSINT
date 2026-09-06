"""
AI Pentest Planner Agent — Reasoning & Hypothesis-Driven Test Orchestrator

Adheres strictly to the absolute safety rule:
AI reasoning engine formulates hypotheses and selects tests, but every execution
must be authorized and validated through Policy Engine & Scope Validator.
"""
import asyncio
from typing import Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from app.core.database import AsyncSessionLocal
from app.models import (
    Scan, Project, SecurityHypothesis, HypothesisStatus,
    ApprovalRequest, ApprovalStatus, Severity, AgentType
)
from app.security.policy_engine import PolicyEngine, PolicyConfig, PolicyDecision
from app.services.attack_surface import AttackSurfaceService
from app.services.hypothesis_engine import HypothesisEngine

logger = structlog.get_logger(__name__)


class PentestPlannerAgent:
    """Coordinates the Observe → Hypothesize → Plan → Authorize → Test reasoning loop."""

    def __init__(self, scan_id: str, project_id: str, scope_data: dict):
        self.scan_id = scan_id
        self.project_id = project_id
        self.scope_data = scope_data
        self.policy_engine = PolicyEngine(
            config=PolicyConfig(
                environment=scope_data.get("environment", "development"),
                max_requests_per_minute=scope_data.get("max_requests_per_minute", 30),
            )
        )

    async def run(self) -> dict[str, Any]:
        """
        Executes AI reasoning pass on the current attack surface.
        """
        logger.info("🧠 AI Pentest Planner starting reasoning pass", scan_id=self.scan_id, project_id=self.project_id)

        async with AsyncSessionLocal() as db:
            # 1. Build Attack Surface Graph
            as_service = AttackSurfaceService(db)
            graph = await as_service.get_attack_surface_graph(self.project_id)

            # 2. Formulate Security Hypotheses
            hypothesis_engine = HypothesisEngine(db)
            hypotheses = await hypothesis_engine.generate_hypotheses_for_project(
                project_id=self.project_id,
                scan_id=self.scan_id,
            )

            # 3. Plan & Validate each proposed test action through Policy Engine
            approved_actions = []
            pending_approvals = []
            blocked_actions = []

            for h in hypotheses:
                for action in h.suggested_actions:
                    target_url = action.get("url", h.target)
                    method = action.get("method", "GET")

                    policy_res = self.policy_engine.evaluate_request(
                        target_url=target_url,
                        method=method,
                        test_type=h.test_type,
                        agent_type="AI_PLANNER",
                        project_id=self.project_id,
                    )

                    if policy_res.decision == PolicyDecision.ALLOW:
                        approved_actions.append({
                            "hypothesis_code": h.hypothesis_code,
                            "action": action,
                            "policy_rule": policy_res.policy_rule,
                        })
                    elif policy_res.decision == PolicyDecision.APPROVAL_REQUIRED:
                        # Queue for Human-In-The-Loop approval
                        approval = ApprovalRequest(
                            project_id=self.project_id,
                            scan_id=self.scan_id,
                            requested_by="ai-planner",
                            action_type=h.test_type,
                            target=target_url,
                            reason=f"AI Hypothesis {h.hypothesis_code}: {h.title}. Reasoning: {' '.join(h.reasoning)}",
                            risk_level=h.priority,
                            status=ApprovalStatus.PENDING,
                            payload=action,
                        )
                        db.add(approval)
                        pending_approvals.append(approval)
                    else:
                        blocked_actions.append({
                            "hypothesis_code": h.hypothesis_code,
                            "target": target_url,
                            "reason": policy_res.reason,
                        })

            await db.commit()

            # Update scan hypotheses count
            scan_res = await db.execute(select(Scan).where(Scan.id == self.scan_id))
            scan = scan_res.scalar_one_or_none()
            if scan:
                scan.hypotheses_count = len(hypotheses)
                await db.commit()

            summary = {
                "total_hypotheses": len(hypotheses),
                "auto_approved_actions": len(approved_actions),
                "pending_human_approvals": len(pending_approvals),
                "blocked_actions": len(blocked_actions),
            }

            logger.info("🎯 AI Planner completed reasoning pass", **summary)
            return summary


def run_planner(scan_id: str, project_id: str, scope_data: dict) -> dict[str, Any]:
    """Celery synchronous wrapper."""
    agent = PentestPlannerAgent(scan_id, project_id, scope_data)
    return asyncio.run(agent.run())
