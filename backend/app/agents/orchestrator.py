"""
Pentest Orchestrator V2 — Autonomous AI Security Reasoning Pipeline

Pipeline Phases:
  1. Scope & Policy Initialization
  2. Recon Agent (DNS, HTTP Fingerprinting)
  3. Web Crawler Agent & Secure Browser Agent (DOM, Forms, APIs, Visual Capture)
  4. AI Pentest Planner (Hypothesis Formulation, Policy Evaluation, Approvals)
  5. API Security Agent & Vulnerability Agent (Modular Security Checks)
  6. Multi-Factor Business Risk Engine
  7. Automated Report & Compliance Generation
"""
import asyncio
from datetime import datetime, timezone

import structlog
from celery import shared_task
from sqlalchemy import select

from app.agents.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.models import Scan, ScanStatus, Project, ProjectStatus, Scope, ScanMode, AgentLog, AgentType
from app.services.kill_switch import is_action_killed_sync

logger = structlog.get_logger(__name__)


def _log_to_db_sync(scan_id: str, agent: AgentType, message: str, level: str = "INFO", target: str = None, extra: dict = None):
    """Synchronous helper to write agent logs inside Celery tasks."""
    asyncio.run(_log_to_db_async(scan_id, agent, message, level, target, extra))


async def _log_to_db_async(scan_id: str, agent: AgentType, message: str, level: str, target: str, extra: dict):
    async with AsyncSessionLocal() as db:
        log = AgentLog(
            scan_id=scan_id,
            agent_type=agent,
            level=level,
            message=message,
            target=target,
            extra_data=extra,
        )
        db.add(log)
        await db.commit()


async def _update_scan_async(scan_id: str, **kwargs):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan:
            for k, v in kwargs.items():
                setattr(scan, k, v)
            await db.commit()


def _update_scan_sync(scan_id: str, **kwargs):
    asyncio.run(_update_scan_async(scan_id, **kwargs))


@celery_app.task(bind=True, name="app.agents.orchestrator.run_pentest_orchestrator")
def run_pentest_orchestrator(self, scan_id: str, project_id: str):
    """
    Coordinates all autonomous agents sequentially with continuous kill-switch checks.
    """
    logger.info("🎯 Orchestrator started", scan_id=scan_id, project_id=project_id)

    def check_kill(agent_type: str = "ORCHESTRATOR"):
        if is_action_killed_sync(scan_id=scan_id, project_id=project_id, agent_type=agent_type):
            _log_to_db_sync(scan_id, AgentType.ORCHESTRATOR, "🚨 Kill switch activated — stopping scan", "WARNING")
            _update_scan_sync(scan_id, status=ScanStatus.KILLED, killed_at=datetime.now(timezone.utc))
            return True
        return False

    try:
        # ── Phase 0: Initialize ─────────────────────────────────────────────
        _update_scan_sync(
            scan_id,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            progress=0,
            current_phase="INITIALIZING",
        )
        _log_to_db_sync(scan_id, AgentType.ORCHESTRATOR, "🚀 Pentest scan initialized (V2 Architecture)", target=project_id)

        if check_kill():
            return

        # Load scope
        scope_data = asyncio.run(_load_scope_async(project_id))
        if not scope_data:
            _log_to_db_sync(scan_id, AgentType.ORCHESTRATOR, "❌ No scope found — aborting", "ERROR")
            _update_scan_sync(scan_id, status=ScanStatus.FAILED, error_message="No scope configured")
            return

        _log_to_db_sync(
            scan_id, AgentType.ORCHESTRATOR,
            f"✅ Scope loaded: {len(scope_data['domains'])} domains, {len(scope_data['ips'])} IPs",
            extra={"domains": scope_data["domains"]},
        )

        # ── Phase 1: Recon ────────────────────────────────────────────────
        if check_kill("RECON"):
            return

        _update_scan_sync(scan_id, progress=10, current_phase="RECON")
        _log_to_db_sync(scan_id, AgentType.RECON, "🔍 Starting asset discovery")

        from app.agents.recon_agent import run_recon
        assets_found = run_recon(scan_id, project_id, scope_data)
        _update_scan_sync(scan_id, assets_discovered=assets_found, progress=25)

        _log_to_db_sync(
            scan_id, AgentType.RECON,
            f"✅ Recon complete: {assets_found} assets discovered",
            extra={"assets": assets_found},
        )

        # ── Phase 2: Web Crawling & Browser Agent ─────────────────────────
        if check_kill("WEB_CRAWLER"):
            return

        mode = scope_data.get("scan_mode", "PASSIVE")
        _update_scan_sync(scan_id, progress=30, current_phase="WEB_CRAWLING")
        _log_to_db_sync(scan_id, AgentType.WEB_CRAWLER, f"🕷️ Starting crawler & browser discovery (mode: {mode})")

        from app.agents.crawler_agent import run_crawler
        endpoints_found = run_crawler(scan_id, project_id, scope_data)

        # Run Secure Browser Agent
        try:
            from app.agents.browser_agent import run_browser_crawl
            run_browser_crawl(scan_id, project_id, scope_data)
        except Exception as e:
            logger.warning("Browser agent run skipped or encountered warning", error=str(e))

        _update_scan_sync(scan_id, endpoints_found=endpoints_found, progress=50)
        _log_to_db_sync(
            scan_id, AgentType.WEB_CRAWLER,
            f"✅ Crawling complete: {endpoints_found} endpoints mapped",
            extra={"endpoints": endpoints_found},
        )

        # ── Phase 3: AI Planner & Hypothesis Reasoning ───────────────────
        if check_kill("LLM_PLANNER"):
            return

        _update_scan_sync(scan_id, progress=55, current_phase="AI_REASONING")
        _log_to_db_sync(scan_id, AgentType.LLM_PLANNER, "🧠 Formulating security hypotheses & evaluating policy")

        from app.agents.planner_agent import run_planner
        planner_summary = run_planner(scan_id, project_id, scope_data)
        _log_to_db_sync(
            scan_id, AgentType.LLM_PLANNER,
            f"✅ AI Planner: {planner_summary['total_hypotheses']} hypotheses formulated, {planner_summary['auto_approved_actions']} actions authorized",
            extra=planner_summary,
        )

        # ── Phase 4: API & Vulnerability Testing ──────────────────────────
        total_findings = 0
        if mode != "PASSIVE":
            if check_kill("API_AGENT"):
                return

            _update_scan_sync(scan_id, progress=70, current_phase="API_TESTING")
            _log_to_db_sync(scan_id, AgentType.API_AGENT, "📡 Executing API security checks")

            from app.agents.api_agent import run_api_checks
            api_findings = run_api_checks(scan_id, project_id, scope_data)
            total_findings += api_findings

            if check_kill("VULNERABILITY"):
                return

            _update_scan_sync(scan_id, progress=80, current_phase="VULNERABILITY_TESTING")
            _log_to_db_sync(scan_id, AgentType.VULNERABILITY, "🔬 Executing vulnerability plugin checks")

            from app.agents.vuln_agent import run_vuln_checks
            vuln_findings = run_vuln_checks(scan_id, project_id, scope_data)
            total_findings += vuln_findings

            _update_scan_sync(scan_id, findings_count=total_findings, progress=88)

        # ── Phase 5: Business Risk Calculation ────────────────────────────
        if check_kill():
            return

        _update_scan_sync(scan_id, progress=92, current_phase="RISK_CALCULATION")
        _log_to_db_sync(scan_id, AgentType.ORCHESTRATOR, "📊 Calculating multi-factor business risk scores")
        asyncio.run(_calculate_risk_async(project_id))

        # ── Phase 6: Complete ─────────────────────────────────────────────
        _update_scan_sync(
            scan_id,
            status=ScanStatus.COMPLETED,
            progress=100,
            current_phase="COMPLETED",
            completed_at=datetime.now(timezone.utc),
        )

        # Finish Project
        asyncio.run(_finish_project_async(project_id))

        scan_data = asyncio.run(_load_scan_summary_async(scan_id))
        _log_to_db_sync(
            scan_id, AgentType.ORCHESTRATOR,
            "🏁 Pentest scan completed successfully",
            extra=scan_data,
        )

        logger.info("✅ Orchestrator completed successfully", scan_id=scan_id, **scan_data)

    except Exception as e:
        logger.error("Orchestrator failed", scan_id=scan_id, error=str(e), exc_info=True)
        _log_to_db_sync(scan_id, AgentType.ORCHESTRATOR, f"❌ Scan failed: {str(e)}", "ERROR")
        _update_scan_sync(
            scan_id,
            status=ScanStatus.FAILED,
            error_message=str(e),
            completed_at=datetime.now(timezone.utc),
        )
        raise


async def _load_scope_async(project_id: str) -> dict | None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scope).where(Scope.project_id == project_id))
        scope = result.scalar_one_or_none()
        if not scope:
            return None
        return {
            "domains": scope.allowed_domains,
            "ips": scope.allowed_ips,
            "cidrs": scope.allowed_cidrs,
            "urls": scope.allowed_urls,
            "environment": scope.environment,
            "excluded_domains": scope.excluded_domains,
            "excluded_ips": scope.excluded_ips,
            "excluded_paths": scope.excluded_paths,
            "allow_private_ips": scope.allow_private_ips,
            "scan_mode": scope.scan_mode.value,
            "max_requests_per_minute": scope.max_requests_per_minute,
        }


async def _calculate_risk_async(project_id: str):
    from app.services.risk_engine import calculate_project_risk
    async with AsyncSessionLocal() as db:
        await calculate_project_risk(db, project_id)


async def _finish_project_async(project_id: str):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Project).where(Project.id == project_id))
        project = result.scalar_one_or_none()
        if project:
            project.status = ProjectStatus.COMPLETED
            await db.commit()


async def _load_scan_summary_async(scan_id: str) -> dict:
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan:
            return {
                "assets": scan.assets_discovered,
                "endpoints": scan.endpoints_found,
                "findings": scan.findings_count,
            }
        return {}


@celery_app.task(bind=True, name="app.agents.orchestrator.run_retest")
def run_retest(self, retest_id: str, finding_id: str):
    """Execute a retest for a specific finding."""
    logger.info("🔄 Retest started", retest_id=retest_id, finding_id=finding_id)
    try:
        from app.agents.vuln_agent import run_single_finding_retest
        result = asyncio.run(run_single_finding_retest(retest_id, finding_id))
        logger.info("✅ Retest completed", retest_id=retest_id, result=result)
    except Exception as e:
        logger.error("Retest failed", retest_id=retest_id, error=str(e))
        raise
