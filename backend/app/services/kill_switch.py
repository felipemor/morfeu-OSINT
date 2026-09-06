"""
Kill Switch Service V2 — Multi-Tier Emergency Stop System

Supports granular hierarchy:
1. Global Kill Switch
2. Organization Kill Switch
3. Project Kill Switch
4. Scan Kill Switch
5. Agent Kill Switch
6. Browser Kill Switch
"""
import redis.asyncio as aioredis
import structlog
from typing import Optional
from app.core.config import settings

logger = structlog.get_logger(__name__)

GLOBAL_KILL_KEY = "global:kill_switch"
ORG_KILL_PREFIX = "org:kill:"
PROJECT_KILL_PREFIX = "project:kill:"
SCAN_KILL_PREFIX = "scan:kill:"
AGENT_KILL_PREFIX = "agent:kill:"
BROWSER_KILL_PREFIX = "browser:kill:"


async def _get_redis():
    return aioredis.from_url(settings.REDIS_URL, decode_responses=True)


# ─── Global Kill Switch ───────────────────────────────────────────────────────

async def activate_kill_switch(activated_by: str = "system"):
    """Activate the global kill switch. All agents check this flag."""
    redis = await _get_redis()
    try:
        await redis.set(GLOBAL_KILL_KEY, activated_by, ex=86400)
        logger.warning("🚨 GLOBAL KILL SWITCH ACTIVATED", by=activated_by)
    finally:
        await redis.aclose()


async def deactivate_kill_switch():
    """Deactivate the global kill switch."""
    redis = await _get_redis()
    try:
        await redis.delete(GLOBAL_KILL_KEY)
        logger.info("✅ Global kill switch deactivated")
    finally:
        await redis.aclose()


async def is_kill_switch_active() -> bool:
    """Check if the global kill switch is active."""
    redis = await _get_redis()
    try:
        result = await redis.get(GLOBAL_KILL_KEY)
        return result is not None
    finally:
        await redis.aclose()


# ─── Granular Kill Switches ───────────────────────────────────────────────────

async def kill_organization(org_id: str, activated_by: str = "system"):
    """Set kill flag for all activities under an organization."""
    redis = await _get_redis()
    try:
        await redis.set(f"{ORG_KILL_PREFIX}{org_id}", activated_by, ex=86400)
        logger.warning("🚨 ORG KILL SWITCH ACTIVATED", org_id=org_id, by=activated_by)
    finally:
        await redis.aclose()


async def kill_project(project_id: str, activated_by: str = "system"):
    """Set kill flag for all activities under a project."""
    redis = await _get_redis()
    try:
        await redis.set(f"{PROJECT_KILL_PREFIX}{project_id}", activated_by, ex=86400)
        logger.warning("🚨 PROJECT KILL SWITCH ACTIVATED", project_id=project_id, by=activated_by)
    finally:
        await redis.aclose()


async def kill_scan(scan_id: str, activated_by: str = "system"):
    """Set kill flag for a specific scan."""
    redis = await _get_redis()
    try:
        await redis.set(f"{SCAN_KILL_PREFIX}{scan_id}", activated_by, ex=86400)
        logger.warning("🚨 SCAN KILL SWITCH ACTIVATED", scan_id=scan_id, by=activated_by)
    finally:
        await redis.aclose()


async def kill_agent(agent_type: str, scan_id: Optional[str] = None):
    """Set kill flag for a specific agent type or agent in a scan."""
    redis = await _get_redis()
    try:
        key = f"{AGENT_KILL_PREFIX}{scan_id}:{agent_type}" if scan_id else f"{AGENT_KILL_PREFIX}{agent_type}"
        await redis.set(key, "1", ex=86400)
        logger.warning("🚨 AGENT KILL SWITCH ACTIVATED", key=key)
    finally:
        await redis.aclose()


async def kill_browser_session(scan_id: str):
    """Set kill flag to immediately terminate browser workers for a scan."""
    redis = await _get_redis()
    try:
        await redis.set(f"{BROWSER_KILL_PREFIX}{scan_id}", "1", ex=3600)
        logger.warning("🚨 BROWSER KILL SWITCH ACTIVATED", scan_id=scan_id)
    finally:
        await redis.aclose()


# ─── Synchronous Check for Celery Workers / Sub-processes ────────────────────

def is_action_killed_sync(
    scan_id: Optional[str] = None,
    project_id: Optional[str] = None,
    org_id: Optional[str] = None,
    agent_type: Optional[str] = None,
) -> bool:
    """
    Synchronous hierarchical kill check for workers.
    Returns True if ANY higher level in the hierarchy is killed.
    """
    import redis as sync_redis

    try:
        r = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
    except Exception as e:
        logger.warning("Redis connection error in kill switch check", error=str(e))
        return False

    try:
        # 1. Global Kill
        if r.get(GLOBAL_KILL_KEY) is not None:
            return True

        # 2. Org Kill
        if org_id and r.get(f"{ORG_KILL_PREFIX}{org_id}") is not None:
            return True

        # 3. Project Kill
        if project_id and r.get(f"{PROJECT_KILL_PREFIX}{project_id}") is not None:
            return True

        # 4. Scan Kill
        if scan_id and r.get(f"{SCAN_KILL_PREFIX}{scan_id}") is not None:
            return True

        # 5. Agent Kill
        if agent_type:
            if r.get(f"{AGENT_KILL_PREFIX}{agent_type}") is not None:
                return True
            if scan_id and r.get(f"{AGENT_KILL_PREFIX}{scan_id}:{agent_type}") is not None:
                return True

        # 6. Browser Kill
        if agent_type == "BROWSER_AGENT" and scan_id:
            if r.get(f"{BROWSER_KILL_PREFIX}{scan_id}") is not None:
                return True

        return False
    finally:
        r.close()


def is_scan_killed_sync(scan_id: str) -> bool:
    """Backward compatibility wrapper."""
    return is_action_killed_sync(scan_id=scan_id)
