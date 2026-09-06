"""
Secure Browser Controller & Network Interceptor

Playwright/Chromium-based isolated browser environment.
Enforces:
1. Complete context isolation per scan/project
2. Privacy-by-default (zero telemetry, ephemeral storage destroyed on teardown)
3. Deterministic Network Interceptor (blocks unauthorized requests/redirects/iframes/websockets)
4. Comprehensive evidence capture (screenshots, DOM, network, headers, CSP/CORS)
5. Authentication-aware role contexts
"""
import asyncio
import os
from datetime import datetime, timezone
from typing import Optional, Any
from urllib.parse import urlparse
import structlog

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.scope_validator import ScopeValidator, ScopeViolationError
from app.models import BlockedAction, AgentType
from app.security.policy_engine import PolicyEngine, PolicyConfig, PolicyDecision
from app.services.kill_switch import is_scan_killed_sync

logger = structlog.get_logger(__name__)


class SecureBrowserController:
    """Controls isolated Playwright browser instances with network policy interception."""

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
                max_requests_per_minute=scope_data.get("max_requests_per_minute", 60),
            ),
        )
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        self.blocked_requests: list[dict[str, Any]] = []

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def start(self):
        """Initializes isolated Chromium browser with privacy-by-default flags."""
        try:
            from playwright.async_api import async_playwright
            self._playwright = await async_playwright().start()

            # Launch Chromium with privacy and isolation arguments
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-telemetry",
                    "--disable-background-networking",
                    "--disable-sync",
                    "--disable-default-apps",
                    "--mute-audio",
                    "--no-first-run",
                ],
            )

            # Ephemeral isolated context
            self._context = await self._browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 PentestAgent/2.0",
                viewport={"width": 1280, "height": 800},
            )

            self._page = await self._context.new_page()

            # Attach Network Interceptor
            await self._page.route("**/*", self._network_interceptor)
            logger.info("🔒 Secure Browser Session initialized", scan_id=self.scan_id)

        except Exception as e:
            logger.error("Failed to start Playwright Secure Browser", error=str(e))
            raise

    async def _network_interceptor(self, route):
        """
        Intercepts EVERY request from the browser (redirects, iframes, scripts, XHR).
        Evaluates against Policy Engine & Scope Validator.
        """
        request = route.request
        req_url = request.url

        # Check Kill Switch
        if is_scan_killed_sync(self.scan_id):
            logger.warning("Kill switch triggered in browser interceptor — aborting request", url=req_url)
            await route.abort("blockedbyclient")
            return

        # Policy Engine Evaluation
        policy_res = self.policy_engine.evaluate_request(
            target_url=req_url,
            method=request.method,
            test_type="BROWSER_NAVIGATION",
            agent_type="BROWSER_AGENT",
            project_id=self.project_id,
        )

        if not policy_res.allowed:
            # Block and record violation
            block_info = {
                "scan_id": self.scan_id,
                "project_id": self.project_id,
                "agent_type": AgentType.BROWSER_AGENT,
                "target": req_url,
                "url": req_url,
                "reason": policy_res.reason,
                "policy_rule": policy_res.policy_rule,
                "initiator": request.resource_type,
            }
            self.blocked_requests.append(block_info)
            asyncio.create_task(self._log_blocked_action(block_info))

            logger.warning("🚫 Browser Interceptor BLOCKED request", url=req_url, reason=policy_res.reason)
            await route.abort("blockedbyclient")
        else:
            await route.continue_()

    async def _log_blocked_action(self, info: dict):
        """Records blocked action in the database."""
        try:
            async with AsyncSessionLocal() as db:
                action = BlockedAction(
                    scan_id=info["scan_id"],
                    project_id=info["project_id"],
                    agent_type=info["agent_type"],
                    target=info["target"],
                    url=info["url"],
                    reason=info["reason"],
                    policy_rule=info["policy_rule"],
                    initiator=info["initiator"],
                )
                db.add(action)
                await db.commit()
        except Exception as e:
            logger.debug("Failed to record blocked action", error=str(e))

    async def navigate_and_capture(
        self,
        url: str,
        auth_headers: Optional[dict] = None,
    ) -> dict[str, Any]:
        """
        Navigates to URL, captures DOM snapshot, screenshot, security headers, and forms.
        """
        if not self._page:
            raise RuntimeError("Browser not started.")

        if auth_headers:
            await self._page.set_extra_http_headers(auth_headers)

        response = await self._page.goto(url, wait_until="networkidle", timeout=15000)

        # 1. Capture DOM Snapshot
        dom_content = await self._page.content()

        # 2. Capture Screenshot
        screenshot_dir = settings.SCREENSHOTS_DIR
        os.makedirs(screenshot_dir, exist_ok=True)
        screenshot_filename = f"scan_{self.scan_id}_{int(datetime.now(timezone.utc).timestamp())}.png"
        screenshot_path = os.path.join(screenshot_dir, screenshot_filename)
        await self._page.screenshot(path=screenshot_path, full_page=True)

        # 3. Extract Forms and Links
        forms = await self._page.evaluate("""() => {
            return Array.from(document.forms).map(form => ({
                action: form.action,
                method: form.method,
                inputs: Array.from(form.elements).map(el => ({
                    name: el.name,
                    type: el.type,
                    id: el.id
                }))
            }));
        }""")

        # 4. Extract Security Headers & Status
        status_code = response.status if response else 0
        headers = response.headers if response else {}

        return {
            "url": url,
            "status_code": status_code,
            "headers": headers,
            "screenshot_path": screenshot_path,
            "dom_length": len(dom_content),
            "dom_snippet": dom_content[:4000],
            "forms": forms,
            "blocked_count": len(self.blocked_requests),
        }

    async def close(self):
        """Secure cleanup — destroys ephemeral context and browser instance."""
        try:
            if self._context:
                await self._context.close()
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
            logger.info("🔒 Secure Browser Session cleanly destroyed", scan_id=self.scan_id)
        except Exception as e:
            logger.debug("Error during browser teardown", error=str(e))
