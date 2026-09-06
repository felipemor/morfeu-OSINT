"""
Secure Browser Agent — Crawls pages, extracts forms/APIs, and collects visual evidence safely
"""
import asyncio
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from app.agents.secure_browser import SecureBrowserController
from app.core.database import AsyncSessionLocal
from app.models import Asset, Endpoint, Screenshot, Finding, Severity

logger = structlog.get_logger(__name__)


class SecureBrowserAgent:
    """Uses SecureBrowserController to navigate authorized surfaces and discover web components."""

    def __init__(self, scan_id: str, project_id: str, scope_data: dict):
        self.scan_id = scan_id
        self.project_id = project_id
        self.scope_data = scope_data

    async def run(self) -> int:
        """Executes browser-based crawl on discovered web assets."""
        logger.info("🌐 Secure Browser Agent starting crawl", scan_id=self.scan_id, project_id=self.project_id)
        pages_processed = 0

        async with AsyncSessionLocal() as db:
            # 1. Fetch assets for target project
            asset_res = await db.execute(
                select(Asset).where(
                    Asset.project_id == self.project_id,
                )
            )
            assets = asset_res.scalars().all()

        urls_to_visit = []
        for asset in assets:
            if asset.value.startswith("http://") or asset.value.startswith("https://"):
                urls_to_visit.append((asset.id, asset.value))
            elif asset.port in [80, 8080, 3000, 5000]:
                urls_to_visit.append((asset.id, f"http://{asset.value}:{asset.port}"))
            elif asset.port in [443, 8443]:
                urls_to_visit.append((asset.id, f"https://{asset.value}:{asset.port}"))
            else:
                urls_to_visit.append((asset.id, f"http://{asset.value}"))

        if not urls_to_visit:
            # Default to domains in scope
            for d in self.scope_data.get("domains", []):
                urls_to_visit.append((None, f"http://{d}"))

        # Launch Browser Controller
        try:
            controller = SecureBrowserController(self.scan_id, self.project_id, self.scope_data)
            async with controller:
                for asset_id, url in urls_to_visit[:10]:  # Cap visits for speed
                    try:
                        logger.info("Browser navigating to target", url=url)
                        capture_data = await controller.navigate_and_capture(url)

                        async with AsyncSessionLocal() as db:
                            # Save screenshot record
                            if capture_data.get("screenshot_path"):
                                ss = Screenshot(
                                    project_id=self.project_id,
                                    asset_id=asset_id,
                                    file_path=capture_data["screenshot_path"],
                                    file_name=capture_data["screenshot_path"].split("\\")[-1].split("/")[-1],
                                    url=url,
                                    description=f"Captured page view of {url} (Status: {capture_data['status_code']})",
                                )
                                db.add(ss)

                            # Register discovered form endpoints
                            for form in capture_data.get("forms", []):
                                action_url = form.get("action") or url
                                method = form.get("method", "POST").upper()
                                if asset_id:
                                    ep = Endpoint(
                                        asset_id=asset_id,
                                        project_id=self.project_id,
                                        url=action_url,
                                        method=method,
                                        path=action_url.split("://")[-1].partition("/")[2] or "/",
                                        parameters=form.get("inputs", []),
                                        source="BROWSER_AGENT",
                                    )
                                    db.add(ep)

                            await db.commit()
                        pages_processed += 1

                    except Exception as e:
                        logger.warning("Browser navigation failed for URL", url=url, error=str(e))

        except Exception as e:
            logger.error("Secure Browser Agent encountered an error", error=str(e))

        logger.info("✅ Secure Browser Agent finished", pages_processed=pages_processed)
        return pages_processed


def run_browser_crawl(scan_id: str, project_id: str, scope_data: dict) -> int:
    """Celery synchronous wrapper."""
    agent = SecureBrowserAgent(scan_id, project_id, scope_data)
    return asyncio.run(agent.run())
