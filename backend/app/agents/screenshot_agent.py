"""
Screenshot Agent — Playwright-based screenshot capture

Captures browser screenshots with metadata overlay for evidence.
"""
import asyncio
import hashlib
import os
from datetime import datetime, timezone

import structlog

from app.core.config import settings

logger = structlog.get_logger(__name__)


async def capture_screenshot(
    url: str,
    project_id: str,
    finding_title: str = "",
    highlight_selector: str = None,
) -> dict:
    """
    Capture a screenshot of a URL with optional element highlighting.
    Returns dict with file_path, file_name, file_hash.
    """
    from playwright.async_api import async_playwright

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in url[:60])
    file_name = f"screenshot_{safe_name}_{timestamp}.png"

    project_dir = os.path.join(settings.SCREENSHOTS_DIR, project_id)
    os.makedirs(project_dir, exist_ok=True)
    file_path = os.path.join(project_dir, file_name)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Security Assessment Tool)",
            ignore_https_errors=True,
        )
        page = await context.new_page()

        try:
            await page.goto(url, timeout=15000, wait_until="networkidle")
            await asyncio.sleep(1)  # Wait for dynamic content

            # Highlight element if selector provided
            if highlight_selector:
                try:
                    await page.evaluate(f"""
                        (() => {{
                            const el = document.querySelector('{highlight_selector}');
                            if (el) {{
                                el.style.outline = '3px solid red';
                                el.style.outlineOffset = '2px';
                                el.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                            }}
                        }})()
                    """)
                    await asyncio.sleep(0.5)
                except Exception:
                    pass

            # Add metadata overlay
            await page.evaluate(f"""
                (() => {{
                    const overlay = document.createElement('div');
                    overlay.style.cssText = 'position:fixed;top:0;left:0;right:0;background:rgba(0,0,0,0.85);color:white;padding:8px 16px;font-family:monospace;font-size:12px;z-index:99999;display:flex;justify-content:space-between;';
                    overlay.innerHTML = `
                        <span>🔒 AI Autonomous Pentest | {finding_title[:60]}</span>
                        <span>{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}</span>
                    `;
                    document.body.prepend(overlay);
                }})()
            """)

            await page.screenshot(path=file_path, full_page=False)

            # Calculate hash
            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            logger.info("Screenshot captured", url=url, path=file_path)

            return {
                "file_path": file_path,
                "file_name": file_name,
                "file_hash": file_hash,
                "url": url,
            }

        except Exception as e:
            logger.error("Screenshot capture failed", url=url, error=str(e))
            return {"file_path": None, "file_name": None, "file_hash": None, "url": url, "error": str(e)}
        finally:
            await browser.close()


def capture_screenshot_sync(url: str, project_id: str, finding_title: str = "") -> dict:
    """Synchronous wrapper for use in Celery tasks."""
    return asyncio.run(capture_screenshot(url, project_id, finding_title))
