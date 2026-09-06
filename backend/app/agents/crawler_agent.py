"""
Web Crawler Agent — Playwright-based browser crawler

Capabilities:
- Navigate pages using real Chromium browser
- Follow links within scope
- Identify forms, inputs, cookies, localStorage, sessionStorage
- Intercept XHR/fetch API calls
- Capture screenshots
- Detect JavaScript endpoints
"""
import asyncio
import json
import re
import time
from urllib.parse import urljoin, urlparse
import structlog

from app.core.scope_validator import ScopeValidator, ScopeViolationError
from app.services.kill_switch import is_scan_killed_sync

logger = structlog.get_logger(__name__)

MAX_PAGES_PER_TARGET = 50
MAX_DEPTH = 3


def run_crawler(scan_id: str, project_id: str, scope_data: dict) -> int:
    """Main crawler entry point. Returns number of endpoints discovered."""
    return asyncio.run(_run_crawler_async(scan_id, project_id, scope_data))


async def _run_crawler_async(scan_id: str, project_id: str, scope_data: dict) -> int:
    from playwright.async_api import async_playwright
    from app.core.database import AsyncSessionLocal
    from app.models import Asset, Endpoint, AgentLog, AgentType, AssetType

    validator = ScopeValidator(
        allowed_domains=scope_data.get("domains", []),
        allowed_ips=scope_data.get("ips", []),
        allowed_cidrs=scope_data.get("cidrs", []),
        excluded_domains=scope_data.get("excluded_domains", []),
        excluded_ips=scope_data.get("excluded_ips", []),
        allow_private_ips=scope_data.get("allow_private_ips", False),
    )

    # Build start URLs from scope
    start_urls = list(scope_data.get("urls", []))
    for domain in scope_data.get("domains", []):
        if not domain.startswith("*"):
            start_urls.append(f"https://{domain}")
            start_urls.append(f"http://{domain}")

    endpoints_total = 0
    visited_urls: set[str] = set()
    api_calls_seen: set[str] = set()

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-extensions",
                "--disable-gpu",
            ],
        )

        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Security Assessment Tool)",
            ignore_https_errors=True,
            java_script_enabled=True,
        )

        for start_url in start_urls[:5]:  # Limit start URLs
            if is_scan_killed_sync(scan_id):
                break

            try:
                validator.validate(start_url)
            except ScopeViolationError as e:
                logger.warning("Start URL out of scope", url=start_url, reason=str(e))
                continue

            # BFS crawl from this start URL
            queue = [(start_url, 0)]

            while queue and len(visited_urls) < MAX_PAGES_PER_TARGET:
                if is_scan_killed_sync(scan_id):
                    break

                url, depth = queue.pop(0)
                if url in visited_urls or depth > MAX_DEPTH:
                    continue

                visited_urls.add(url)

                try:
                    page_data = await _crawl_page(context, url, validator)
                    if not page_data:
                        continue

                    # Save endpoints to DB
                    async with AsyncSessionLocal() as db:
                        # Find parent asset
                        parsed = urlparse(url)
                        asset_result = await db.execute(
                            __import__("sqlalchemy", fromlist=["select"]).select(Asset).where(
                                Asset.project_id == project_id,
                                Asset.value == parsed.hostname,
                            ).limit(1)
                        )
                        asset = asset_result.scalar_one_or_none()

                        if not asset:
                            # Create asset for this domain if not exists
                            asset = Asset(
                                project_id=project_id,
                                asset_type=AssetType.URL,
                                value=parsed.hostname or url,
                                protocol=parsed.scheme,
                                is_internet_facing=True,
                            )
                            db.add(asset)
                            await db.flush()

                        # Save page as endpoint
                        endpoint = Endpoint(
                            asset_id=asset.id,
                            project_id=project_id,
                            url=url,
                            method="GET",
                            path=parsed.path or "/",
                            parameters=[{"name": k, "value": v, "location": "query"}
                                        for k, v in _parse_query(parsed.query)],
                            is_api=False,
                            source="crawler",
                        )
                        db.add(endpoint)
                        endpoints_total += 1

                        # Save API calls as endpoints
                        for api_call in page_data.get("api_calls", []):
                            api_url = api_call.get("url", "")
                            if api_url in api_calls_seen:
                                continue
                            api_calls_seen.add(api_url)

                            try:
                                validator.validate(api_url)
                                api_parsed = urlparse(api_url)
                                api_endpoint = Endpoint(
                                    asset_id=asset.id,
                                    project_id=project_id,
                                    url=api_url,
                                    method=api_call.get("method", "GET"),
                                    path=api_parsed.path or "/",
                                    parameters=[],
                                    is_api=True,
                                    source="crawler_intercept",
                                )
                                db.add(api_endpoint)
                                endpoints_total += 1
                            except ScopeViolationError:
                                pass

                        await db.commit()

                        log_entry = AgentLog(
                            scan_id=scan_id,
                            agent_type=AgentType.WEB_CRAWLER,
                            level="INFO",
                            message=f"🕷️  Crawled: {url} | Forms: {len(page_data.get('forms', []))} | APIs: {len(page_data.get('api_calls', []))}",
                            target=url,
                        )
                        db.add(log_entry)
                        await db.commit()

                    # Queue discovered links
                    for link in page_data.get("links", []):
                        abs_link = urljoin(url, link)
                        if abs_link not in visited_urls:
                            try:
                                validator.validate(abs_link)
                                queue.append((abs_link, depth + 1))
                            except ScopeViolationError:
                                pass

                    # Rate limiting
                    await asyncio.sleep(60 / max(scope_data.get("max_requests_per_minute", 30), 1))

                except Exception as e:
                    logger.warning("Error crawling page", url=url, error=str(e))

        await browser.close()

    return endpoints_total


async def _crawl_page(context, url: str, validator: ScopeValidator) -> dict | None:
    """Crawl a single page. Returns page data dict."""
    page = await context.new_page()
    api_calls = []
    page_errors = []

    # Intercept network requests
    def on_request(request):
        req_url = request.url
        if any(ct in request.headers.get("accept", "").lower() for ct in ["json", "xml"]) or \
           any(req_url.endswith(ext) for ext in [".json", "/api/", "/graphql"]) or \
           req_url.endswith("graphql"):
            try:
                validator.validate(req_url, resolve_dns=False)
                api_calls.append({
                    "url": req_url,
                    "method": request.method,
                    "headers": dict(request.headers),
                })
            except ScopeViolationError:
                pass

    page.on("request", on_request)

    try:
        response = await page.goto(url, timeout=15000, wait_until="networkidle")
        if not response:
            return None

        # Extract page data
        page_data = await page.evaluate("""
            () => {
                // Links
                const links = Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.getAttribute('href'))
                    .filter(h => h && !h.startsWith('mailto:') && !h.startsWith('tel:'))
                    .slice(0, 100);
                
                // Forms
                const forms = Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action,
                    method: f.method || 'GET',
                    inputs: Array.from(f.querySelectorAll('input, select, textarea')).map(i => ({
                        name: i.name,
                        type: i.type || 'text',
                        id: i.id,
                    }))
                }));
                
                // Storage
                const localStorage_keys = Object.keys(localStorage);
                const sessionStorage_keys = Object.keys(sessionStorage);
                
                // Cookies
                const cookies = document.cookie.split(';').map(c => c.trim().split('=')[0]);
                
                // JavaScript endpoints in source
                const scripts = Array.from(document.querySelectorAll('script'))
                    .map(s => s.src || '')
                    .filter(s => s);
                
                return { links, forms, localStorage_keys, sessionStorage_keys, cookies, scripts };
            }
        """)

        page_data["api_calls"] = api_calls
        page_data["url"] = url
        page_data["status"] = response.status

        return page_data

    except Exception as e:
        logger.warning("Page crawl failed", url=url, error=str(e))
        return None
    finally:
        try:
            await page.close()
        except Exception:
            pass


def _parse_query(query_str: str) -> list[tuple[str, str]]:
    if not query_str:
        return []
    from urllib.parse import parse_qsl
    return parse_qsl(query_str)
