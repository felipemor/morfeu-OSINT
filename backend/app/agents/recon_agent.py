"""
Recon Agent — Asset Discovery, DNS Resolution, Technology Fingerprinting

Responsibilities:
- DNS resolution and subdomain enumeration
- HTTP/HTTPS fingerprinting
- Technology detection (server headers, HTML patterns, cookies)
- Port scanning (top web ports only)
- Asset inventory creation
"""
import asyncio
import socket
import time
from typing import Optional
import httpx
import structlog

from app.agents.celery_app import celery_app
from app.core.scope_validator import ScopeValidator, ScopeViolationError
from app.services.kill_switch import is_scan_killed_sync

logger = structlog.get_logger(__name__)

# Technology fingerprints — (pattern, technology_name)
TECH_FINGERPRINTS = [
    # Server headers
    ("server", "nginx", "Nginx"),
    ("server", "apache", "Apache"),
    ("server", "iis", "IIS"),
    ("server", "gunicorn", "Gunicorn"),
    ("server", "caddy", "Caddy"),
    ("server", "cloudflare", "Cloudflare"),
    ("x-powered-by", "php", "PHP"),
    ("x-powered-by", "asp.net", "ASP.NET"),
    ("x-powered-by", "express", "Express.js"),
    # Response body patterns
    ("body", "react", "React"),
    ("body", "angular", "Angular"),
    ("body", "vue.js", "Vue.js"),
    ("body", "next.js", "Next.js"),
    ("body", "laravel", "Laravel"),
    ("body", "django", "Django"),
    ("body", "spring", "Spring"),
    ("body", "wordpress", "WordPress"),
    ("body", "drupal", "Drupal"),
    ("body", "shopify", "Shopify"),
    # Cloud
    ("headers", "x-amz", "AWS"),
    ("headers", "x-azure", "Azure"),
    ("headers", "x-goog", "Google Cloud"),
    ("headers", "cf-ray", "Cloudflare"),
    ("headers", "x-akamai", "Akamai"),
]

# Common web ports to check
WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 4000, 5000, 9000]


def run_recon(scan_id: str, project_id: str, scope_data: dict) -> int:
    """
    Main recon entry point. Returns number of assets discovered.
    """
    return asyncio.run(_run_recon_async(scan_id, project_id, scope_data))


async def _run_recon_async(scan_id: str, project_id: str, scope_data: dict) -> int:
    from app.core.database import AsyncSessionLocal
    from app.models import Asset, AssetType, AgentLog, AgentType, BusinessCriticality

    validator = ScopeValidator(
        allowed_domains=scope_data.get("domains", []),
        allowed_ips=scope_data.get("ips", []),
        allowed_cidrs=scope_data.get("cidrs", []),
        excluded_domains=scope_data.get("excluded_domains", []),
        excluded_ips=scope_data.get("excluded_ips", []),
        allow_private_ips=scope_data.get("allow_private_ips", False),
    )

    assets_created = 0
    targets = scope_data.get("domains", []) + scope_data.get("ips", [])

    async with httpx.AsyncClient(
        timeout=10.0,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (Security Assessment Tool)"},
        limits=httpx.Limits(max_connections=10),
    ) as client:
        for target in targets:
            if is_scan_killed_sync(scan_id):
                logger.warning("Kill switch — stopping recon", scan_id=scan_id)
                break

            try:
                # Scope validation
                validator.validate(target)
            except ScopeViolationError as e:
                logger.warning("Target out of scope", target=target, reason=str(e))
                continue

            logger.info("Probing target", target=target)

            # DNS Resolution
            resolved_ips = _resolve_dns(target)

            # HTTP/HTTPS probe
            for scheme in ["https", "http"]:
                url = f"{scheme}://{target}"
                try:
                    response = await client.get(url, timeout=8.0)
                    technologies = _detect_technologies(response)
                    title = _extract_title(response.text)

                    async with AsyncSessionLocal() as db:
                        asset = Asset(
                            project_id=project_id,
                            asset_type=AssetType.SUBDOMAIN if "." in target else AssetType.DOMAIN,
                            value=target,
                            ip_address=resolved_ips[0] if resolved_ips else None,
                            port=443 if scheme == "https" else 80,
                            protocol=scheme,
                            status_code=response.status_code,
                            title=title,
                            server=response.headers.get("server", ""),
                            technologies=technologies,
                            is_internet_facing=True,
                            raw_headers=dict(response.headers),
                        )
                        db.add(asset)
                        await db.commit()
                        assets_created += 1

                        _db_log(db, scan_id, AgentType.RECON,
                            f"✅ Asset discovered: {url} [{response.status_code}] - {', '.join(technologies[:3])}",
                            target=target,
                        )
                        await db.commit()

                    break  # Got a response, skip HTTP if HTTPS worked

                except httpx.TimeoutException:
                    logger.info("Timeout probing target", target=url)
                except httpx.ConnectError:
                    pass  # Port not open, expected
                except Exception as e:
                    logger.warning("Error probing target", target=url, error=str(e))

            await asyncio.sleep(60 / max(scope_data.get("max_requests_per_minute", 30), 1))

    return assets_created


def _resolve_dns(hostname: str) -> list[str]:
    try:
        results = socket.getaddrinfo(hostname, None)
        return list({r[4][0] for r in results})
    except Exception:
        return []


def _detect_technologies(response: httpx.Response) -> list[str]:
    technologies = []
    headers_str = " ".join(f"{k}:{v}" for k, v in response.headers.items()).lower()
    body_lower = (response.text or "")[:50000].lower()

    for source, pattern, name in TECH_FINGERPRINTS:
        if source == "server" and pattern in response.headers.get("server", "").lower():
            if name not in technologies:
                technologies.append(name)
        elif source == "x-powered-by" and pattern in response.headers.get("x-powered-by", "").lower():
            if name not in technologies:
                technologies.append(name)
        elif source == "body" and pattern in body_lower:
            if name not in technologies:
                technologies.append(name)
        elif source == "headers" and pattern in headers_str:
            if name not in technologies:
                technologies.append(name)

    # Security headers detection
    sec_headers = {
        "content-security-policy": "CSP",
        "strict-transport-security": "HSTS",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
    }
    for header, name in sec_headers.items():
        if header in response.headers:
            technologies.append(f"has_{name}")

    return technologies[:20]  # Cap at 20


def _extract_title(html: str) -> Optional[str]:
    import re
    match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    return match.group(1).strip()[:200] if match else None


def _db_log(db, scan_id: str, agent, message: str, target: str = None, level: str = "INFO"):
    """Sync log within an already-open async session."""
    from app.models import AgentLog, AgentType
    log = AgentLog(
        scan_id=scan_id,
        agent_type=agent,
        level=level,
        message=message,
        target=target,
    )
    db.add(log)
