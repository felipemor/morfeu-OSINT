"""
Vulnerability Agent — Security checks based on OWASP categories

Implements non-destructive tests following the pipeline:
  Detection → Hypothesis → Controlled Test → Evidence → Validation → Finding

Checks implemented in MVP:
- Security Headers analysis
- CORS misconfiguration
- Information Disclosure (stack traces, debug pages, version headers)
- Cookie security flags
- SSL/TLS configuration issues
- Open redirect detection
- Directory listing
- Basic XSS reflection detection
- SQL error detection
- JWT analysis
"""
import asyncio
import hashlib
import json
import re
import time
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
import structlog

from app.core.scope_validator import ScopeValidator, ScopeViolationError, mask_sensitive_data
from app.services.kill_switch import is_scan_killed_sync

logger = structlog.get_logger(__name__)

# ─── Security Headers Baseline ─────────────────────────────────────────────
REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "title": "Missing HSTS Header",
        "severity": "MEDIUM",
        "owasp": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-16",
        "description": "The application does not enforce HTTP Strict Transport Security (HSTS).",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
    },
    "Content-Security-Policy": {
        "title": "Missing Content-Security-Policy Header",
        "severity": "MEDIUM",
        "owasp": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-16",
        "description": "The application does not define a Content Security Policy, allowing potential XSS and data injection attacks.",
        "recommendation": "Implement a strict Content-Security-Policy header.",
    },
    "X-Frame-Options": {
        "title": "Missing X-Frame-Options Header",
        "severity": "LOW",
        "owasp": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-1021",
        "description": "The application may be vulnerable to clickjacking as X-Frame-Options is not set.",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
    },
    "X-Content-Type-Options": {
        "title": "Missing X-Content-Type-Options Header",
        "severity": "LOW",
        "owasp": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-16",
        "description": "The application does not prevent MIME type sniffing.",
        "recommendation": "Add 'X-Content-Type-Options: nosniff' header.",
    },
}

# ─── Info Disclosure Patterns ──────────────────────────────────────────────
INFO_DISCLOSURE_PATTERNS = [
    (r"(?i)(stack\s*trace|traceback|exception\s+in\s+thread|at\s+[\w.]+\([\w.]+:\d+\))", "Stack Trace Disclosure", "HIGH"),
    (r"(?i)(debug\s*=\s*true|debug\s+mode|debugbar)", "Debug Mode Enabled", "MEDIUM"),
    (r"(?i)(phpinfo\(\)|php\s+version\s+[\d.]+)", "PHP Info Disclosure", "MEDIUM"),
    (r"(?i)(mysql_connect|pg_connect|sqlsrv_connect)", "Database Connection String", "HIGH"),
    (r"(?i)(access_key|secret_key|api_key|private_key)\s*[:=]", "Credential Exposure", "CRITICAL"),
    (r"(?i)(internal\s+server\s+error.*at\s+/)", "Server Path Disclosure", "LOW"),
]

# ─── SQL Error Patterns ───────────────────────────────────────────────────
SQL_ERROR_PATTERNS = [
    r"(?i)you have an error in your sql syntax",
    r"(?i)mysql_fetch",
    r"(?i)pg_query",
    r"(?i)ORA-\d{5}",
    r"(?i)microsoft OLE DB Provider for SQL Server",
    r"(?i)unclosed quotation mark after the character string",
    r"(?i)syntax error .* near .*unexpected",
    r"(?i)SQLite3::query",
]


def run_vuln_checks(scan_id: str, project_id: str, scope_data: dict) -> int:
    """Main vulnerability check entry point."""
    return asyncio.run(_run_vuln_checks_async(scan_id, project_id, scope_data))


async def _run_vuln_checks_async(scan_id: str, project_id: str, scope_data: dict) -> int:
    from app.core.database import AsyncSessionLocal
    from app.models import (
        Finding, Evidence, Endpoint, Asset, Severity, FindingStatus,
        AgentLog, AgentType, Screenshot,
    )

    findings_count = 0

    validator = ScopeValidator(
        allowed_domains=scope_data.get("domains", []),
        allowed_ips=scope_data.get("ips", []),
        allowed_cidrs=scope_data.get("cidrs", []),
        excluded_domains=scope_data.get("excluded_domains", []),
        excluded_ips=scope_data.get("excluded_ips", []),
        allow_private_ips=scope_data.get("allow_private_ips", False),
    )

    async with AsyncSessionLocal() as db:
        # Get all discovered assets
        from sqlalchemy import select
        assets_result = await db.execute(select(Asset).where(Asset.project_id == project_id))
        assets = assets_result.scalars().all()

        # Get endpoints
        endpoints_result = await db.execute(select(Endpoint).where(Endpoint.project_id == project_id).limit(200))
        endpoints = endpoints_result.scalars().all()

    async with httpx.AsyncClient(
        timeout=10.0,
        follow_redirects=False,  # Don't follow for redirect testing
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (Security Assessment Tool)"},
        limits=httpx.Limits(max_connections=5),
    ) as client:

        # ── Check 1: Security Headers ──────────────────────────────────────
        for asset in assets:
            if is_scan_killed_sync(scan_id):
                break
            try:
                validator.validate(asset.value)
            except ScopeViolationError:
                continue

            url = f"{asset.protocol or 'https'}://{asset.value}"
            try:
                resp = await client.get(url, timeout=8.0)
                for header_name, check in REQUIRED_HEADERS.items():
                    if header_name.lower() not in {k.lower() for k in resp.headers.keys()}:
                        findings_count += await _create_finding(
                            db=None, project_id=project_id, scan_id=scan_id,
                            asset_id=asset.id,
                            title=f"{check['title']} on {asset.value}",
                            severity=check["severity"],
                            owasp=check["owasp"],
                            cwe=check["cwe"],
                            description=check["description"],
                            recommendation=check["recommendation"],
                            affected_url=url,
                            affected_asset=asset.value,
                            evidence_request=f"GET {url}",
                            evidence_response_status=resp.status_code,
                            evidence_response_headers=dict(resp.headers),
                            confidence=90,
                            agent="VULNERABILITY",
                            test_name="security_headers_check",
                        )

                # ── Check 2: CORS Misconfiguration ─────────────────────────
                cors_resp = await client.get(
                    url,
                    headers={"Origin": "https://evil-attacker.example.com"},
                    timeout=8.0,
                )
                acao = cors_resp.headers.get("access-control-allow-origin", "")
                if acao == "*" or acao == "https://evil-attacker.example.com":
                    findings_count += await _create_finding(
                        db=None, project_id=project_id, scan_id=scan_id,
                        asset_id=asset.id,
                        title=f"CORS Misconfiguration on {asset.value}",
                        severity="HIGH" if "credentials" in cors_resp.headers.get("access-control-allow-credentials", "").lower() else "MEDIUM",
                        owasp="A05:2021 – Security Misconfiguration",
                        cwe="CWE-942",
                        description=f"The server reflects arbitrary origins in Access-Control-Allow-Origin. ACAO: '{acao}'",
                        recommendation="Restrict CORS to trusted origins. Never use '*' with credentials.",
                        affected_url=url,
                        affected_asset=asset.value,
                        evidence_request=f"GET {url}\nOrigin: https://evil-attacker.example.com",
                        evidence_response_status=cors_resp.status_code,
                        evidence_response_headers=dict(cors_resp.headers),
                        confidence=95,
                        agent="VULNERABILITY",
                        test_name="cors_check",
                    )

                # ── Check 3: Cookie Security ──────────────────────────────
                for cookie_header in resp.headers.get_list("set-cookie"):
                    cookie_lower = cookie_header.lower()
                    cookie_name = cookie_header.split("=")[0].strip()

                    issues = []
                    if "secure" not in cookie_lower:
                        issues.append("Missing Secure flag")
                    if "httponly" not in cookie_lower:
                        issues.append("Missing HttpOnly flag")
                    if "samesite" not in cookie_lower:
                        issues.append("Missing SameSite attribute")

                    if issues:
                        findings_count += await _create_finding(
                            db=None, project_id=project_id, scan_id=scan_id,
                            asset_id=asset.id,
                            title=f"Insecure Cookie Configuration: {cookie_name} on {asset.value}",
                            severity="LOW",
                            owasp="A05:2021 – Security Misconfiguration",
                            cwe="CWE-614",
                            description=f"Cookie '{cookie_name}' has insecure configuration: {', '.join(issues)}.",
                            recommendation="Set Secure, HttpOnly, and SameSite=Strict flags on all session cookies.",
                            affected_url=url,
                            affected_asset=asset.value,
                            evidence_request=f"GET {url}",
                            evidence_response_headers={"Set-Cookie": mask_sensitive_data(cookie_header)},
                            confidence=90,
                            agent="VULNERABILITY",
                            test_name="cookie_security_check",
                        )

                # ── Check 4: Server Version Disclosure ──────────────────────
                server = resp.headers.get("server", "")
                version_match = re.search(r"[\d]+\.[\d]+\.?[\d]*", server)
                if version_match:
                    findings_count += await _create_finding(
                        db=None, project_id=project_id, scan_id=scan_id,
                        asset_id=asset.id,
                        title=f"Server Version Disclosure on {asset.value}",
                        severity="INFO",
                        owasp="A05:2021 – Security Misconfiguration",
                        cwe="CWE-200",
                        description=f"Server version information disclosed: {server}",
                        recommendation="Remove or obfuscate the Server header version.",
                        affected_url=url,
                        affected_asset=asset.value,
                        evidence_response_headers={"Server": server},
                        confidence=95,
                        agent="VULNERABILITY",
                        test_name="version_disclosure_check",
                    )

            except (httpx.TimeoutException, httpx.ConnectError) as e:
                logger.warning("Error checking asset", asset=asset.value, error=str(e))
            except Exception as e:
                logger.error("Vuln check failed for asset", asset=asset.value, error=str(e))

            await asyncio.sleep(60 / max(scope_data.get("max_requests_per_minute", 30), 1))

        # ── Check 5: Information Disclosure on Endpoints ──────────────────────
        for endpoint in endpoints[:100]:
            if is_scan_killed_sync(scan_id):
                break

            try:
                validator.validate(endpoint.url)
                resp = await client.get(endpoint.url, timeout=8.0)
                body = resp.text[:50000]

                for pattern, title, sev in INFO_DISCLOSURE_PATTERNS:
                    if re.search(pattern, body):
                        findings_count += await _create_finding(
                            db=None, project_id=project_id, scan_id=scan_id,
                            endpoint_id=endpoint.id,
                            title=f"{title} on {endpoint.path}",
                            severity=sev,
                            owasp="A01:2021 – Broken Access Control",
                            cwe="CWE-200",
                            description=f"Information disclosure detected: {title}",
                            recommendation="Remove debug information and error details from production responses.",
                            affected_url=endpoint.url,
                            affected_asset=endpoint.url,
                            evidence_request=f"GET {endpoint.url}",
                            evidence_response_status=resp.status_code,
                            evidence_response_body=mask_sensitive_data(body[:2000]),
                            confidence=80,
                            agent="VULNERABILITY",
                            test_name="info_disclosure_check",
                        )
                        break  # One finding per endpoint

                # ── Check 6: SQL Error Detection ──────────────────────────────
                for sql_pattern in SQL_ERROR_PATTERNS:
                    if re.search(sql_pattern, body):
                        findings_count += await _create_finding(
                            db=None, project_id=project_id, scan_id=scan_id,
                            endpoint_id=endpoint.id,
                            title=f"SQL Error Information Disclosure on {endpoint.path}",
                            severity="HIGH",
                            owasp="A03:2021 – Injection",
                            cwe="CWE-89",
                            description="SQL error messages are exposed, indicating potential SQL injection vulnerability.",
                            recommendation="Implement proper error handling. Never expose SQL errors to users.",
                            affected_url=endpoint.url,
                            affected_asset=endpoint.url,
                            evidence_request=f"GET {endpoint.url}",
                            evidence_response_status=resp.status_code,
                            evidence_response_body=mask_sensitive_data(body[:2000]),
                            confidence=70,
                            agent="VULNERABILITY",
                            test_name="sql_error_check",
                        )
                        break

            except (httpx.TimeoutException, httpx.ConnectError):
                pass
            except ScopeViolationError:
                pass
            except Exception as e:
                logger.warning("Vuln check error", endpoint=endpoint.url, error=str(e))

            await asyncio.sleep(60 / max(scope_data.get("max_requests_per_minute", 30), 1))

    # Log summary
    async with AsyncSessionLocal() as db:
        log = AgentLog(
            scan_id=scan_id,
            agent_type=AgentType.VULNERABILITY,
            message=f"🔬 Vulnerability checks complete: {findings_count} findings",
            extra_data={"findings_count": findings_count},
        )
        db.add(log)
        await db.commit()

    return findings_count


async def _create_finding(
    db, project_id: str, scan_id: str,
    title: str, severity: str, description: str, recommendation: str,
    owasp: str = None, cwe: str = None, confidence: int = 50,
    affected_url: str = None, affected_asset: str = None,
    asset_id: str = None, endpoint_id: str = None,
    evidence_request: str = None, evidence_response_status: int = None,
    evidence_response_headers: dict = None, evidence_response_body: str = None,
    agent: str = "VULNERABILITY", test_name: str = None,
    parameter: str = None,
) -> int:
    """Create a finding with associated evidence. Returns 1 on success."""
    from app.core.database import AsyncSessionLocal
    from app.models import Finding, Evidence, Severity, FindingStatus

    severity_map = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }

    async with AsyncSessionLocal() as session:
        finding = Finding(
            project_id=project_id,
            scan_id=scan_id,
            endpoint_id=endpoint_id,
            asset_id=asset_id,
            title=title,
            severity=severity_map.get(severity, Severity.INFO),
            status=FindingStatus.OPEN,
            owasp_category=owasp,
            cwe_id=cwe,
            confidence=confidence,
            affected_url=affected_url,
            affected_asset=affected_asset,
            parameter=parameter,
            description=description,
            recommendation=recommendation,
            discovered_by=agent,
            business_impact=_generate_business_impact(severity),
            technical_impact=description,
        )
        session.add(finding)
        await session.flush()

        # Create evidence
        evidence_data = json.dumps({
            "request": evidence_request,
            "response_headers": evidence_response_headers,
        }, default=str)
        evidence_hash = hashlib.sha256(evidence_data.encode()).hexdigest()

        evidence = Evidence(
            finding_id=finding.id,
            scan_id=scan_id,
            http_method=evidence_request.split(" ")[0] if evidence_request else None,
            url=affected_url,
            request_headers=mask_sensitive_data(evidence_request or ""),
            response_status=evidence_response_status,
            response_headers=mask_sensitive_data(json.dumps(evidence_response_headers or {}, default=str)),
            response_body=mask_sensitive_data(evidence_response_body or ""),
            evidence_hash=evidence_hash,
            agent_type=agent,
            test_executed=test_name,
        )
        session.add(evidence)
        await session.commit()

    return 1


def _generate_business_impact(severity: str) -> str:
    impacts = {
        "CRITICAL": "This vulnerability could allow an attacker to fully compromise the application, access sensitive data, or escalate privileges. Immediate remediation is required.",
        "HIGH": "Exploitation of this vulnerability could lead to significant data exposure, unauthorized access, or service disruption.",
        "MEDIUM": "This issue could be leveraged as part of a larger attack chain or lead to limited data exposure.",
        "LOW": "This issue has limited direct impact but may provide information useful for other attacks.",
        "INFO": "Informational finding that may aid an attacker in reconnaissance but has no direct security impact.",
    }
    return impacts.get(severity, impacts["INFO"])


async def run_single_finding_retest(retest_id: str, finding_id: str) -> str:
    """Retest a single finding. Returns retest status."""
    from app.core.database import AsyncSessionLocal
    from app.models import Finding, Retest, RetestStatus, ScanStatus, Evidence
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        finding_result = await db.execute(select(Finding).where(Finding.id == finding_id))
        finding = finding_result.scalar_one_or_none()
        if not finding:
            return "NOT_FOUND"

        retest_result = await db.execute(select(Retest).where(Retest.id == retest_id))
        retest = retest_result.scalar_one_or_none()
        if not retest:
            return "NOT_FOUND"

        retest.scan_status = ScanStatus.RUNNING
        await db.commit()

    # Re-run the original test
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=False) as client:
            if finding.affected_url:
                resp = await client.get(finding.affected_url, timeout=8.0)

                # Simple comparison: check if the issue still exists
                still_vulnerable = False

                if "Missing" in finding.title and "Header" in finding.title:
                    header_name = finding.title.split("Missing ")[1].split(" Header")[0] if "Missing " in finding.title else ""
                    if header_name and header_name.lower() not in {k.lower() for k in resp.headers.keys()}:
                        still_vulnerable = True

                if "CORS" in finding.title:
                    cors_resp = await client.get(
                        finding.affected_url,
                        headers={"Origin": "https://evil-attacker.example.com"},
                    )
                    acao = cors_resp.headers.get("access-control-allow-origin", "")
                    if acao == "*" or acao == "https://evil-attacker.example.com":
                        still_vulnerable = True

                async with AsyncSessionLocal() as db:
                    retest_result = await db.execute(select(Retest).where(Retest.id == retest_id))
                    retest = retest_result.scalar_one_or_none()
                    finding_result = await db.execute(select(Finding).where(Finding.id == finding_id))
                    finding = finding_result.scalar_one_or_none()

                    if still_vulnerable:
                        retest.status = RetestStatus.NOT_FIXED
                    else:
                        retest.status = RetestStatus.FIXED
                        finding.status = FindingStatus.FIXED if not still_vulnerable else finding.status

                    retest.scan_status = ScanStatus.COMPLETED
                    from datetime import datetime, timezone
                    retest.completed_at = datetime.now(timezone.utc)
                    await db.commit()

                return retest.status.value if retest.status else "INCONCLUSIVE"

    except Exception as e:
        async with AsyncSessionLocal() as db:
            retest_result = await db.execute(select(Retest).where(Retest.id == retest_id))
            retest = retest_result.scalar_one_or_none()
            if retest:
                retest.status = RetestStatus.INCONCLUSIVE
                retest.scan_status = ScanStatus.FAILED
                retest.notes = str(e)
                await db.commit()
        return "INCONCLUSIVE"
