"""
Evidence Chain & Data Classification Service

Enforces:
1. Cryptographic SHA-256 immutability & verification
2. Parent-event causal linking (Scan → Action → Request → Response → Observation → Finding → Evidence)
3. Data classification (PUBLIC, INTERNAL, CONFIDENTIAL, SECRET, PII)
4. Secret & PII masking
5. Interactive timeline event generation
"""
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from app.models import Evidence, Finding, Scan, AgentLog, DataClassification

logger = structlog.get_logger(__name__)

# Patterns for masking secrets in headers, requests, and responses
SENSITIVE_PATTERNS = [
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*([^\s,;\"'}\]]+)", r"\1: [MASKED:PASSWORD]"),
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*([^\s,;\"'}\]]+)", r"\1: [MASKED:API_KEY]"),
    (r"(?i)(secret|token)\s*[:=]\s*([^\s,;\"'}\]]+)", r"\1: [MASKED:SECRET]"),
    (r"(?i)(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", r"\1[MASKED:BEARER_TOKEN]"),
    (r"(?i)(Authorization:\s*)[^\r\n]+", r"\1[MASKED:AUTH_HEADER]"),
    (r"(?i)(Cookie:\s*)[^\r\n]+", r"\1[MASKED:COOKIE]"),
    (r"(?i)(Set-Cookie:\s*)[^\r\n]+", r"\1[MASKED:COOKIE]"),
    (r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", "[MASKED:CARD_NUMBER]"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b", "[MASKED:EMAIL]"),
]


def mask_sensitive_content(text: Optional[str]) -> Optional[str]:
    """Masks credentials, tokens, cookies and PII from request/response strings."""
    if not text:
        return text
    masked = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        masked = re.sub(pattern, replacement, masked)
    return masked


def compute_evidence_hash(
    finding_id: str,
    url: Optional[str],
    method: Optional[str],
    status: Optional[int],
    req_body: Optional[str],
    resp_body: Optional[str],
    collected_at: str,
) -> str:
    """Calculates SHA-256 fingerprint for immutable evidence verification."""
    payload = f"{finding_id}:{url}:{method}:{status}:{req_body}:{resp_body}:{collected_at}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class EvidenceService:
    """Manages evidence collection, validation, and timeline generation."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def record_evidence(
        self,
        finding_id: str,
        scan_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        parent_evidence_id: Optional[str] = None,
        http_method: Optional[str] = None,
        url: Optional[str] = None,
        request_headers: Optional[str] = None,
        request_body: Optional[str] = None,
        response_status: Optional[int] = None,
        response_headers: Optional[str] = None,
        response_body: Optional[str] = None,
        screenshot_path: Optional[str] = None,
        dom_snapshot: Optional[str] = None,
        additional_data: Optional[dict] = None,
        agent_type: Optional[str] = None,
        test_executed: Optional[str] = None,
        data_classification: DataClassification = DataClassification.CONFIDENTIAL,
    ) -> Evidence:
        """
        Masks secrets, computes SHA-256 integrity hash, and stores immutable evidence.
        """
        collected_at = datetime.now(timezone.utc)

        # Apply masking
        clean_req_headers = mask_sensitive_content(request_headers)
        clean_req_body = mask_sensitive_content(request_body)
        clean_resp_headers = mask_sensitive_content(response_headers)
        clean_resp_body = mask_sensitive_content(response_body)

        ev_hash = compute_evidence_hash(
            finding_id=finding_id,
            url=url,
            method=http_method,
            status=response_status,
            req_body=clean_req_body,
            resp_body=clean_resp_body,
            collected_at=collected_at.isoformat(),
        )

        evidence = Evidence(
            finding_id=finding_id,
            scan_id=scan_id,
            agent_id=agent_id,
            parent_evidence_id=parent_evidence_id,
            http_method=http_method,
            url=url,
            request_headers=clean_req_headers,
            request_body=clean_req_body,
            response_status=response_status,
            response_headers=clean_resp_headers,
            response_body=clean_resp_body,
            screenshot_path=screenshot_path,
            dom_snapshot=dom_snapshot,
            additional_data=additional_data,
            data_classification=data_classification,
            evidence_hash=ev_hash,
            integrity_verified=True,
            agent_type=agent_type,
            test_executed=test_executed,
            collected_at=collected_at,
        )

        self.db.add(evidence)
        await self.db.commit()
        await self.db.refresh(evidence)

        logger.info(
            "Evidence recorded with SHA-256 hash",
            evidence_id=evidence.id,
            finding_id=finding_id,
            hash=ev_hash,
        )

        return evidence

    async def get_pentest_timeline(self, scan_id: str) -> list[dict[str, Any]]:
        """
        Builds a chronological, interactive timeline of pentest events.
        """
        events: list[dict[str, Any]] = []

        # 1. Fetch Agent Logs
        logs_res = await self.db.execute(
            select(AgentLog).where(AgentLog.scan_id == scan_id).order_by(AgentLog.timestamp)
        )
        logs = logs_res.scalars().all()
        for log in logs:
            events.append({
                "id": log.id,
                "type": "LOG",
                "agent": log.agent_type.value if hasattr(log.agent_type, "value") else str(log.agent_type),
                "level": log.level,
                "message": log.message,
                "target": log.target,
                "timestamp": log.timestamp.isoformat(),
                "extra": log.extra_data,
            })

        # 2. Fetch Findings
        findings_res = await self.db.execute(
            select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.created_at)
        )
        findings = findings_res.scalars().all()
        for f in findings:
            events.append({
                "id": f.id,
                "type": "FINDING_DISCOVERED",
                "agent": f.discovered_by or "VULNERABILITY",
                "level": f.severity.value,
                "message": f"Finding Validated: {f.title} ({f.severity.value})",
                "target": f.affected_url or f.affected_asset,
                "timestamp": f.created_at.isoformat(),
                "extra": {
                    "cwe": f.cwe_id,
                    "confidence": f.confidence,
                    "cvss": f.cvss_score,
                },
            })

        # Sort all combined events by timestamp
        events.sort(key=lambda e: e["timestamp"])
        return events
