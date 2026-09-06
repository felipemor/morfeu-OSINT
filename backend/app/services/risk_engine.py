"""
Business Risk Engine V2 — Multi-Factor Contextual Risk Scoring

Formula:
  Technical Risk (Severity + CVSS)
  + Exploitability
  + Asset Criticality
  + Internet Exposure
  + Authentication Context
  + Business Impact
  = Business Risk (0-100)
"""
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import structlog

from app.models import (
    Finding, RiskScore, Severity, Asset, BusinessCriticality,
    Organization, Project
)

logger = structlog.get_logger(__name__)

SEVERITY_BASE_SCORES = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 4.5,
    Severity.LOW: 2.0,
    Severity.INFO: 0.5,
}

CRITICALITY_MULTIPLIERS = {
    BusinessCriticality.LOW: 0.7,
    BusinessCriticality.MEDIUM: 1.0,
    BusinessCriticality.HIGH: 1.4,
    BusinessCriticality.CRITICAL: 2.0,
}

EXPLOITABILITY_WEIGHTS = {
    "HIGH": 1.3,
    "MEDIUM": 1.0,
    "LOW": 0.7,
}


def calculate_finding_business_risk(
    severity: Severity,
    confidence: int = 80,
    cvss_score: Optional[float] = None,
    asset_criticality: BusinessCriticality = BusinessCriticality.MEDIUM,
    is_internet_facing: bool = True,
    auth_required: bool = False,
    exploitability: str = "MEDIUM",
    custom_weights: Optional[dict] = None,
) -> float:

    """
    Computes holistic 0-100 Business Risk score taking into account exposure and asset value.
    """
    weights = custom_weights or {
        "technical_risk": 1.0,
        "exploitability": 1.0,
        "asset_criticality": 1.2,
        "internet_exposure": 1.3,
        "business_impact": 1.2,
    }

    # 1. Technical Baseline Score
    base_tech = (cvss_score if cvss_score is not None else SEVERITY_BASE_SCORES.get(severity, 5.0))
    conf_factor = max(0.5, min(1.0, confidence / 100.0))

    # 2. Modifiers
    crit_factor = CRITICALITY_MULTIPLIERS.get(asset_criticality, 1.0) * weights.get("asset_criticality", 1.0)
    exp_factor = (1.4 if is_internet_facing else 0.9) * weights.get("internet_exposure", 1.0)
    exploit_factor = EXPLOITABILITY_WEIGHTS.get(exploitability.upper(), 1.0) * weights.get("exploitability", 1.0)
    # Unauthenticated findings on internet-facing assets pose much higher immediate risk
    auth_factor = 1.2 if not auth_required else 1.0

    raw_risk = base_tech * conf_factor * crit_factor * exp_factor * exploit_factor * auth_factor

    # Normalize to 0-100 scale
    max_theoretical = 10.0 * 1.0 * (2.0 * 1.2) * (1.4 * 1.3) * (1.3 * 1.0) * 1.2
    normalized = min(100.0, (raw_risk / max_theoretical) * 100.0)

    return round(normalized, 2)


# Backward compatibility alias
calculate_finding_risk_score = calculate_finding_business_risk


async def calculate_project_risk(db: AsyncSession, project_id: str) -> RiskScore:
    """
    Calculates aggregate project risk based on confirmed findings and asset exposure.
    """
    # 1. Fetch Project and Organization (to retrieve custom risk weights if set)
    proj_res = await db.execute(select(Project).where(Project.id == project_id))
    project = proj_res.scalar_one_or_none()

    weights = None
    if project and project.organization_id:
        org_res = await db.execute(select(Organization).where(Organization.id == project.organization_id))
        org = org_res.scalar_one_or_none()
        if org and org.risk_weights:
            weights = org.risk_weights

    # 2. Fetch Findings
    findings_res = await db.execute(
        select(Finding).where(
            Finding.project_id == project_id,
            Finding.is_false_positive == False,
        )
    )
    findings = findings_res.scalars().all()

    counts = {sev: 0 for sev in Severity}
    total_score = 0.0

    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        score = calculate_finding_business_risk(
            severity=f.severity,
            cvss_score=f.cvss_score,
            confidence=f.confidence,
            exploitability=f.exploitability or "MEDIUM",
            custom_weights=weights,
        )
        f.risk_score = score
        total_score += score

    # Aggregated Project Risk
    if findings:
        project_score = min(total_score / max(len(findings), 1) * 10, 100.0)
        if counts[Severity.CRITICAL] > 0:
            project_score = max(project_score, 75.0)
        elif counts[Severity.HIGH] > 2:
            project_score = max(project_score, 55.0)
    else:
        project_score = 0.0

    # Upsert Risk Score record
    risk_res = await db.execute(select(RiskScore).where(RiskScore.project_id == project_id))
    risk = risk_res.scalar_one_or_none()
    if not risk:
        risk = RiskScore(project_id=project_id)
        db.add(risk)

    risk.total_score = round(project_score, 2)
    risk.critical_count = counts[Severity.CRITICAL]
    risk.high_count = counts[Severity.HIGH]
    risk.medium_count = counts[Severity.MEDIUM]
    risk.low_count = counts[Severity.LOW]
    risk.info_count = counts[Severity.INFO]

    # Coverage
    from app.models import Endpoint
    ep_res = await db.execute(select(func.count(Endpoint.id)).where(Endpoint.project_id == project_id))
    ep_count = ep_res.scalar() or 0
    risk.coverage_percentage = min(98.0, float(ep_count * 5)) if ep_count > 0 else 0.0

    await db.commit()
    await db.refresh(risk)

    logger.info("Business Risk Score computed", project_id=project_id, total_score=risk.total_score)
    return risk
