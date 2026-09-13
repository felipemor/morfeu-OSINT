"""
Security Correlation Engine — Multi-Plane Correlation, Dynamic Business Risk, SLA Calculation & Deduplication
Correlates: Asset -> Domain -> Application -> Repository -> Finding -> Vulnerability -> Business Service -> Owner -> Control -> Compliance -> Evidence -> Risk.
"""
from typing import Dict, Any, List, Optional
import hashlib
from datetime import datetime, timezone, timedelta


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EnterpriseCorrelationEngine:
    """Multi-Plane Correlation and Business Risk Calculator"""

    # SLA standards in hours
    SLA_CONFIG = {
        "CRITICAL": {"sla_hours": 24, "escalation_hours": 12},
        "HIGH": {"sla_hours": 168, "escalation_hours": 72},       # 7 days
        "MEDIUM": {"sla_hours": 720, "escalation_hours": 360},    # 30 days
        "LOW": {"sla_hours": 2160, "escalation_hours": 1080},     # 90 days
        "INFO": {"sla_hours": 4320, "escalation_hours": 2160},    # 180 days
    }

    SAMPLE_CORRELATED_CHAINS = [
        {
            "correlation_id": "CORR-2026-PIX-001",
            "chain_title": "Pix Core Gateway Exposure & Missing Rate-Limit",
            "business_service": "Instant Payments (Pix)",
            "business_unit": "Retail Banking",
            "business_owner": "Carlos Mendonça",
            "tech_owner": "Felipe Costa",
            "criticality": "CRITICAL",
            "nodes": [
                {"type": "Asset", "label": "api-pix.banking.internal / 198.51.100.22", "status": "EXPOSED"},
                {"type": "Application", "label": "Pix Core Transaction Engine (PIX-CORE-API)", "status": "CRITICAL"},
                {"type": "Repository", "label": "retail-banking/pix-core-api (main)", "status": "MONITORED"},
                {"type": "Finding", "label": "FND-000412 — Inadequate Rate Limiting on Authentication Endpoint", "status": "IN_REMEDIATION"},
                {"type": "Control", "label": "CTRL-WAF-001 — WAF L7 & Anti-DDoS", "status": "ENFORCING_MITIGATION"},
                {"type": "Compliance", "label": "BACEN Res. 4.893 Art. 3º & PCI DSS Req 6.4", "status": "UNDER_SLA"},
                {"type": "Evidence", "label": "EV-99214 — SHA256 Verified HTTP 429 Test Payload", "status": "VALIDATED"}
            ],
            "technical_severity": "HIGH",
            "business_risk_score": 38.5,
            "business_risk_level": "LOW",  # lowered by compensating WAF control
            "compensating_controls": ["Akamai Edge Rate-Limiting Rule #4812", "mTLS Client Cert Required"],
            "sla_remaining_hours": 112,
            "sla_status": "ON_TRACK",
        },
        {
            "correlation_id": "CORR-2026-IB-002",
            "chain_title": "Internet Banking Web & CSP Nonce Policy Weakness",
            "business_service": "Digital Channels Banking Portal",
            "business_unit": "Digital Channels",
            "business_owner": "Renata Silveira",
            "tech_owner": "Rodrigo Alvarez",
            "criticality": "HIGH",
            "nodes": [
                {"type": "Asset", "label": "app.shieldsecurity.io / 104.18.22.10", "status": "INTERNET_FACING"},
                {"type": "Application", "label": "Internet Banking Web (IB-WEB-APP)", "status": "CRITICAL"},
                {"type": "Repository", "label": "digital-channels/ib-portal-frontend (main)", "status": "MONITORED"},
                {"type": "Finding", "label": "FND-000389 — CSP Header missing strict script-src nonce", "status": "OPEN"},
                {"type": "Control", "label": "CTRL-APPSEC-001 & CTRL-TLS-001", "status": "COMPLIANT"},
                {"type": "Compliance", "label": "OWASP A03 / CIS Controls v8 #4.1", "status": "UNDER_SLA"},
                {"type": "Evidence", "label": "EV-88123 — SHA256 HTTP Header Response Parser", "status": "VALIDATED"}
            ],
            "technical_severity": "MEDIUM",
            "business_risk_score": 28.0,
            "business_risk_level": "LOW",
            "compensating_controls": ["X-XSS-Protection", "Strict Origin Isolation"],
            "sla_remaining_hours": 480,
            "sla_status": "ON_TRACK",
        }
    ]

    RISK_ACCEPTANCE_REGISTRY = [
        {
            "id": "RA-2026-001",
            "finding_id": "FND-000305",
            "title": "Legacy Internal Service TLS 1.2 CBC Ciphersuite on isolated DMZ backend",
            "requested_by": "Felipe Costa",
            "business_unit": "Core Infrastructure",
            "business_justification": "Backend connection terminates in dedicated encrypted IPSec VPN tunnel with internal HSM.",
            "compensating_controls": "Microsegmentation eBPF isolation + mTLS certificate pinning.",
            "risk_level": "MEDIUM",
            "status": "APPROVED",
            "approver": "Security Committee / CISO Office",
            "expiration_date": "2026-12-31T23:59:59Z",
            "days_until_expiration": 111,
        }
    ]

    @classmethod
    def calculate_business_risk(
        cls,
        severity: str,
        cvss: float,
        is_internet_facing: bool,
        business_criticality: str,
        is_production: bool = True,
        has_compensating_control: bool = False,
        sla_breached: bool = False
    ) -> Dict[str, Any]:
        """
        Dynamic Business Risk Algorithm:
        Business Risk (0-100) = (CVSS * 5) + (Exposure Weight) + (Criticality Weight) + (SLA Penalty) - (Compensating Control Bonus)
        """
        base_score = min(cvss * 5.5, 55.0)  # up to 55 points
        
        # Exposure modifier
        exposure_points = 20.0 if is_internet_facing else 5.0
        
        # Criticality modifier
        crit_weights = {"CRITICAL": 20.0, "HIGH": 14.0, "MEDIUM": 8.0, "LOW": 2.0}
        criticality_points = crit_weights.get(business_criticality.upper(), 8.0)
        
        # Production multiplier
        prod_multiplier = 1.0 if is_production else 0.5
        
        # SLA Penalty
        sla_penalty = 15.0 if sla_breached else 0.0
        
        # Compensating Control Reduction
        mitigation_discount = 25.0 if has_compensating_control else 0.0
        
        total_risk = max(0.0, min(100.0, ((base_score + exposure_points + criticality_points) * prod_multiplier + sla_penalty) - mitigation_discount))
        
        if total_risk >= 80.0:
            risk_level = "CRITICAL"
        elif total_risk >= 60.0:
            risk_level = "HIGH"
        elif total_risk >= 30.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        return {
            "business_risk_score": round(total_risk, 1),
            "business_risk_level": risk_level,
            "technical_severity": severity,
            "cvss": cvss,
            "is_internet_facing": is_internet_facing,
            "business_criticality": business_criticality,
            "compensating_control_active": has_compensating_control,
            "sla_breached": sla_breached,
        }

    @classmethod
    def compute_finding_fingerprint(
        cls,
        source: str,
        asset_or_repo: str,
        file_or_endpoint: str,
        vulnerability_type_or_cwe: str
    ) -> str:
        """Computes deterministic SHA-256 fingerprint for intelligent finding deduplication."""
        raw_key = f"{source.strip().lower()}|{asset_or_repo.strip().lower()}|{file_or_endpoint.strip().lower()}|{vulnerability_type_or_cwe.strip().lower()}"
        return hashlib.sha256(raw_key.encode()).hexdigest()

    @classmethod
    def get_correlation_matrix(cls) -> Dict[str, Any]:
        """Returns multi-plane correlation map and active business risks."""
        return {
            "correlated_chains": cls.SAMPLE_CORRELATED_CHAINS,
            "risk_acceptance_registry": cls.RISK_ACCEPTANCE_REGISTRY,
            "total_correlated_entities": 48,
            "critical_business_risks": 0,
            "high_business_risks": 2,
            "medium_business_risks": 8,
            "low_business_risks": 38,
            "average_risk_score": 24.5,
            "active_risk_acceptances": len(cls.RISK_ACCEPTANCE_REGISTRY),
        }
