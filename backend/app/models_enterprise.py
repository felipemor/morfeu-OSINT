"""
SQLAlchemy Models — Enterprise Posture Management Extensions (ASPM, GRC/Compliance, Connectors, Risk Acceptance, Snapshots)
"""
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Optional, List, Any

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Integer, String, Text,
    func, Enum, JSON
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def gen_uuid() -> str:
    return str(uuid.uuid4())


# ─── Enums ────────────────────────────────────────────────────────────────────

class ConnectorType(str, PyEnum):
    CHECKMARX = "CHECKMARX"
    GITHUB_ADVANCED_SECURITY = "GITHUB_ADVANCED_SECURITY"
    MICROSOFT_DEFENDER = "MICROSOFT_DEFENDER"
    SNYK = "SNYK"
    VERACODE = "VERACODE"
    AKAMAI_WAF = "AKAMAI_WAF"
    CROWDSTRIKE = "CROWDSTRIKE"
    AWS_SECURITY_HUB = "AWS_SECURITY_HUB"
    SPLUNK = "SPLUNK"
    JIRA = "JIRA"


class ConnectorStatus(str, PyEnum):
    CONNECTED = "CONNECTED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    SYNCING = "SYNCING"
    ERROR = "ERROR"
    DISABLED = "DISABLED"


class QualityGateStatus(str, PyEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"
    NOT_EVALUATED = "NOT_EVALUATED"


class ComplianceFrameworkCode(str, PyEnum):
    BACEN_4893 = "BACEN_4893"
    PCI_DSS_V4 = "PCI_DSS_V4"
    CIS_CONTROLS_V8 = "CIS_CONTROLS_V8"
    NIST_CSF_V2 = "NIST_CSF_V2"
    ISO_27001 = "ISO_27001"
    OWASP_TOP10 = "OWASP_TOP10"
    OWASP_API = "OWASP_API"
    MITRE_ATTACK = "MITRE_ATTACK"


class ControlStatus(str, PyEnum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    DRIFT_DETECTED = "DRIFT_DETECTED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RiskAcceptanceStatus(str, PyEnum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


# ─── Application & Repository Mapping ──────────────────────────────────────────

class BusinessApplication(Base):
    __tablename__ = "business_applications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    business_unit: Mapped[str] = mapped_column(String(100), nullable=False, default="Digital Banking")
    department: Mapped[str] = mapped_column(String(100), default="Engineering")
    squad: Mapped[str] = mapped_column(String(100), default="Core Squad")
    business_owner: Mapped[str] = mapped_column(String(255), nullable=False)
    tech_owner: Mapped[str] = mapped_column(String(255), nullable=False)
    criticality: Mapped[str] = mapped_column(String(20), default="CRITICAL")  # CRITICAL, HIGH, MEDIUM, LOW
    data_classification: Mapped[str] = mapped_column(String(50), default="CONFIDENTIAL")
    is_internet_facing: Mapped[bool] = mapped_column(Boolean, default=True)
    quality_gate_status: Mapped[QualityGateStatus] = mapped_column(Enum(QualityGateStatus), default=QualityGateStatus.PASSED)
    appsec_score: Mapped[float] = mapped_column(Float, default=88.5)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class CodeRepository(Base):
    __tablename__ = "code_repositories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("business_applications.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(String(512), nullable=False)
    default_branch: Mapped[str] = mapped_column(String(64), default="main")
    primary_language: Mapped[str] = mapped_column(String(50), default="TypeScript")
    quality_gate_status: Mapped[QualityGateStatus] = mapped_column(Enum(QualityGateStatus), default=QualityGateStatus.PASSED)
    sast_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    sca_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    secret_scanning_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    open_critical_findings: Mapped[int] = mapped_column(Integer, default=0)
    open_high_findings: Mapped[int] = mapped_column(Integer, default=0)
    open_medium_findings: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─── Integration Connectors ───────────────────────────────────────────────────

class IntegrationConnector(Base):
    __tablename__ = "integration_connectors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    connector_type: Mapped[ConnectorType] = mapped_column(Enum(ConnectorType), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[ConnectorStatus] = mapped_column(Enum(ConnectorStatus), default=ConnectorStatus.NOT_CONFIGURED)
    endpoint_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    auth_type: Mapped[str] = mapped_column(String(50), default="API_TOKEN")  # API_TOKEN, OAUTH2, MTLS
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    sync_interval_minutes: Mapped[int] = mapped_column(Integer, default=60)
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_status: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    last_error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    records_ingested: Mapped[int] = mapped_column(Integer, default=0)
    configuration_json: Mapped[dict] = mapped_column(JSON, default=dict)
    health_metrics: Mapped[dict] = mapped_column(JSON, default=lambda: {"latency_ms": 0, "error_count_24h": 0, "success_rate": 100.0})
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


# ─── Central Control Catalog & Compliance ──────────────────────────────────────

class EnterpriseSecurityControl(Base):
    __tablename__ = "enterprise_security_controls"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    control_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)  # CTRL-WAF-001, CTRL-TLS-001, etc.
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)  # WAF, TLS, DNS, IAM, APPSEC, VULN, LOG, IR, CRYPTO
    description: Mapped[str] = mapped_column(Text, nullable=False)
    frameworks: Mapped[list] = mapped_column(JSON, default=list)  # ["BACEN_4893", "PCI_DSS_V4", "CIS_CONTROLS_V8", "ISO_27001"]
    test_method: Mapped[str] = mapped_column(String(100), default="AUTOMATED_VALIDATION")  # AUTOMATED_VALIDATION, AGENT_CHECK, AUDIT_REVIEW
    frequency: Mapped[str] = mapped_column(String(50), default="CONTINUOUS")  # CONTINUOUS, DAILY, WEEKLY, MONTHLY
    owner: Mapped[str] = mapped_column(String(255), default="SecOps / AppSec Team")
    status: Mapped[ControlStatus] = mapped_column(Enum(ControlStatus), default=ControlStatus.COMPLIANT)
    drift_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    last_evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class ComplianceRequirement(Base):
    __tablename__ = "compliance_requirements"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    framework: Mapped[ComplianceFrameworkCode] = mapped_column(Enum(ComplianceFrameworkCode), nullable=False)
    requirement_code: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # e.g., "BACEN-Art-3-I", "PCI-Req-6.4"
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    section: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    control_ids: Mapped[list] = mapped_column(JSON, default=list)  # ["CTRL-WAF-001", "CTRL-TLS-001"]
    status: Mapped[ControlStatus] = mapped_column(Enum(ControlStatus), default=ControlStatus.COMPLIANT)
    compliance_score: Mapped[float] = mapped_column(Float, default=95.0)


# ─── Risk Acceptance Workflow ─────────────────────────────────────────────────

class RiskAcceptanceRequest(Base):
    __tablename__ = "risk_acceptance_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), nullable=False)
    requested_by_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    business_justification: Mapped[str] = mapped_column(Text, nullable=False)
    compensating_control: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[RiskAcceptanceStatus] = mapped_column(Enum(RiskAcceptanceStatus), default=RiskAcceptanceStatus.PENDING_APPROVAL)
    approver_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    approver_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    expiration_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


# ─── Executive Data Mart & Snapshots ──────────────────────────────────────────

class SecurityMonthlySnapshot(Base):
    __tablename__ = "security_monthly_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    period: Mapped[str] = mapped_column(String(7), nullable=False, index=True)  # e.g. "2026-08", "2026-09"
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    health_score: Mapped[float] = mapped_column(Float, default=87.0)
    risk_score: Mapped[float] = mapped_column(Float, default=24.5)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0)
    high_findings: Mapped[int] = mapped_column(Integer, default=0)
    medium_findings: Mapped[int] = mapped_column(Integer, default=0)
    low_findings: Mapped[int] = mapped_column(Integer, default=0)
    total_assets: Mapped[int] = mapped_column(Integer, default=0)
    internet_facing_assets: Mapped[int] = mapped_column(Integer, default=0)
    sla_compliance_rate: Mapped[float] = mapped_column(Float, default=94.5)
    average_mttr_days: Mapped[float] = mapped_column(Float, default=4.2)
    controls_coverage_pct: Mapped[float] = mapped_column(Float, default=96.0)
    appsec_maturity_score: Mapped[float] = mapped_column(Float, default=91.0)
    cloud_posture_score: Mapped[float] = mapped_column(Float, default=89.5)
    compliance_score_bacen: Mapped[float] = mapped_column(Float, default=98.0)
    compliance_score_pci: Mapped[float] = mapped_column(Float, default=95.0)
    compliance_score_cis: Mapped[float] = mapped_column(Float, default=94.0)
    drift_events_count: Mapped[int] = mapped_column(Integer, default=0)
    executive_narrative: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
