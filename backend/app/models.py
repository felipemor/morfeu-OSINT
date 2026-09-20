"""
SQLAlchemy Models — all database entities for V2 AI Autonomous Security Validation Platform
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

class UserRole(str, PyEnum):
    ADMIN = "ADMIN"
    SECURITY_MANAGER = "SECURITY_MANAGER"
    PENTESTER = "PENTESTER"
    ANALYST = "ANALYST"
    AUDITOR = "AUDITOR"
    READONLY = "READONLY"


class ProjectStatus(str, PyEnum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    SCANNING = "SCANNING"
    COMPLETED = "COMPLETED"
    PAUSED = "PAUSED"
    ARCHIVED = "ARCHIVED"


class ScanMode(str, PyEnum):
    PASSIVE = "PASSIVE"
    SAFE_ACTIVE = "SAFE_ACTIVE"
    AUTHORIZED_ADVERSARY = "AUTHORIZED_ADVERSARY"


class ScanStatus(str, PyEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    KILLED = "KILLED"
    PAUSED = "PAUSED"


class Severity(str, PyEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, PyEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RETEST_PENDING = "RETEST_PENDING"
    FIXED = "FIXED"
    ACCEPTED = "ACCEPTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    VALIDATING = "VALIDATING"
    CONFIRMED = "CONFIRMED"
    REPORTED = "REPORTED"
    REMEDIATION = "REMEDIATION"
    RETEST = "RETEST"
    RESOLVED = "RESOLVED"
    DUPLICATE = "DUPLICATE"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    MITIGATED = "MITIGATED"


class AssetType(str, PyEnum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP = "IP"
    URL = "URL"
    API_ENDPOINT = "API_ENDPOINT"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    APPLICATION = "APPLICATION"
    ENDPOINT = "ENDPOINT"
    SERVER = "SERVER"
    WORKSTATION = "WORKSTATION"


class TargetType(str, PyEnum):
    DOMAIN = "DOMAIN"
    IP = "IP"
    CIDR = "CIDR"
    URL = "URL"
    API = "API"
    ENDPOINT = "ENDPOINT"


class BusinessCriticality(str, PyEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AgentType(str, PyEnum):
    ORCHESTRATOR = "ORCHESTRATOR"
    RECON = "RECON"
    WEB_CRAWLER = "WEB_CRAWLER"
    VULNERABILITY = "VULNERABILITY"
    SCREENSHOT = "SCREENSHOT"
    REPORT = "REPORT"
    LLM_PLANNER = "LLM_PLANNER"
    API_AGENT = "API_AGENT"
    BROWSER_AGENT = "BROWSER_AGENT"
    VALIDATION_AGENT = "VALIDATION_AGENT"
    EVIDENCE_AGENT = "EVIDENCE_AGENT"
    AUTH_AGENT = "AUTH_AGENT"
    ENDPOINT_AGENT = "ENDPOINT_AGENT"


class AgentStatus(str, PyEnum):
    PENDING = "PENDING"
    ENROLLING = "ENROLLING"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    REVOKED = "REVOKED"
    UPDATING = "UPDATING"
    ERROR = "ERROR"


class CampaignType(str, PyEnum):
    WEB_ASSESSMENT = "WEB_ASSESSMENT"
    API_ASSESSMENT = "API_ASSESSMENT"
    ENDPOINT_ASSESSMENT = "ENDPOINT_ASSESSMENT"
    FULL_SECURITY_VALIDATION = "FULL_SECURITY_VALIDATION"
    CONTINUOUS_VALIDATION = "CONTINUOUS_VALIDATION"


class TaskStatus(str, PyEnum):
    PENDING = "PENDING"
    SENT = "SENT"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class TaskResultStatus(str, PyEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


class ReportType(str, PyEnum):
    TECHNICAL = "TECHNICAL"
    EXECUTIVE = "EXECUTIVE"
    COMPLIANCE = "COMPLIANCE"
    AUDIT = "AUDIT"
    RETEST = "RETEST"


class ReportFormat(str, PyEnum):
    PDF = "PDF"
    HTML = "HTML"
    JSON = "JSON"
    CSV = "CSV"


class RetestStatus(str, PyEnum):
    FIXED = "FIXED"
    NOT_FIXED = "NOT_FIXED"
    INCONCLUSIVE = "INCONCLUSIVE"
    PARTIALLY_FIXED = "PARTIALLY_FIXED"


class DataClassification(str, PyEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    PII = "PII"


class ApprovalStatus(str, PyEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    EXECUTED = "EXECUTED"


class HypothesisStatus(str, PyEnum):
    PROPOSED = "PROPOSED"
    VALIDATING = "VALIDATING"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"


class PentestHubCategory(str, PyEnum):
    RECON = "RECON"
    VULN_SCAN = "VULN_SCAN"
    EXPLOIT = "EXPLOIT"
    WIRELESS = "WIRELESS"
    SOCIAL_ENG = "SOCIAL_ENG"
    MOBILE = "MOBILE"
    AI_ASSIST = "AI_ASSIST"


class HubJobStatus(str, PyEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


# ─── Core Models ──────────────────────────────────────────────────────────────

class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    risk_weights: Mapped[dict] = mapped_column(JSON, default=lambda: {
        "technical_risk": 1.0,
        "exploitability": 1.0,
        "asset_criticality": 1.5,
        "internet_exposure": 1.2,
        "business_impact": 1.5,
        "endpoint_posture": 1.2,
    })
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    organization_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), nullable=False, default=UserRole.ANALYST)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    organization_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    client: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    business_unit: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owner_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    status: Mapped[ProjectStatus] = mapped_column(Enum(ProjectStatus), default=ProjectStatus.DRAFT)
    start_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    end_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Scope(Base):
    __tablename__ = "scopes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False, unique=True)
    allowed_domains: Mapped[list] = mapped_column(JSON, default=list)
    allowed_ips: Mapped[list] = mapped_column(JSON, default=list)
    allowed_cidrs: Mapped[list] = mapped_column(JSON, default=list)
    allowed_urls: Mapped[list] = mapped_column(JSON, default=list)
    allowed_methods: Mapped[list] = mapped_column(JSON, default=lambda: ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    allowed_ports: Mapped[list] = mapped_column(JSON, default=lambda: [80, 443, 8000, 8080, 8443, 3000, 5000])
    environment: Mapped[str] = mapped_column(String(50), default="development")
    excluded_domains: Mapped[list] = mapped_column(JSON, default=list)
    excluded_ips: Mapped[list] = mapped_column(JSON, default=list)
    excluded_paths: Mapped[list] = mapped_column(JSON, default=list)
    max_requests_per_minute: Mapped[int] = mapped_column(Integer, default=30)
    max_concurrent_requests: Mapped[int] = mapped_column(Integer, default=5)
    execution_window_start: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    execution_window_end: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    authorized_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    authorization_document: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    allow_private_ips: Mapped[bool] = mapped_column(Boolean, default=False)
    scan_mode: Mapped[ScanMode] = mapped_column(Enum(ScanMode), default=ScanMode.PASSIVE)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    target_type: Mapped[TargetType] = mapped_column(Enum(TargetType), nullable=False)
    business_criticality: Mapped[BusinessCriticality] = mapped_column(Enum(BusinessCriticality), default=BusinessCriticality.MEDIUM)
    is_internet_facing: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    target_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("targets.id"), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("endpoint_agents.id"), nullable=True)
    asset_type: Mapped[AssetType] = mapped_column(Enum(AssetType), nullable=False, default=AssetType.DOMAIN)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    title: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    server: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    os_info: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    technologies: Mapped[list] = mapped_column(JSON, default=list)
    is_internet_facing: Mapped[bool] = mapped_column(Boolean, default=True)
    business_criticality: Mapped[BusinessCriticality] = mapped_column(Enum(BusinessCriticality), default=BusinessCriticality.MEDIUM)
    raw_headers: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    screenshot_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(String(10), default="GET")
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    parameters: Mapped[list] = mapped_column(JSON, default=list)
    headers: Mapped[dict] = mapped_column(JSON, default=dict)
    auth_required: Mapped[bool] = mapped_column(Boolean, default=False)
    auth_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    is_api: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─── Endpoint Agent Models (Lightweight Assessment Agent Architecture) ──────────────

class EndpointAgent(Base):
    __tablename__ = "endpoint_agents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    installation_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("assets.id"), nullable=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    platform: Mapped[str] = mapped_column(String(50), nullable=False)  # windows, linux, darwin
    architecture: Mapped[str] = mapped_column(String(20), default="x86_64")
    version: Mapped[str] = mapped_column(String(20), default="2.0.0")
    status: Mapped[AgentStatus] = mapped_column(Enum(AgentStatus), default=AgentStatus.PENDING)
    capabilities: Mapped[list] = mapped_column(JSON, default=lambda: [
        "inventory",
        "os_assessment",
        "patch_assessment",
        "firewall_assessment",
        "service_assessment",
        "network_assessment",
        "application_inventory",
        "security_controls",
    ])
    public_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    certificate_thumbprint: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    cpu_usage_pct: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    memory_usage_pct: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    disk_usage_pct: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    security_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # 0-100 endpoint posture score
    metadata_info: Mapped[dict] = mapped_column(JSON, default=dict)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentEnrollmentToken(Base):
    __tablename__ = "agent_enrollment_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    created_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    max_uses: Mapped[int] = mapped_column(Integer, default=1)
    use_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentGroup(Base):
    __tablename__ = "agent_groups"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)  # e.g., ["windows", "dmz", "production"]
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentGroupMember(Base):
    __tablename__ = "agent_group_members"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    group_id: Mapped[str] = mapped_column(String(36), ForeignKey("agent_groups.id"), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("endpoint_agents.id"), nullable=False)
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    campaign_type: Mapped[CampaignType] = mapped_column(Enum(CampaignType), default=CampaignType.FULL_SECURITY_VALIDATION)
    status: Mapped[str] = mapped_column(String(50), default="SCHEDULED")
    target_agent_groups: Mapped[list] = mapped_column(JSON, default=list)
    schedule_cron: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentTask(Base):
    __tablename__ = "agent_tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    campaign_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("campaigns.id"), nullable=True)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("endpoint_agents.id"), nullable=False)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    task_type: Mapped[str] = mapped_column(String(100), default="SECURITY_CHECK")
    check_id: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g., WIN-FW-001, LNX-PATCH-001
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[TaskStatus] = mapped_column(Enum(TaskStatus), default=TaskStatus.PENDING)
    signature: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    max_runtime_seconds: Mapped[int] = mapped_column(Integer, default=60)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentTaskResult(Base):
    __tablename__ = "agent_task_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    task_id: Mapped[str] = mapped_column(String(36), ForeignKey("agent_tasks.id"), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("endpoint_agents.id"), nullable=False)
    status: Mapped[TaskResultStatus] = mapped_column(Enum(TaskResultStatus), default=TaskResultStatus.PASS)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.INFO)
    evidence_data: Mapped[dict] = mapped_column(JSON, default=dict)
    raw_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EndpointBaseline(Base):
    __tablename__ = "endpoint_baselines"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("endpoint_agents.id"), nullable=False)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    baseline_data: Mapped[dict] = mapped_column(JSON, default=dict)  # OS, firewall, services, listening_ports, controls
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class SecurityDriftEvent(Base):
    __tablename__ = "security_drift_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("endpoint_agents.id"), nullable=False)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    drift_type: Mapped[str] = mapped_column(String(100), nullable=False)  # FIREWALL_DISABLED, NEW_LISTENING_PORT, NEW_SERVICE, EDR_DISABLED
    description: Mapped[str] = mapped_column(Text, nullable=False)
    previous_state: Mapped[dict] = mapped_column(JSON, default=dict)
    current_state: Mapped[dict] = mapped_column(JSON, default=dict)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.HIGH)
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─── Scans, Findings, Evidence & Reporting ────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    mode: Mapped[ScanMode] = mapped_column(Enum(ScanMode), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING)
    initiated_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    current_phase: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    assets_discovered: Mapped[int] = mapped_column(Integer, default=0)
    endpoints_found: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    hypotheses_count: Mapped[int] = mapped_column(Integer, default=0)
    blocked_requests_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    killed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentLog(Base):
    __tablename__ = "agent_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    agent_type: Mapped[AgentType] = mapped_column(Enum(AgentType), nullable=False)
    level: Mapped[str] = mapped_column(String(10), default="INFO")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    target: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    extra_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("scans.id"), nullable=True)
    endpoint_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("endpoints.id"), nullable=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("assets.id"), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("endpoint_agents.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.OPEN)
    owasp_category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    cwe_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    reproducibility: Mapped[Optional[str]] = mapped_column(String(50), default="HIGH")
    false_positive_probability: Mapped[Optional[float]] = mapped_column(Float, default=0.05)
    affected_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    affected_asset: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    parameter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    business_impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    technical_impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    exploitability: Mapped[Optional[str]] = mapped_column(String(50), default="MEDIUM")
    root_cause: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    steps_to_reproduce: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    developer_recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    architecture_recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    compensating_controls: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    references: Mapped[list] = mapped_column(JSON, default=list)
    compliance_tags: Mapped[dict] = mapped_column(JSON, default=dict)
    discovered_by: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    false_positive_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), nullable=False)
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("scans.id"), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("endpoint_agents.id"), nullable=True)
    parent_evidence_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    http_method: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    request_headers: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    request_body: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    response_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    response_headers: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    response_body: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    screenshot_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    screenshot_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    dom_snapshot: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    additional_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    data_classification: Mapped[DataClassification] = mapped_column(Enum(DataClassification), default=DataClassification.CONFIDENTIAL)
    evidence_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    integrity_verified: Mapped[bool] = mapped_column(Boolean, default=True)
    agent_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    test_executed: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Screenshot(Base):
    __tablename__ = "screenshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    finding_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("findings.id"), nullable=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("assets.id"), nullable=True)
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    taken_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SecurityHypothesis(Base):
    __tablename__ = "security_hypotheses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("scans.id"), nullable=True)
    hypothesis_code: Mapped[str] = mapped_column(String(20), nullable=False)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    reasoning: Mapped[list] = mapped_column(JSON, default=list)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    priority: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.MEDIUM)
    status: Mapped[HypothesisStatus] = mapped_column(Enum(HypothesisStatus), default=HypothesisStatus.PROPOSED)
    test_type: Mapped[str] = mapped_column(String(100), nullable=False)
    suggested_actions: Mapped[list] = mapped_column(JSON, default=list)
    result_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    finding_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("findings.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("scans.id"), nullable=True)
    requested_by: Mapped[str] = mapped_column(String(50), default="ai-planner")
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.MEDIUM)
    status: Mapped[ApprovalStatus] = mapped_column(Enum(ApprovalStatus), default=ApprovalStatus.PENDING)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    reviewed_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    decision_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class BlockedAction(Base):
    __tablename__ = "blocked_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("scans.id"), nullable=True)
    agent_type: Mapped[AgentType] = mapped_column(Enum(AgentType), nullable=False)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    policy_rule: Mapped[str] = mapped_column(String(100), nullable=False)
    initiator: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    report_type: Mapped[ReportType] = mapped_column(Enum(ReportType), nullable=False, default=ReportType.TECHNICAL)
    format: Mapped[ReportFormat] = mapped_column(Enum(ReportFormat), nullable=False, default=ReportFormat.PDF)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    file_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    file_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    generated_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    compliance_framework: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="GENERATING")
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class Retest(Base):
    __tablename__ = "retests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), nullable=False)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False)
    initiated_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    status: Mapped[Optional[RetestStatus]] = mapped_column(Enum(RetestStatus), nullable=True)
    scan_status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence_before: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    evidence_after: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    project_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    result: Mapped[str] = mapped_column(String(20), default="SUCCESS")
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), nullable=False, unique=True)
    total_score: Mapped[float] = mapped_column(Float, default=0.0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)
    false_positive_count: Mapped[int] = mapped_column(Integer, default=0)
    coverage_percentage: Mapped[float] = mapped_column(Float, default=0.0)
    exploitability_weight: Mapped[float] = mapped_column(Float, default=1.0)
    impact_weight: Mapped[float] = mapped_column(Float, default=1.0)
    exposure_weight: Mapped[float] = mapped_column(Float, default=1.0)
    asset_criticality_weight: Mapped[float] = mapped_column(Float, default=1.0)
    business_impact_weight: Mapped[float] = mapped_column(Float, default=1.0)
    endpoint_posture_weight: Mapped[float] = mapped_column(Float, default=1.0)
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


# ─── Pentest Hub ───────────────────────────────────────────────────────────────

class HubJobResult(Base):
    """Tracks async tool executions from the Pentest Hub."""
    __tablename__ = "hub_job_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    category: Mapped[PentestHubCategory] = mapped_column(Enum(PentestHubCategory), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    target: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[HubJobStatus] = mapped_column(Enum(HubJobStatus), default=HubJobStatus.PENDING, nullable=False)
    raw_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    parsed_result: Mapped[dict] = mapped_column(JSON, default=dict)
    findings_registered: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    initiated_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─── EASM ──────────────────────────────────────────────────────────────────────

class EASMScanStatus(str, PyEnum):
    PENDING   = "PENDING"
    RUNNING   = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED    = "FAILED"


class EASMThreatLevel(str, PyEnum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class EASMScan(Base):
    """Tracks an EASM / dark-web reconnaissance job."""
    __tablename__ = "easm_scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), default="FULL")
    status: Mapped[EASMScanStatus] = mapped_column(Enum(EASMScanStatus), default=EASMScanStatus.PENDING)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)
    assets_found: Mapped[int] = mapped_column(Integer, default=0)
    dark_web_hits: Mapped[int] = mapped_column(Integer, default=0)
    initiated_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EASMDarkWebHit(Base):
    """A single dark-web or data-breach mention for a target."""
    __tablename__ = "easm_darkweb_hits"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("easm_scans.id"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    hit_type: Mapped[str] = mapped_column(String(50), nullable=False)
    data_summary: Mapped[str] = mapped_column(Text, nullable=True)
    raw_data: Mapped[dict] = mapped_column(JSON, default=dict)
    severity: Mapped[EASMThreatLevel] = mapped_column(Enum(EASMThreatLevel), default=EASMThreatLevel.HIGH)
    url: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─── AegisLattice ──────────────────────────────────────────────────────────────

class CryptoRiskLevel(str, PyEnum):
    QUANTUM_RESISTANT   = "QUANTUM_RESISTANT"
    HARVEST_NOW_DECRYPT = "HARVEST_NOW_DECRYPT"
    CRITICAL_VULNERABLE = "CRITICAL_VULNERABLE"
    UNKNOWN             = "UNKNOWN"


class AegisScanResult(Base):
    """TLS/crypto posture scan result for a single host."""
    __tablename__ = "aegis_scan_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    host: Mapped[str] = mapped_column(String(500), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=443)
    tls_version: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    cipher_suite: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    key_exchange: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    cert_algo: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    cert_key_bits: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    cert_not_after: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    risk_level: Mapped[CryptoRiskLevel] = mapped_column(Enum(CryptoRiskLevel), default=CryptoRiskLevel.UNKNOWN)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    cbom: Mapped[dict] = mapped_column(JSON, default=dict)
    pqc_supported: Mapped[bool] = mapped_column(Boolean, default=False)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    initiated_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)


# ─── Brand Protection & Financial Fraud ────────────────────────────────────────

class BrandAlertType(str, PyEnum):
    TYPOSQUATTING  = "TYPOSQUATTING"
    HOMOGLYPH      = "HOMOGLYPH"
    COMBOSQUATTING = "COMBOSQUATTING"
    PHISHING_PAGE  = "PHISHING_PAGE"
    AD_HIJACK      = "AD_HIJACK"
    FAKE_APP       = "FAKE_APP"


class BrandAlertStatus(str, PyEnum):
    OPEN     = "OPEN"
    REPORTED = "REPORTED"
    TAKEN_DOWN = "TAKEN_DOWN"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class BrandAlert(Base):
    """A suspicious domain or brand-abuse incident."""
    __tablename__ = "brand_alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    brand: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    suspicious_domain: Mapped[str] = mapped_column(String(500), nullable=False)
    alert_type: Mapped[BrandAlertType] = mapped_column(Enum(BrandAlertType), nullable=False)
    similarity_score: Mapped[float] = mapped_column(Float, default=0.0)
    screenshot_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    registrar: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    registered_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    hosting_provider: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[BrandAlertStatus] = mapped_column(Enum(BrandAlertStatus), default=BrandAlertStatus.OPEN)
    takedown_sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BoletoCheck(Base):
    """Result of a boleto validation request."""
    __tablename__ = "boleto_checks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    linha_digitavel: Mapped[str] = mapped_column(String(500), nullable=False)
    bank_code: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    bank_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    beneficiary_name: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    beneficiary_cnpj: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    amount: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    due_date: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    is_valid: Mapped[bool] = mapped_column(Boolean, default=True)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    fraud_indicators: Mapped[list] = mapped_column(JSON, default=list)
    verdict: Mapped[str] = mapped_column(String(20), default="OK")
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    checked_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)


class BINIncident(Base):
    """Detected BIN attack or card-testing event."""
    __tablename__ = "bin_incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    bin_prefix: Mapped[str] = mapped_column(String(8), nullable=False, index=True)
    bank_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    card_brand: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    attempts_per_minute: Mapped[float] = mapped_column(Float, default=0.0)
    decline_rate: Mapped[float] = mapped_column(Float, default=0.0)
    source_ips: Mapped[list] = mapped_column(JSON, default=list)
    merchants_affected: Mapped[list] = mapped_column(JSON, default=list)
    severity: Mapped[str] = mapped_column(String(20), default="HIGH")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    mitigation_applied: Mapped[str] = mapped_column(String(50), default="NONE")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


# ─── FISCAL FORENSIC AI ────────────────────────────────────────────────────────

class FiscalFindingSeverity(str, PyEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FiscalFindingStatus(str, PyEnum):
    OPEN = "OPEN"
    UNDER_REVIEW = "UNDER_REVIEW"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


class FiscalCaseStatus(str, PyEnum):
    OPEN = "OPEN"
    TRIAGE = "TRIAGE"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    EVIDENCE_COLLECTION = "EVIDENCE_COLLECTION"
    REVIEW = "REVIEW"
    CLOSED = "CLOSED"


class FiscalDataset(Base):
    """Uploaded fiscal/financial dataset with smart schema mapping and retention."""
    __tablename__ = "fiscal_datasets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, default=0)
    file_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    total_rows: Mapped[int] = mapped_column(Integer, default=0)
    valid_rows: Mapped[int] = mapped_column(Integer, default=0)
    total_financial_volume: Mapped[float] = mapped_column(Float, default=0.0)
    data_quality_score: Mapped[float] = mapped_column(Float, default=0.0)
    schema_mapping: Mapped[dict] = mapped_column(JSON, default=dict)
    quality_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(50), default="UPLOADED")  # UPLOADED, PROCESSING, AUDITED, FAILED
    retention_days: Mapped[int] = mapped_column(Integer, default=1825)  # 5 years default
    is_legal_hold: Mapped[bool] = mapped_column(Boolean, default=False)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    uploaded_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    audited_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class FiscalRecord(Base):
    """A single normalized transaction/invoice record."""
    __tablename__ = "fiscal_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    dataset_id: Mapped[str] = mapped_column(String(36), ForeignKey("fiscal_datasets.id"), nullable=False, index=True)
    row_index: Mapped[int] = mapped_column(Integer, nullable=False)
    invoice_number: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    invoice_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    amount: Mapped[float] = mapped_column(Float, default=0.0)
    supplier_tax_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, index=True)
    supplier_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    customer_tax_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, index=True)
    customer_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tax_icms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    tax_ipi: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    tax_iss: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    tax_pis: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    tax_cofins: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cfop: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    ncm: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    raw_data: Mapped[dict] = mapped_column(JSON, default=dict)
    normalized_data: Mapped[dict] = mapped_column(JSON, default=dict)
    is_valid: Mapped[bool] = mapped_column(Boolean, default=True)
    validation_flags: Mapped[list] = mapped_column(JSON, default=list)
    sha256_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FiscalEntity(Base):
    """Normalized counterparty (Company, Supplier, Customer, Bank Account)."""
    __tablename__ = "fiscal_entities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    dataset_id: Mapped[str] = mapped_column(String(36), ForeignKey("fiscal_datasets.id"), nullable=False, index=True)
    tax_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # Clean CNPJ/CPF
    entity_type: Mapped[str] = mapped_column(String(50), default="SUPPLIER")  # SUPPLIER, CUSTOMER, COMPANY
    canonical_name: Mapped[str] = mapped_column(String(255), nullable=False)
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    total_volume: Mapped[float] = mapped_column(Float, default=0.0)
    transaction_count: Mapped[int] = mapped_column(Integer, default=0)
    average_ticket: Mapped[float] = mapped_column(Float, default=0.0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    concentration_ratio: Mapped[float] = mapped_column(Float, default=0.0)
    relationships: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FiscalFinding(Base):
    """An analytical, non-accusatory forensic audit finding."""
    __tablename__ = "fiscal_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    dataset_id: Mapped[str] = mapped_column(String(36), ForeignKey("fiscal_datasets.id"), nullable=False, index=True)
    finding_code: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)  # DUPLICITY, ANOMALY, CONCENTRATION, TAX, TEMPORAL
    subcategory: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    severity: Mapped[FiscalFindingSeverity] = mapped_column(Enum(FiscalFindingSeverity), default=FiscalFindingSeverity.MEDIUM)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0 to 100
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0 to 100%
    financial_exposure: Mapped[float] = mapped_column(Float, default=0.0)
    affected_records_count: Mapped[int] = mapped_column(Integer, default=0)
    entities_involved: Mapped[list] = mapped_column(JSON, default=list)
    period_start: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    period_end: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    rule_triggered: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    model_triggered: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    ai_explanation: Mapped[dict] = mapped_column(JSON, default=dict)  # WHAT, WHY, HOW, WHEN, WHO, HOW_MUCH, EVIDENCE, RECOMMENDATION
    alternative_hypotheses: Mapped[list] = mapped_column(JSON, default=list)
    recommended_actions: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[FiscalFindingStatus] = mapped_column(Enum(FiscalFindingStatus), default=FiscalFindingStatus.OPEN)
    false_positive_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    sample_records: Mapped[list] = mapped_column(JSON, default=list)
    auditor_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reviewed_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class FiscalEvidence(Base):
    """Chain-of-custody evidence snippet with SHA-256 integrity hash."""
    __tablename__ = "fiscal_evidences"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    dataset_id: Mapped[str] = mapped_column(String(36), ForeignKey("fiscal_datasets.id"), nullable=False, index=True)
    finding_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("fiscal_findings.id"), nullable=True, index=True)
    record_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("fiscal_records.id"), nullable=True)
    row_number: Mapped[int] = mapped_column(Integer, nullable=False)
    original_snippet: Mapped[dict] = mapped_column(JSON, default=dict)
    normalized_snippet: Mapped[dict] = mapped_column(JSON, default=dict)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_file: Mapped[str] = mapped_column(String(255), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FiscalCase(Base):
    """Investigative audit case grouping multiple findings and counterparties."""
    __tablename__ = "fiscal_cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    case_number: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[FiscalCaseStatus] = mapped_column(Enum(FiscalCaseStatus), default=FiscalCaseStatus.OPEN)
    priority: Mapped[FiscalFindingSeverity] = mapped_column(Enum(FiscalFindingSeverity), default=FiscalFindingSeverity.HIGH)
    dataset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("fiscal_datasets.id"), nullable=True)
    assigned_auditor_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    financial_exposure: Mapped[float] = mapped_column(Float, default=0.0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    entities_involved: Mapped[list] = mapped_column(JSON, default=list)
    audit_notes: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class FiscalRule(Base):
    """Configurable audit rule definition with legal basis and thresholds."""
    __tablename__ = "fiscal_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    rule_code: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    condition_summary: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[FiscalFindingSeverity] = mapped_column(Enum(FiscalFindingSeverity), default=FiscalFindingSeverity.MEDIUM)
    threshold_value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    jurisdiction: Mapped[str] = mapped_column(String(50), default="BR")
    source_law: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # ex: Lei 5.172/66 CTN, RICMS, CPC 25
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[str] = mapped_column(String(20), default="1.0.0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FiscalAuditLog(Base):
    """Immutable forensic audit trail for all operations, queries, and case updates."""
    __tablename__ = "fiscal_audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    object_type: Mapped[str] = mapped_column(String(50), nullable=False)
    object_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ip_address: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

