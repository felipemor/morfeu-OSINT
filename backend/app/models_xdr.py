"""
SQLAlchemy Models for MorfeuXDR — Extended Detection & Response Platform (Wazuh Engine)
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


# Enums for MorfeuXDR

class XDRSeverity(str, PyEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class XDRFindingStatus(str, PyEnum):
    NEW = "NEW"
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    MITIGATED = "MITIGATED"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class XDRIncidentStatus(str, PyEnum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class XDRAgentStatus(str, PyEnum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    DISCONNECTED = "DISCONNECTED"
    NEVER_CONNECTED = "NEVER_CONNECTED"


# Models

class XDRSecurityPosture(Base):
    __tablename__ = "xdr_security_posture"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    overall_score: Mapped[float] = mapped_column(Float, default=87.0)
    threat_detection_score: Mapped[float] = mapped_column(Float, default=85.0)
    endpoint_security_score: Mapped[float] = mapped_column(Float, default=90.0)
    vulnerability_score: Mapped[float] = mapped_column(Float, default=78.0)
    configuration_score: Mapped[float] = mapped_column(Float, default=88.0)
    identity_score: Mapped[float] = mapped_column(Float, default=92.0)
    compliance_score: Mapped[float] = mapped_column(Float, default=89.0)
    incident_response_score: Mapped[float] = mapped_column(Float, default=94.0)
    agent_health_score: Mapped[float] = mapped_column(Float, default=95.0)
    detection_coverage_score: Mapped[float] = mapped_column(Float, default=86.0)
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class XDRAgent(Base):
    __tablename__ = "xdr_agents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    wazuh_agent_id: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    os_name: Mapped[str] = mapped_column(String(100), default="Linux")
    os_platform: Mapped[str] = mapped_column(String(50), default="ubuntu")
    os_version: Mapped[str] = mapped_column(String(50), default="22.04 LTS")
    version: Mapped[str] = mapped_column(String(50), default="v4.8.0")
    status: Mapped[str] = mapped_column(String(20), default=XDRAgentStatus.ONLINE.value)
    node_name: Mapped[Optional[str]] = mapped_column(String(100), default="wazuh-manager-01")
    group_name: Mapped[Optional[str]] = mapped_column(String(100), default="default")
    risk_score: Mapped[float] = mapped_column(Float, default=12.0)
    vulnerabilities_count: Mapped[int] = mapped_column(Integer, default=2)
    last_keepalive: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class XDRCorrelation(Base):
    __tablename__ = "xdr_correlations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(150), nullable=False)
    events_count: Mapped[int] = mapped_column(Integer, default=1)
    risk_score: Mapped[float] = mapped_column(Float, default=75.0)
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class XDRIncident(Base):
    __tablename__ = "xdr_incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    incident_number: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Text] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default=XDRSeverity.HIGH.value)
    risk_score: Mapped[float] = mapped_column(Float, default=88.0)
    status: Mapped[str] = mapped_column(String(20), default=XDRIncidentStatus.OPEN.value)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("xdr_correlations.correlation_id"), nullable=True)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(100), default="SOC Tier 2 Team")
    impacted_assets_count: Mapped[int] = mapped_column(Integer, default=1)
    mitre_techniques: Mapped[Optional[dict]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class XDRFinding(Base):
    __tablename__ = "xdr_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    finding_number: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Text] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default=XDRSeverity.HIGH.value)
    risk_score: Mapped[float] = mapped_column(Float, default=78.5)
    status: Mapped[str] = mapped_column(String(20), default=XDRFindingStatus.NEW.value)
    confidence: Mapped[float] = mapped_column(Float, default=90.0)

    # Source & Engine Data
    source_product: Mapped[str] = mapped_column(String(50), default="Wazuh SIEM/XDR Engine")
    source_rule: Mapped[str] = mapped_column(String(150), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    rule_level: Mapped[int] = mapped_column(Integer, default=12)

    # Agent & Asset
    agent_id: Mapped[Optional[str]] = mapped_column(String(50), index=True)
    hostname: Mapped[str] = mapped_column(String(150), nullable=False, index=True)
    ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    os: Mapped[Optional[str]] = mapped_column(String(100), default="Linux Ubuntu 22.04")

    # Threat Entities
    username: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    process: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    parent_process: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    command_line: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Network Entities
    src_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Threat Intelligence
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    cve: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)

    # Correlation & Links
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("xdr_correlations.correlation_id"), nullable=True)
    incident_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("xdr_incidents.id"), nullable=True)

    # Evidence & Raw Data
    evidence: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    raw_event: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)

    # Governance & SLA
    assigned_to: Mapped[Optional[str]] = mapped_column(String(100), default="Analista SOC")
    sla_deadline: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    suppression_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class XDREntity(Base):
    __tablename__ = "xdr_entities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String(150), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)  # USER, HOST, PROCESS, IP, HASH, DOMAIN
    risk_score: Mapped[float] = mapped_column(Float, default=20.0)
    related_findings_count: Mapped[int] = mapped_column(Integer, default=1)
    details: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class XDRAuditLog(Base):
    __tablename__ = "xdr_audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    actor: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    action_category: Mapped[str] = mapped_column(String(50), default="FINDING_MUTATION")
    finding_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("xdr_findings.id"), nullable=True)
    incident_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("xdr_incidents.id"), nullable=True)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    before_state: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    after_state: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    result: Mapped[str] = mapped_column(String(20), default="SUCCESS")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
