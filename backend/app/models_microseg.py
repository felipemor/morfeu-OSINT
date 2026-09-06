"""
SQLAlchemy Models for Hybrid Microsegmentation & Zero Trust Module
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


# Enums for Microsegmentation

class MicroAssetType(str, PyEnum):
    K8S_POD = "K8S_POD"
    VM_LINUX = "VM_LINUX"
    VM_WINDOWS = "VM_WINDOWS"
    CONTAINER = "CONTAINER"
    CLOUD_DB = "CLOUD_DB"
    BARE_METAL = "BARE_METAL"
    LAMBDA_FUNC = "LAMBDA_FUNC"
    LOAD_BALANCER = "LOAD_BALANCER"


class MicroFlowAction(str, PyEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    DROPPED = "DROPPED"
    VIOLATION = "VIOLATION"


class MicroPolicyStatus(str, PyEnum):
    DRAFT = "DRAFT"
    SIMULATION = "SIMULATION"
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"


class MicroEnforcementMode(str, PyEnum):
    MONITORING = "MONITORING"
    ENFORCING = "ENFORCING"
    AUDIT = "AUDIT"


class MicroRiskLevel(str, PyEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Models

class MicroSegmentationZone(Base):
    __tablename__ = "micro_segmentation_zones"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    color: Mapped[str] = mapped_column(String(20), default="#00d4ff")
    strictness_level: Mapped[str] = mapped_column(String(20), default="STRICT")  # STRICT, MODERATE, PERMISSIVE
    default_action: Mapped[str] = mapped_column(String(20), default="DENY")
    icon: Mapped[Optional[str]] = mapped_column(String(50), default="Shield")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class MicroAsset(Base):
    __tablename__ = "micro_assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(String(30), default=MicroAssetType.K8S_POD.value)
    zone_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("micro_segmentation_zones.id"), nullable=True)
    namespace: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    labels: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    os_info: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="HEALTHY")  # HEALTHY, WARNING, CRITICAL, ISOLATED
    risk_score: Mapped[float] = mapped_column(Float, default=15.0)
    agent_installed: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MicroNetworkFlow(Base):
    __tablename__ = "micro_network_flows"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    source_asset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("micro_assets.id"), nullable=True)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_name: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    destination_asset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("micro_assets.id"), nullable=True)
    destination_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    destination_name: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(20), default="TCP")
    action: Mapped[str] = mapped_column(String(20), default=MicroFlowAction.ALLOW.value)
    byte_count: Mapped[int] = mapped_column(Integer, default=1024)
    packet_count: Mapped[int] = mapped_column(Integer, default=12)
    process_name: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    telemetry_source: Mapped[str] = mapped_column(String(50), default="Hubble eBPF")
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class MicroNetworkPolicy(Base):
    __tablename__ = "micro_network_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_zone_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("micro_segmentation_zones.id"), nullable=True)
    source_selector: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    destination_zone_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("micro_segmentation_zones.id"), nullable=True)
    destination_selector: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    port_range: Mapped[str] = mapped_column(String(50), default="443")
    protocol: Mapped[str] = mapped_column(String(20), default="TCP")
    action: Mapped[str] = mapped_column(String(20), default="ALLOW")  # ALLOW, DENY, AUDIT
    status: Mapped[str] = mapped_column(String(20), default=MicroPolicyStatus.ACTIVE.value)
    enforcement_mode: Mapped[str] = mapped_column(String(20), default=MicroEnforcementMode.MONITORING.value)
    auto_generated: Mapped[bool] = mapped_column(Boolean, default=False)
    ai_recommendation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    yaml_config: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hits_count: Mapped[int] = mapped_column(Integer, default=0)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class MicroPolicyVersion(Base):
    __tablename__ = "micro_policy_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    policy_id: Mapped[str] = mapped_column(String(36), ForeignKey("micro_network_policies.id"), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    yaml_snapshot: Mapped[str] = mapped_column(Text, nullable=False)
    changed_by: Mapped[Optional[str]] = mapped_column(String(100), default="System AI")
    change_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MicroAttackPath(Base):
    __tablename__ = "micro_attack_paths"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    risk_level: Mapped[str] = mapped_column(String(20), default=MicroRiskLevel.HIGH.value)
    entry_point_asset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("micro_assets.id"), nullable=True)
    target_asset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("micro_assets.id"), nullable=True)
    hops: Mapped[list] = mapped_column(JSON, default=list)  # List of asset node hops
    vulnerability_finding_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")  # ACTIVE, MITIGATED, SIMULATED
    mitigation_policy_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("micro_network_policies.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MicroSecurityAlert(Base):
    __tablename__ = "micro_security_alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default=MicroRiskLevel.HIGH.value)
    flow_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("micro_network_flows.id"), nullable=True)
    source_asset_name: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    destination_asset_name: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    violating_policy_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("micro_network_policies.id"), nullable=True)
    description: Mapped[Text] = mapped_column(Text, nullable=False)
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MicroTelemetrySource(Base):
    __tablename__ = "micro_telemetry_sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)  # HUBBLE_EBPF, VPC_FLOW_LOGS, AGENT_COLLECTOR, MOCK_DEMO
    status: Mapped[str] = mapped_column(String(20), default="CONNECTED")  # CONNECTED, DISCONNECTED, DEGRADED
    endpoint_url: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    events_per_second: Mapped[int] = mapped_column(Integer, default=450)
    last_heartbeat: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
