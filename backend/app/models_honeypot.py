"""
SQLAlchemy Models for Grafana Security Operations & Honeypot Decoy Engine
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


# Enums for Honeypot & Grafana Correlation

class HoneypotTrapType(str, PyEnum):
    SSH_DECOY = "SSH_DECOY"
    HTTP_ADMIN_PORTAL = "HTTP_ADMIN_PORTAL"
    REDIS_CLUSTER_DECOY = "REDIS_CLUSTER_DECOY"
    TELNET_TRAP = "TELNET_TRAP"
    MYSQL_DECOY = "MYSQL_DECOY"


class HoneypotSeverity(str, PyEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Models

class HoneypotTrap(Base):
    __tablename__ = "honeypot_traps"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    trap_type: Mapped[str] = mapped_column(String(50), default=HoneypotTrapType.SSH_DECOY.value)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    target_server_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    hostname: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")  # ACTIVE, PAUSED, TRIGGERED
    hits_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class HoneypotEvent(Base):
    __tablename__ = "honeypot_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    trap_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("honeypot_traps.id"), nullable=True)
    trap_name: Mapped[str] = mapped_column(String(100), nullable=False)
    attacker_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    attacker_country: Mapped[Optional[str]] = mapped_column(String(50), default="Unknown")
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default=HoneypotSeverity.HIGH.value)
    attempted_credentials: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    payload_sample: Mapped[Optional[Text]] = mapped_column(Text, nullable=True)
    interaction_type: Mapped[str] = mapped_column(String(50), default="BRUTE_FORCE_ATTEMPT")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class GrafanaCorrelationNode(Base):
    __tablename__ = "grafana_correlation_nodes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    label: Mapped[str] = mapped_column(String(150), nullable=False)
    node_type: Mapped[str] = mapped_column(String(50), nullable=False)  # PENTEST_VULN, EBPF_FLOW, WAZUH_ALERT, HONEYPOT_TRAP, CRITICAL_ASSET
    risk_score: Mapped[float] = mapped_column(Float, default=50.0)
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    is_critical_vector: Mapped[bool] = mapped_column(Boolean, default=False)
    details: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GrafanaCorrelationEdge(Base):
    __tablename__ = "grafana_correlation_edges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    source_node_id: Mapped[str] = mapped_column(String(36), ForeignKey("grafana_correlation_nodes.id"), nullable=False)
    target_node_id: Mapped[str] = mapped_column(String(36), ForeignKey("grafana_correlation_nodes.id"), nullable=False)
    relation_label: Mapped[str] = mapped_column(String(100), nullable=False)
    is_critical_path: Mapped[bool] = mapped_column(Boolean, default=False)
    protocol_port: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
