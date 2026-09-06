"""
Grafana Analytics & Honeypot Correlation Router — API Endpoints
"""
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession
from app.models_honeypot import HoneypotTrap, HoneypotEvent, GrafanaCorrelationNode, GrafanaCorrelationEdge
from app.services.honeypot_service import HoneypotService
from app.services.grafana_correlation_service import GrafanaCorrelationService

router = APIRouter()


class AttackSimulationRequest(BaseModel):
    trap_id: Optional[str] = None


@router.post("/seed-demo")
async def seed_demo(current_user: CurrentUser, db: DbSession):
    """Populates initial enterprise demo data for Honeypots and Grafana Correlation Graph."""
    await HoneypotService.seed_honeypot_data(db)
    return await GrafanaCorrelationService.seed_correlation_graph(db)


@router.get("/overview")
async def get_overview(current_user: CurrentUser, db: DbSession):
    """Returns Grafana correlation summary and Prometheus metrics."""
    return await GrafanaCorrelationService.get_grafana_dashboard_data(db)


@router.get("/dashboards")
async def get_dashboards(current_user: CurrentUser, db: DbSession):
    """Returns Grafana panel configurations and live metrics."""
    return await GrafanaCorrelationService.get_grafana_dashboard_data(db)


@router.get("/attack-graph")
async def get_attack_graph(current_user: CurrentUser, db: DbSession):
    """Returns graph nodes and edges highlighting the #1 Most Critical Attack Vector."""
    return await GrafanaCorrelationService.get_attack_graph(db)


@router.get("/honeypot/traps")
async def get_honeypot_traps(current_user: CurrentUser, db: DbSession):
    """Returns list of active Honeypot decoy traps."""
    await HoneypotService.seed_honeypot_data(db)
    result = await db.execute(select(HoneypotTrap))
    traps = result.scalars().all()
    return [
        {
            "id": t.id,
            "name": t.name,
            "trap_type": t.trap_type,
            "port": t.port,
            "target_server_ip": t.target_server_ip,
            "hostname": t.hostname,
            "status": t.status,
            "hits_count": t.hits_count,
            "created_at": t.created_at.isoformat() if t.created_at else None
        }
        for t in traps
    ]


@router.get("/honeypot/events")
async def get_honeypot_events(current_user: CurrentUser, db: DbSession, limit: int = 100):
    """Returns live log of attacker interactions captured on Honeypot traps."""
    await HoneypotService.seed_honeypot_data(db)
    result = await db.execute(select(HoneypotEvent).order_by(HoneypotEvent.timestamp.desc()).limit(limit))
    events = result.scalars().all()
    return [
        {
            "id": e.id,
            "trap_name": e.trap_name,
            "attacker_ip": e.attacker_ip,
            "attacker_country": e.attacker_country,
            "port": e.port,
            "severity": e.severity,
            "attempted_credentials": e.attempted_credentials,
            "payload_sample": e.payload_sample,
            "interaction_type": e.interaction_type,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None
        }
        for e in events
    ]


@router.post("/honeypot/simulate-attack")
async def simulate_attack(payload: AttackSimulationRequest, current_user: CurrentUser, db: DbSession):
    """Simulates an attacker hitting a Honeypot trap in real time."""
    return await HoneypotService.simulate_attack(db, payload.trap_id)


class RemoteHoneypotReportRequest(BaseModel):
    trap_name: str
    attacker_ip: str
    payload_sample: str
    protocol: Optional[str] = "TCP"
    port: Optional[int] = 2222
    country: Optional[str] = "Unknown"


@router.post("/honeypot/report")
async def report_remote_honeypot_attack(payload: RemoteHoneypotReportRequest, db: DbSession):
    """Receives real-time attack reports from remote Honeypot agent daemons deployed on external servers."""
    return await HoneypotService.record_remote_attack(
        db,
        trap_name=payload.trap_name,
        attacker_ip=payload.attacker_ip,
        payload_sample=payload.payload_sample,
        protocol=payload.protocol or "TCP",
        port=payload.port or 2222,
        country=payload.country or "Unknown"
    )



@router.get("/metrics")
async def get_prometheus_metrics(current_user: CurrentUser, db: DbSession):
    """Returns raw Prometheus metric exporter strings for Grafana."""
    return {
        "prometheus_metrics_raw": """
# HELP honeypot_attacks_total Total number of honeypot decoy hits captured
# TYPE honeypot_attacks_total counter
honeypot_attacks_total{trap="SSH Decoy",port="2222"} 450
honeypot_attacks_total{trap="Fake Admin Portal",port="8080"} 1280
honeypot_attacks_total{trap="Redis Trap",port="6379"} 310

# HELP ebpf_flow_volume_bytes Total bytes monitored by eBPF
# TYPE ebpf_flow_volume_bytes counter
ebpf_flow_volume_bytes{zone="DMZ"} 1420500000

# HELP morfeuxdr_critical_incidents Active critical correlated incidents
# TYPE morfeuxdr_critical_incidents gauge
morfeuxdr_critical_incidents 1
"""
    }
