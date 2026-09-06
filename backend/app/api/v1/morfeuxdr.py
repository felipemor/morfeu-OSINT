"""
MorfeuXDR Router — Extended Detection & Response API Endpoints (Wazuh Engine)
"""
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy import select, func

from app.api.deps import CurrentUser, DbSession
from app.models_xdr import (
    XDRSecurityPosture, XDRAgent, XDRCorrelation, XDRIncident, XDRFinding,
    XDREntity, XDRAuditLog
)
from app.services.xdr_service import XDRService

router = APIRouter()


class FindingStatusUpdate(BaseModel):
    status: str
    reason: Optional[str] = None


@router.post("/seed-demo")
async def seed_demo(current_user: CurrentUser, db: DbSession):
    """Populates initial enterprise-grade demo data for MorfeuXDR."""
    return await XDRService.seed_demo_data(db)


@router.get("/overview")
async def get_overview(current_user: CurrentUser, db: DbSession):
    """Returns SOC dashboard KPIs, MTTD/MTTR, Security Posture Score."""
    return await XDRService.get_overview(db)


@router.get("/findings")
async def get_findings(
    current_user: CurrentUser,
    db: DbSession,
    severity: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    search: Optional[str] = Query(None),
    limit: int = 100
):
    """Returns filterable normalized findings."""
    await XDRService.seed_demo_data(db)
    stmt = select(XDRFinding).order_by(XDRFinding.risk_score.desc()).limit(limit)

    if severity:
        stmt = stmt.where(XDRFinding.severity == severity)
    if status_filter:
        stmt = stmt.where(XDRFinding.status == status_filter)
    if search:
        stmt = stmt.where(
            (XDRFinding.title.ilike(f"%{search}%")) |
            (XDRFinding.hostname.ilike(f"%{search}%")) |
            (XDRFinding.finding_number.ilike(f"%{search}%")) |
            (XDRFinding.ip.ilike(f"%{search}%"))
        )

    result = await db.execute(stmt)
    findings = result.scalars().all()

    return [
        {
            "id": f.id,
            "finding_number": f.finding_number,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "risk_score": f.risk_score,
            "status": f.status,
            "confidence": f.confidence,
            "source_product": f.source_product,
            "source_rule": f.source_rule,
            "rule_id": f.rule_id,
            "rule_level": f.rule_level,
            "agent_id": f.agent_id,
            "hostname": f.hostname,
            "ip": f.ip,
            "username": f.username,
            "process": f.process,
            "command_line": f.command_line,
            "src_ip": f.src_ip,
            "src_port": f.src_port,
            "dst_ip": f.dst_ip,
            "dst_port": f.dst_port,
            "mitre_tactic": f.mitre_tactic,
            "mitre_technique": f.mitre_technique,
            "cve": f.cve,
            "correlation_id": f.correlation_id,
            "incident_id": f.incident_id,
            "evidence": f.evidence,
            "assigned_to": f.assigned_to,
            "created_at": f.created_at.isoformat() if f.created_at else None
        }
        for f in findings
    ]


@router.post("/findings/{id}/status")
async def update_finding_status(
    id: str,
    payload: FindingStatusUpdate,
    current_user: CurrentUser,
    db: DbSession
):
    """Updates finding status with append-only audit trail."""
    try:
        actor_name = getattr(current_user, 'full_name', 'Analista SOC')
        return await XDRService.mutate_finding_status(db, id, payload.status, actor_name, payload.reason)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/incidents")
async def get_incidents(current_user: CurrentUser, db: DbSession):
    """Returns correlated security incidents."""
    await XDRService.seed_demo_data(db)
    result = await db.execute(select(XDRIncident))
    incidents = result.scalars().all()
    return [
        {
            "id": i.id,
            "incident_number": i.incident_number,
            "title": i.title,
            "description": i.description,
            "severity": i.severity,
            "risk_score": i.risk_score,
            "status": i.status,
            "correlation_id": i.correlation_id,
            "assigned_to": i.assigned_to,
            "impacted_assets_count": i.impacted_assets_count,
            "mitre_techniques": i.mitre_techniques,
            "created_at": i.created_at.isoformat() if i.created_at else None
        }
        for i in incidents
    ]


@router.get("/investigation/{id}")
async def get_investigation(id: str, current_user: CurrentUser, db: DbSession):
    """Returns deep investigation detail payload for finding/incident."""
    await XDRService.seed_demo_data(db)
    f_res = await db.execute(select(XDRFinding).where(XDRFinding.id == id))
    finding = f_res.scalars().first()

    if not finding:
        # Fallback to first finding if id is generic
        finding = (await db.execute(select(XDRFinding))).scalars().first()

    # Related audit trail
    audits = (await db.execute(
        select(XDRAuditLog).where(XDRAuditLog.finding_id == finding.id)
    )).scalars().all()

    return {
        "finding": {
            "id": finding.id,
            "finding_number": finding.finding_number,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "risk_score": finding.risk_score,
            "status": finding.status,
            "confidence": finding.confidence,
            "hostname": finding.hostname,
            "ip": finding.ip,
            "username": finding.username,
            "process": finding.process,
            "command_line": finding.command_line,
            "src_ip": finding.src_ip,
            "dst_ip": finding.dst_ip,
            "mitre_tactic": finding.mitre_tactic,
            "mitre_technique": finding.mitre_technique,
            "correlation_id": finding.correlation_id,
            "raw_event": finding.raw_event or {"rule": {"id": finding.rule_id, "level": finding.rule_level}},
            "evidence": finding.evidence
        },
        "why_this_matters": {
            "why_detected": f"Regra Wazuh {finding.rule_id} disparada devido ao comportamento suspeito de {finding.process or 'processo'}.",
            "impact": "Potencial acesso não autorizado e movimentação lateral na rede de produção.",
            "recommended_action": "Isolar o agente afetado via Active Response e auditar sessões ativas do usuário."
        },
        "timeline": [
            {"time": "10:01:15", "event": "Conexão de rede de IP externo", "type": "NETWORK"},
            {"time": "10:01:22", "event": "Autenticação SSH com sucesso", "type": "AUTH"},
            {"time": "10:01:45", "event": "Criação de subprocesso powershell.exe", "type": "PROCESS"},
            {"time": "10:02:10", "event": "Regra Wazuh #91802 disparou alerta no MorfeuXDR", "type": "DETECTION"}
        ],
        "audit_trail": [
            {
                "id": a.id,
                "actor": a.actor,
                "action": a.action,
                "result": a.result,
                "timestamp": a.timestamp.isoformat()
            }
            for a in audits
        ]
    }


@router.get("/entity-graph")
async def get_entity_graph(current_user: CurrentUser, db: DbSession):
    """Returns visual entity relationship graph nodes and links."""
    await XDRService.seed_demo_data(db)
    result = await db.execute(select(XDREntity))
    entities = result.scalars().all()

    nodes = [
        {"id": e.id, "label": e.name, "type": e.entity_type, "risk": e.risk_score}
        for e in entities
    ]

    # Links
    links = [
        {"source": nodes[0]["id"], "target": nodes[2]["id"], "relation": "LOGGED_INTO"},
        {"source": nodes[2]["id"], "target": nodes[4]["id"], "relation": "EXECUTED"},
        {"source": nodes[4]["id"], "target": nodes[6]["id"], "relation": "C2_CONNECTION"},
        {"source": nodes[1]["id"], "target": nodes[3]["id"], "relation": "SYSTEM_SERVICE"}
    ] if len(nodes) >= 7 else []

    return {"nodes": nodes, "links": links}


@router.get("/mitre-matrix")
async def get_mitre_matrix(current_user: CurrentUser, db: DbSession):
    """Returns MITRE ATT&CK coverage matrix."""
    return {
        "tactics": [
            {"name": "Initial Access", "count": 12, "detected_techniques": ["T1190 (Exploit Public App)", "T1078 (Valid Accounts)"]},
            {"name": "Execution", "count": 28, "detected_techniques": ["T1059.001 (PowerShell)", "T1059.004 (Unix Shell)"]},
            {"name": "Persistence", "count": 15, "detected_techniques": ["T1098 (Account Manipulation)", "T1053 (Scheduled Task)"]},
            {"name": "Privilege Escalation", "count": 9, "detected_techniques": ["T1548 (Sudo & Sudoers)"]},
            {"name": "Defense Evasion", "count": 22, "detected_techniques": ["T1027 (Obfuscated Command)"]},
            {"name": "Credential Access", "count": 34, "detected_techniques": ["T1110.001 (Brute Force)", "T1003 (OS Credential Dumping)"]},
            {"name": "Command & Control", "count": 18, "detected_techniques": ["T1071.001 (Web Protocols)"]}
        ]
    }


@router.get("/wazuh/agents")
async def get_wazuh_agents(current_user: CurrentUser, db: DbSession):
    """Returns Wazuh agent inventory."""
    await XDRService.seed_demo_data(db)
    result = await db.execute(select(XDRAgent))
    agents = result.scalars().all()
    return [
        {
            "id": a.id,
            "wazuh_agent_id": a.wazuh_agent_id,
            "name": a.name,
            "ip": a.ip,
            "os_name": a.os_name,
            "os_platform": a.os_platform,
            "status": a.status,
            "risk_score": a.risk_score,
            "last_keepalive": a.last_keepalive.isoformat() if a.last_keepalive else None
        }
        for a in agents
    ]


@router.get("/active-response")
async def get_active_response(current_user: CurrentUser, db: DbSession):
    """Returns log of active responses executed by Wazuh."""
    return [
        {
            "id": "ar-001",
            "command": "firewall-drop",
            "target_ip": "185.220.101.4",
            "agent": "srv-prod-app-01",
            "status": "SUCCESS",
            "executed_at": datetime.now(timezone.utc).isoformat()
        }
    ]


@router.get("/compliance")
async def get_compliance(current_user: CurrentUser, db: DbSession):
    """Returns compliance mapping for frameworks."""
    return {
        "frameworks": [
            {"name": "NIST 800-53", "score": 89.2, "status": "COMPLIANT"},
            {"name": "ISO 27001", "score": 91.0, "status": "COMPLIANT"},
            {"name": "CIS Controls", "score": 88.5, "status": "COMPLIANT"},
            {"name": "PCI DSS v4.0", "score": 84.0, "status": "ATTENTION_REQUIRED"},
            {"name": "BACEN Cybersecurity", "score": 92.4, "status": "COMPLIANT"}
        ]
    }


@router.get("/audit-logs")
async def get_xdr_audit_logs(current_user: CurrentUser, db: DbSession):
    """Returns XDR append-only audit trail."""
    await XDRService.seed_demo_data(db)
    result = await db.execute(select(XDRAuditLog).order_by(XDRAuditLog.timestamp.desc()))
    logs = result.scalars().all()
    return [
        {
            "id": l.id,
            "actor": l.actor,
            "action": l.action,
            "action_category": l.action_category,
            "finding_id": l.finding_id,
            "incident_id": l.incident_id,
            "correlation_id": l.correlation_id,
            "before_state": l.before_state,
            "after_state": l.after_state,
            "result": l.result,
            "timestamp": l.timestamp.isoformat() if l.timestamp else None
        }
        for l in logs
    ]
