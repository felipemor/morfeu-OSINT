"""
MorfeuXDR Service — Core Logic for Correlation Engine, Risk Engine, Incident Engine & Audit Trail
"""
import uuid
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update
from sqlalchemy.orm import selectinload

from app.models_xdr import (
    XDRSecurityPosture, XDRAgent, XDRCorrelation, XDRIncident, XDRFinding,
    XDREntity, XDRAuditLog, XDRSeverity, XDRFindingStatus, XDRIncidentStatus, XDRAgentStatus
)


class XDRService:

    @staticmethod
    async def seed_demo_data(db: AsyncSession) -> Dict[str, Any]:
        """Seeds enterprise SOC dataset (MorfeuXDR powered by Wazuh)."""
        result = await db.execute(select(XDRFinding))
        existing = result.scalars().all()
        if existing:
            return {"status": "Already seeded", "findings_count": len(existing)}

        now = datetime.now(timezone.utc)

        # 1. Posture Score
        posture = XDRSecurityPosture(
            id=str(uuid.uuid4()),
            overall_score=87.4,
            threat_detection_score=85.0,
            endpoint_security_score=90.5,
            vulnerability_score=78.0,
            configuration_score=88.2,
            identity_score=92.0,
            compliance_score=89.0,
            incident_response_score=94.0,
            agent_health_score=96.0,
            detection_coverage_score=86.5,
            calculated_at=now
        )
        db.add(posture)

        # 2. Agents
        agents_data = [
            {"id": "001", "name": "srv-prod-app-01", "ip": "10.0.1.15", "os": "Ubuntu 22.04 LTS", "plat": "linux", "status": "ONLINE", "risk": 15.0},
            {"id": "002", "name": "win-dc-prod-01", "ip": "10.0.1.20", "os": "Windows Server 2022", "plat": "windows", "status": "ONLINE", "risk": 48.0},
            {"id": "003", "name": "k8s-worker-node-03", "ip": "10.0.2.50", "os": "Debian 12 Bookworm", "plat": "linux", "status": "ONLINE", "risk": 10.0},
            {"id": "004", "name": "macbook-secops-dev", "ip": "10.0.5.99", "os": "macOS Sonoma 14.4", "plat": "macos", "status": "ONLINE", "risk": 5.0},
            {"id": "005", "name": "srv-legacy-billing", "ip": "10.0.4.12", "type": "VM", "os": "CentOS 7.9", "plat": "linux", "status": "OFFLINE", "risk": 82.0}
        ]

        agent_instances = []
        for ad in agents_data:
            ag = XDRAgent(
                id=str(uuid.uuid4()),
                wazuh_agent_id=ad["id"],
                name=ad["name"],
                ip=ad["ip"],
                os_name=ad["os"],
                os_platform=ad["plat"],
                status=ad["status"],
                risk_score=ad["risk"],
                registered_at=now - timedelta(days=30)
            )
            db.add(ag)
            agent_instances.append(ag)

        await db.flush()

        # 3. Correlations & Incidents
        corr_1 = XDRCorrelation(
            id=str(uuid.uuid4()),
            correlation_id="CORR-2026-98471",
            title="Sequência de Ataque Detectada: Brute Force SSH seguido de Execução de PowerShell Codificado",
            rule_name="Multiple Failed SSH Logins + Suspicious Encoded Shell",
            events_count=14,
            risk_score=94.5,
            mitre_tactic="Credential Access",
            mitre_technique="T1110.001"
        )
        db.add(corr_1)

        inc_1 = XDRIncident(
            id=str(uuid.uuid4()),
            incident_number="INC-2026-00104",
            title="Possível Comprometimento de Endpoint — Servidor Domain Controller / Web App",
            description="Motor de Correlação MorfeuXDR identificou 14 alertas do Wazuh correlacionados na máquina win-dc-prod-01 indicando tentativa de movimentação lateral e abuso de credenciais.",
            severity="CRITICAL",
            risk_score=94.5,
            status="INVESTIGATING",
            correlation_id="CORR-2026-98471",
            assigned_to="Equipe SOC Tier 2",
            impacted_assets_count=2,
            mitre_techniques=["T1110.001 (Brute Force)", "T1059.001 (PowerShell)", "T1053 (Scheduled Task)"]
        )
        db.add(inc_1)
        await db.flush()

        # 4. Findings
        findings_data = [
            {
                "num": "FND-8801",
                "title": "Ataque de Força Bruta SSH bem-sucedido (Multiple Failed Logins + Success)",
                "desc": "Detectadas 450 tentativas de login via SSH com falha seguidas de uma autenticação bem-sucedida para o usuário 'root' a partir do IP externo 185.220.101.4.",
                "sev": "CRITICAL",
                "risk": 92.0,
                "status": "INVESTIGATING",
                "rule": "wazuh-rule-5715 (SSHD Authentication Success after Failures)",
                "rule_id": "5715",
                "lvl": 14,
                "agent_id": "001",
                "host": "srv-prod-app-01",
                "ip": "10.0.1.15",
                "user": "root",
                "proc": "sshd",
                "cmd": "/usr/sbin/sshd -D",
                "src_ip": "185.220.101.4",
                "src_port": 54210,
                "dst_ip": "10.0.1.15",
                "dst_port": 22,
                "tactic": "Credential Access",
                "technique": "T1110.001",
                "corr": "CORR-2026-98471",
                "inc_id": inc_1.id
            },
            {
                "num": "FND-8802",
                "title": "Execução de Comando PowerShell Codificado Base64 Suspeito",
                "desc": "Processo powershell.exe executado com argumento -EncodedCommand abrindo conexão reversa para C2.",
                "sev": "CRITICAL",
                "risk": 96.0,
                "status": "INVESTIGATING",
                "rule": "wazuh-rule-91802 (Windows PowerShell Suspicious Base64 Command)",
                "rule_id": "91802",
                "lvl": 13,
                "agent_id": "002",
                "host": "win-dc-prod-01",
                "ip": "10.0.1.20",
                "user": "SYSTEM",
                "proc": "powershell.exe",
                "cmd": "powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdAA...",
                "src_ip": "10.0.1.20",
                "dst_ip": "194.26.29.110",
                "dst_port": 443,
                "tactic": "Execution",
                "technique": "T1059.001",
                "corr": "CORR-2026-98471",
                "inc_id": inc_1.id
            },
            {
                "num": "FND-8803",
                "title": "Alteração Crítica de Integridade de Arquivo (FIM — /etc/shadow modified)",
                "desc": "O módulo Wazuh FIM (File Integrity Monitoring) detectou a modificação no arquivo sensível /etc/shadow fora da janela de manutenção.",
                "sev": "HIGH",
                "risk": 84.0,
                "status": "TRIAGED",
                "rule": "wazuh-rule-550 (Integrity checksum changed for /etc/shadow)",
                "rule_id": "550",
                "lvl": 12,
                "agent_id": "001",
                "host": "srv-prod-app-01",
                "ip": "10.0.1.15",
                "user": "root",
                "proc": "useradd",
                "tactic": "Persistence",
                "technique": "T1098"
            },
            {
                "num": "FND-8804",
                "title": "Vulnerabilidade Crítica de Execução de Código Remoto (CVE-2021-41773 Apache RCE)",
                "desc": "O módulo Wazuh Vulnerability Detector identificou a presença do pacote Apache httpd 2.4.49 vulnerável a Path Traversal & RCE.",
                "sev": "HIGH",
                "risk": 88.0,
                "status": "OPEN",
                "rule": "wazuh-rule-23501 (Vulnerability Detector — CVE-2021-41773)",
                "rule_id": "23501",
                "lvl": 10,
                "agent_id": "005",
                "host": "srv-legacy-billing",
                "ip": "10.0.4.12",
                "cve": "CVE-2021-41773",
                "tactic": "Initial Access",
                "technique": "T1190"
            }
        ]

        finding_instances = []
        for fd in findings_data:
            fnd = XDRFinding(
                id=str(uuid.uuid4()),
                finding_number=fd["num"],
                title=fd["title"],
                description=fd["desc"],
                severity=fd["sev"],
                risk_score=fd["risk"],
                status=fd["status"],
                confidence=95.0,
                source_product="Wazuh SIEM/XDR Engine",
                source_rule=fd["rule"],
                rule_id=fd["rule_id"],
                rule_level=fd["lvl"],
                agent_id=fd.get("agent_id"),
                hostname=fd["host"],
                ip=fd["ip"],
                username=fd.get("user"),
                process=fd.get("proc"),
                command_line=fd.get("cmd"),
                src_ip=fd.get("src_ip"),
                src_port=fd.get("src_port"),
                dst_ip=fd.get("dst_ip"),
                dst_port=fd.get("dst_port"),
                mitre_tactic=fd.get("tactic"),
                mitre_technique=fd.get("technique"),
                cve=fd.get("cve"),
                correlation_id=fd.get("corr"),
                incident_id=fd.get("inc_id"),
                evidence={
                    "wazuh_full_log": f"Wazuh Alert {fd['rule_id']} triggered on {fd['host']}",
                    "decoder": "json",
                    "location": "/var/log/syslog"
                },
                sla_deadline=now + timedelta(hours=4),
                created_at=now - timedelta(minutes=15)
            )
            db.add(fnd)
            finding_instances.append(fnd)

        await db.flush()

        # 5. Entities Graph Nodes
        entities = [
            {"name": "root", "type": "USER", "risk": 90.0},
            {"name": "SYSTEM", "type": "USER", "risk": 95.0},
            {"name": "srv-prod-app-01", "type": "HOST", "risk": 75.0},
            {"name": "win-dc-prod-01", "type": "HOST", "risk": 94.0},
            {"name": "powershell.exe", "type": "PROCESS", "risk": 96.0},
            {"name": "185.220.101.4", "type": "IP", "risk": 99.0},
            {"name": "194.26.29.110", "type": "IP", "risk": 98.0}
        ]

        for ed in entities:
            ent = XDREntity(
                id=str(uuid.uuid4()),
                name=ed["name"],
                entity_type=ed["type"],
                risk_score=ed["risk"]
            )
            db.add(ent)

        # 6. Audit Trail Initialization
        audit_1 = XDRAuditLog(
            id=str(uuid.uuid4()),
            actor="Felipe Costa (Security Engineer)",
            action="FINDING_STATUS_MUTATION",
            action_category="INVESTIGATION",
            finding_id=finding_instances[0].id,
            incident_id=inc_1.id,
            correlation_id="CORR-2026-98471",
            before_state={"status": "NEW"},
            after_state={"status": "INVESTIGATING"},
            result="SUCCESS",
            timestamp=now - timedelta(minutes=10)
        )
        db.add(audit_1)

        await db.commit()

        return {
            "status": "Success",
            "findings_created": len(findings_data),
            "agents_created": len(agents_data),
            "incidents_created": 1
        }

    @staticmethod
    async def get_overview(db: AsyncSession) -> Dict[str, Any]:
        """Calculates executive SOC metrics and security posture score."""
        await XDRService.seed_demo_data(db)

        # Posture Score
        posture_res = await db.execute(select(XDRSecurityPosture).order_by(XDRSecurityPosture.calculated_at.desc()))
        posture = posture_res.scalars().first()

        # Counts
        total_findings = (await db.execute(select(func.count(XDRFinding.id)))).scalar_one()
        critical_findings = (await db.execute(
            select(func.count(XDRFinding.id)).where(XDRFinding.severity == "CRITICAL")
        )).scalar_one()
        high_findings = (await db.execute(
            select(func.count(XDRFinding.id)).where(XDRFinding.severity == "HIGH")
        )).scalar_one()
        open_findings = (await db.execute(
            select(func.count(XDRFinding.id)).where(XDRFinding.status.in_(["NEW", "OPEN", "TRIAGED", "INVESTIGATING"]))
        )).scalar_one()

        active_incidents = (await db.execute(
            select(func.count(XDRIncident.id)).where(XDRIncident.status.in_(["OPEN", "INVESTIGATING"]))
        )).scalar_one()

        agents_online = (await db.execute(
            select(func.count(XDRAgent.id)).where(XDRAgent.status == "ONLINE")
        )).scalar_one()
        agents_total = (await db.execute(select(func.count(XDRAgent.id)))).scalar_one()

        return {
            "security_score": posture.overall_score if posture else 87.4,
            "score_breakdown": {
                "threat_detection": posture.threat_detection_score if posture else 85.0,
                "endpoint_security": posture.endpoint_security_score if posture else 90.5,
                "vulnerabilities": posture.vulnerability_score if posture else 78.0,
                "configuration_sca": posture.configuration_score if posture else 88.2,
                "compliance": posture.compliance_score if posture else 89.0,
                "agent_health": posture.agent_health_score if posture else 96.0
            },
            "total_findings": total_findings,
            "critical_findings": critical_findings,
            "high_findings": high_findings,
            "open_findings": open_findings,
            "active_incidents": active_incidents,
            "agents_online": agents_online,
            "agents_total": agents_total,
            "mttd_minutes": 4.2,  # Mean Time to Detect
            "mtti_minutes": 12.0, # Mean Time to Investigate
            "mttr_hours": 1.5,    # Mean Time to Resolve
            "events_per_minute": 4850,
            "mitre_coverage_percentage": 86.5
        }

    @staticmethod
    async def mutate_finding_status(db: AsyncSession, finding_id: str, new_status: str, actor: str, reason: Optional[str] = None) -> Dict[str, Any]:
        """Updates finding status and logs an immutable append-only audit record."""
        stmt = select(XDRFinding).where(XDRFinding.id == finding_id)
        result = await db.execute(stmt)
        finding = result.scalars().first()

        if not finding:
            raise ValueError("Finding not found")

        old_status = finding.status
        finding.status = new_status
        finding.updated_at = datetime.now(timezone.utc)

        # Audit Record
        audit = XDRAuditLog(
            id=str(uuid.uuid4()),
            actor=actor,
            action="FINDING_STATUS_MUTATION",
            action_category="GOVERNANCE",
            finding_id=finding.id,
            incident_id=finding.incident_id,
            correlation_id=finding.correlation_id,
            before_state={"status": old_status},
            after_state={"status": new_status, "reason": reason},
            result="SUCCESS"
        )
        db.add(audit)
        await db.commit()

        return {"status": "updated", "id": finding.id, "old_status": old_status, "new_status": new_status}
