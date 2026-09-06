"""
Grafana Correlation Service — Unifies Pentest, eBPF Flows, Wazuh XDR & Honeypots into Correlation Graph & Grafana Panels
"""
import uuid
from typing import Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models_honeypot import GrafanaCorrelationNode, GrafanaCorrelationEdge, HoneypotTrap, HoneypotEvent
from app.services.honeypot_service import HoneypotService


class GrafanaCorrelationService:

    @staticmethod
    async def seed_correlation_graph(db: AsyncSession) -> Dict[str, Any]:
        """Seeds the unified correlation graph connecting Pentest -> eBPF -> Wazuh -> Honeypot."""
        await HoneypotService.seed_honeypot_data(db)

        result = await db.execute(select(GrafanaCorrelationNode))
        existing = result.scalars().all()
        if existing:
            return {"status": "Already seeded", "nodes_count": len(existing)}

        # Nodes Data
        nodes_data = [
            {"label": "External Attacker (185.220.101.4)", "type": "ATTACKER_IP", "risk": 99.0, "ip": "185.220.101.4", "critical": True},
            {"label": "SSH Decoy Honeypot (Port 2222)", "type": "HONEYPOT_TRAP", "risk": 95.0, "ip": "10.0.1.99", "critical": True},
            {"label": "Auto Pentest Finding: CVE-2023-44487", "type": "PENTEST_VULN", "risk": 92.0, "ip": "10.0.1.10", "critical": True},
            {"label": "eBPF Flow: DMZ -> Mobile Gateway (443)", "type": "EBPF_FLOW", "risk": 75.0, "ip": "10.244.2.11", "critical": True},
            {"label": "Wazuh Alert #91802: PowerShell Base64", "type": "WAZUH_ALERT", "risk": 96.0, "ip": "10.0.1.20", "critical": True},
            {"label": "PCI Cardholder Vault DB (Target)", "type": "CRITICAL_ASSET", "risk": 98.0, "ip": "10.0.4.99", "critical": True},

            # Secondary non-critical nodes
            {"label": "Fake Admin Portal (Port 8080)", "type": "HONEYPOT_TRAP", "risk": 45.0, "ip": "10.0.1.100", "critical": False},
            {"label": "GitLab Runner DevOps", "type": "DEVOPS_NODE", "risk": 20.0, "ip": "10.0.5.12", "critical": False}
        ]

        node_instances = []
        node_map = {}
        for nd in nodes_data:
            node = GrafanaCorrelationNode(
                id=str(uuid.uuid4()),
                label=nd["label"],
                node_type=nd["type"],
                risk_score=nd["risk"],
                ip=nd["ip"],
                is_critical_vector=nd["critical"]
            )
            db.add(node)
            node_instances.append(node)
            node_map[nd["label"]] = node

        await db.flush()

        # Edges Data connecting the critical path #1
        edges_data = [
            {"src": "External Attacker (185.220.101.4)", "dst": "SSH Decoy Honeypot (Port 2222)", "label": "PROBED_HONEYPOT", "port": "2222/TCP", "crit": True},
            {"src": "External Attacker (185.220.101.4)", "dst": "Auto Pentest Finding: CVE-2023-44487", "label": "EXPLOITED_VULN", "port": "443/HTTPS", "crit": True},
            {"src": "Auto Pentest Finding: CVE-2023-44487", "dst": "eBPF Flow: DMZ -> Mobile Gateway (443)", "label": "LATERAL_TRAFFIC", "port": "8080/gRPC", "crit": True},
            {"src": "eBPF Flow: DMZ -> Mobile Gateway (443)", "dst": "Wazuh Alert #91802: PowerShell Base64", "label": "EXECUTION_ALERT", "port": "SYSTEM", "crit": True},
            {"src": "Wazuh Alert #91802: PowerShell Base64", "dst": "PCI Cardholder Vault DB (Target)", "label": "TARGET_COMPROMISE", "port": "8443/mTLS", "crit": True},
            {"src": "External Attacker (185.220.101.4)", "dst": "Fake Admin Portal (Port 8080)", "label": "SQLI_PROBE", "port": "8080/HTTP", "crit": False}
        ]

        for ed in edges_data:
            src_n = node_map.get(ed["src"])
            dst_n = node_map.get(ed["dst"])
            if src_n and dst_n:
                edge = GrafanaCorrelationEdge(
                    id=str(uuid.uuid4()),
                    source_node_id=src_n.id,
                    target_node_id=dst_n.id,
                    relation_label=ed["label"],
                    is_critical_path=ed["crit"],
                    protocol_port=ed["port"]
                )
                db.add(edge)

        await db.commit()
        return {"status": "Success", "nodes": len(nodes_data), "edges": len(edges_data)}

    @staticmethod
    async def get_attack_graph(db: AsyncSession) -> Dict[str, Any]:
        """Returns visual attack graph nodes and edges highlighting the #1 Critical Vector."""
        await GrafanaCorrelationService.seed_correlation_graph(db)

        n_res = await db.execute(select(GrafanaCorrelationNode))
        nodes = n_res.scalars().all()

        e_res = await db.execute(select(GrafanaCorrelationEdge))
        edges = e_res.scalars().all()

        node_map = {n.id: n for n in nodes}

        return {
            "nodes": [
                {
                    "id": n.id,
                    "label": n.label,
                    "type": n.node_type,
                    "risk_score": n.risk_score,
                    "ip": n.ip,
                    "is_critical_vector": n.is_critical_vector
                }
                for n in nodes
            ],
            "edges": [
                {
                    "id": e.id,
                    "source": e.source_node_id,
                    "source_label": node_map.get(e.source_node_id).label if node_map.get(e.source_node_id) else "",
                    "target": e.target_node_id,
                    "target_label": node_map.get(e.target_node_id).label if node_map.get(e.target_node_id) else "",
                    "relation": e.relation_label,
                    "is_critical_path": e.is_critical_path,
                    "protocol_port": e.protocol_port
                }
                for e in edges
            ],
            "critical_path_summary": {
                "title": "#1 Critical Attack Path: Honeypot Probe ➔ Pentest CVE ➔ eBPF Flow ➔ Wazuh Alert ➔ PCI Vault",
                "risk_score": 98.5,
                "attacker_ip": "185.220.101.4",
                "target_asset": "PCI Cardholder Vault DB (10.0.4.99)",
                "verdict": "VETOR CRÍTICO ATIVO — Interrupção recomendada via Microsegmentação e Bloqueio de Firewall no Honeypot."
            }
        }

    @staticmethod
    async def get_grafana_dashboard_data(db: AsyncSession) -> Dict[str, Any]:
        """Returns metrics and panel configs formatted for Grafana dashboards."""
        await GrafanaCorrelationService.seed_correlation_graph(db)

        # Count traps and events
        traps = (await db.execute(select(HoneypotTrap))).scalars().all()
        events = (await db.execute(select(HoneypotEvent))).scalars().all()

        return {
            "grafana_url": "http://localhost:3000/d/morfeu-unified-soc",
            "prometheus_datasource": "http://localhost:9090",
            "metrics": {
                "honeypot_traps_active": len(traps),
                "honeypot_attacks_total": sum(t.hits_count for t in traps),
                "attacks_per_second": 14.2,
                "ebpf_flows_volume_mb": 1420.5,
                "wazuh_alerts_count": 4,
                "pentest_critical_vulnerabilities": 2
            },
            "panels": [
                {"id": 1, "title": "Ataques no Honeypot por Segundo (Prometheus)", "type": "graph", "metric": "honeypot_attacks_per_second", "value": "14.2 ops"},
                {"id": 2, "title": "Top IPs de Atacantes (Decoy Traps)", "type": "table", "data": [
                    {"ip": "185.220.101.4", "country": "Russia", "hits": 450, "trap": "SSH Decoy (2222)"},
                    {"ip": "194.26.29.110", "country": "China", "hits": 1280, "trap": "Fake Admin Portal (8080)"},
                    {"ip": "45.143.200.12", "country": "Netherlands", "hits": 310, "trap": "Redis Trap (6379)"}
                ]},
                {"id": 3, "title": "Volume de Tráfego eBPF Monitorado (MB)", "type": "gauge", "value": "1.42 GB"},
                {"id": 4, "title": "MorfeuXDR Incident Correlation Rate", "type": "stat", "value": "98.5% High Confidence"}
            ]
        }
