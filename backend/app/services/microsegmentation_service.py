"""
Microsegmentation Service — Business logic for Hybrid Microsegmentation & Zero Trust
"""
import uuid
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update, delete
from sqlalchemy.orm import selectinload

from app.models_microseg import (
    MicroSegmentationZone, MicroAsset, MicroNetworkFlow, MicroNetworkPolicy,
    MicroPolicyVersion, MicroAttackPath, MicroSecurityAlert, MicroTelemetrySource,
    MicroFlowAction, MicroPolicyStatus, MicroEnforcementMode, MicroRiskLevel
)


class MicrosegmentationService:

    @staticmethod
    async def seed_demo_data(db: AsyncSession) -> Dict[str, Any]:
        """
        Seeds enterprise-grade demo data (Akamai Guardicore style) if database tables are empty.
        """
        # Check if already seeded
        result = await db.execute(select(MicroSegmentationZone))
        existing_zones = result.scalars().all()
        if existing_zones:
            return {"status": "Already seeded", "zone_count": len(existing_zones)}

        # 1. Create Zones
        zones_data = [
            {"name": "DMZ & Ingress", "description": "Public facing load balancers and reverse proxies", "color": "#00d4ff", "strictness_level": "STRICT", "default_action": "DENY", "icon": "Globe"},
            {"name": "App Tier (K8s Microservices)", "description": "Core application microservices running on Kubernetes", "color": "#7c4dff", "strictness_level": "STRICT", "default_action": "DENY", "icon": "Boxes"},
            {"name": "Core Banking & Payments (PCI-DSS)", "description": "Highly isolated payment processing & PCI compliant database zone", "color": "#ff1744", "strictness_level": "STRICT", "default_action": "DENY", "icon": "ShieldAlert"},
            {"name": "Database Zone", "description": "PostgreSQL, Redis and MongoDB production database clusters", "color": "#00e676", "strictness_level": "STRICT", "default_action": "DENY", "icon": "Database"},
            {"name": "Mobile Backend", "description": "APIs and services consumed directly by mobile apps", "color": "#ff9100", "strictness_level": "MODERATE", "default_action": "DENY", "icon": "Smartphone"},
            {"name": "Management & DevOps", "description": "CI/CD runners, monitoring, and telemetry collectors", "color": "#00b0ff", "strictness_level": "MODERATE", "default_action": "LOG", "icon": "Sliders"}
        ]

        zone_instances = []
        zone_map = {}
        for zd in zones_data:
            z = MicroSegmentationZone(
                id=str(uuid.uuid4()),
                name=zd["name"],
                description=zd["description"],
                color=zd["color"],
                strictness_level=zd["strictness_level"],
                default_action=zd["default_action"],
                icon=zd["icon"]
            )
            db.add(z)
            zone_instances.append(z)
            zone_map[zd["name"]] = z.id

        await db.flush()

        # 2. Create Assets
        assets_data = [
            {"name": "ingress-nginx-lb-01", "ip": "10.0.1.10", "type": "LOAD_BALANCER", "zone": "DMZ & Ingress", "ns": "ingress-system", "os": "Linux Alpine", "risk": 25.0, "status": "HEALTHY"},
            {"name": "auth-service-pod-7df8", "ip": "10.244.1.15", "type": "K8S_POD", "zone": "App Tier (K8s Microservices)", "ns": "prod-apps", "os": "Container (Node 20)", "risk": 15.0, "status": "HEALTHY"},
            {"name": "payment-api-pod-9a1b", "ip": "10.244.1.22", "type": "K8S_POD", "zone": "Core Banking & Payments (PCI-DSS)", "ns": "pci-vault", "os": "Container (Go 1.22)", "risk": 45.0, "status": "WARNING"},
            {"name": "mobile-gateway-pod-3c4d", "ip": "10.244.2.11", "type": "K8S_POD", "zone": "Mobile Backend", "ns": "mobile-prod", "os": "Container (Python 3.12)", "risk": 20.0, "status": "HEALTHY"},
            {"name": "postgres-primary-db", "ip": "10.0.3.50", "type": "CLOUD_DB", "zone": "Database Zone", "ns": "db-cluster", "os": "Ubuntu 22.04 LTS", "risk": 35.0, "status": "HEALTHY"},
            {"name": "redis-cache-cluster", "ip": "10.0.3.51", "type": "CONTAINER", "zone": "Database Zone", "ns": "db-cluster", "os": "Redis 7.2 Alpine", "risk": 10.0, "status": "HEALTHY"},
            {"name": "pci-hsm-vault-vm", "ip": "10.0.4.99", "type": "VM_LINUX", "zone": "Core Banking & Payments (PCI-DSS)", "ns": "pci-vault", "os": "RHEL 9.2", "risk": 60.0, "status": "CRITICAL"},
            {"name": "gitlab-runner-agent-01", "ip": "10.0.5.12", "type": "VM_LINUX", "zone": "Management & DevOps", "ns": "devops", "os": "Debian 12", "risk": 30.0, "status": "HEALTHY"}
        ]

        asset_instances = []
        asset_map = {}
        for ad in assets_data:
            ast = MicroAsset(
                id=str(uuid.uuid4()),
                name=ad["name"],
                ip_address=ad["ip"],
                asset_type=ad["type"],
                zone_id=zone_map.get(ad["zone"]),
                namespace=ad["ns"],
                labels={"env": "production", "tier": ad["zone"].split()[0].lower(), "app": ad["name"].split("-")[0]},
                os_info=ad["os"],
                status=ad["status"],
                risk_score=ad["risk"],
                agent_installed=True,
                last_seen=datetime.now(timezone.utc)
            )
            db.add(ast)
            asset_instances.append(ast)
            asset_map[ad["name"]] = ast

        await db.flush()

        # 3. Create Flows
        flow_samples = [
            {"src": "ingress-nginx-lb-01", "dst": "mobile-gateway-pod-3c4d", "port": 443, "proto": "TCP", "action": "ALLOW", "bytes": 142000, "proc": "nginx", "is_anom": False},
            {"src": "mobile-gateway-pod-3c4d", "dst": "auth-service-pod-7df8", "port": 8080, "proto": "gRPC", "action": "ALLOW", "bytes": 85000, "proc": "python", "is_anom": False},
            {"src": "auth-service-pod-7df8", "dst": "postgres-primary-db", "port": 5432, "proto": "TCP", "action": "ALLOW", "bytes": 230000, "proc": "postgres", "is_anom": False},
            {"src": "mobile-gateway-pod-3c4d", "dst": "payment-api-pod-9a1b", "port": 9443, "proto": "HTTPS", "action": "ALLOW", "bytes": 62000, "proc": "go", "is_anom": False},
            {"src": "payment-api-pod-9a1b", "dst": "pci-hsm-vault-vm", "port": 8443, "proto": "mTLS", "action": "ALLOW", "bytes": 31000, "proc": "vault", "is_anom": False},
            # Unauthorized / Anomalous / Denied Lateral Movements
            {"src": "ingress-nginx-lb-01", "dst": "postgres-primary-db", "port": 5432, "proto": "TCP", "action": "VIOLATION", "bytes": 1024, "proc": "curl", "is_anom": True},
            {"src": "gitlab-runner-agent-01", "dst": "pci-hsm-vault-vm", "port": 22, "proto": "SSH", "action": "DENY", "bytes": 512, "proc": "ssh", "is_anom": True},
            {"src": "mobile-gateway-pod-3c4d", "dst": "pci-hsm-vault-vm", "port": 3389, "proto": "RDP", "action": "VIOLATION", "bytes": 2048, "proc": "unknown", "is_anom": True}
        ]

        now = datetime.now(timezone.utc)
        for i, fs in enumerate(flow_samples):
            src_ast = asset_map.get(fs["src"])
            dst_ast = asset_map.get(fs["dst"])
            flow = MicroNetworkFlow(
                id=str(uuid.uuid4()),
                source_asset_id=src_ast.id if src_ast else None,
                source_ip=src_ast.ip_address if src_ast else "192.168.1.100",
                source_name=fs["src"],
                destination_asset_id=dst_ast.id if dst_ast else None,
                destination_ip=dst_ast.ip_address if dst_ast else "10.0.0.1",
                destination_name=fs["dst"],
                destination_port=fs["port"],
                protocol=fs["proto"],
                action=fs["action"],
                byte_count=fs["bytes"],
                packet_count=int(fs["bytes"] / 100),
                process_name=fs["proc"],
                telemetry_source="Hubble eBPF",
                is_anomaly=fs["is_anom"],
                timestamp=now - timedelta(minutes=i * 5)
            )
            db.add(flow)

        # 4. Create Policies
        policies_data = [
            {
                "title": "Strict Ingress to Mobile Gateway Only",
                "desc": "Permite tráfego HTTPS vindo da DMZ apenas para o Mobile Gateway Backend na porta 443",
                "src_z": "DMZ & Ingress",
                "dst_z": "Mobile Backend",
                "port": "443",
                "proto": "TCP",
                "action": "ALLOW",
                "status": "ACTIVE",
                "mode": "ENFORCING",
                "yaml": "apiVersion: cilium.io/2v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: ingress-to-mobile-backend\nspec:\n  endpointSelector:\n    matchLabels:\n      tier: mobile\n  ingress:\n  - fromEndpoints:\n    - matchLabels:\n        tier: dmz\n    toPorts:\n    - ports:\n      - port: \"443\"\n        protocol: TCP"
            },
            {
                "title": "PCI-DSS Vault Isolation Policy",
                "desc": "Bloqueia todo tráfego direto para o cofre PCI-DSS exceto requisições autenticadas da API de pagamentos via mTLS (8443)",
                "src_z": "Core Banking & Payments (PCI-DSS)",
                "dst_z": "Core Banking & Payments (PCI-DSS)",
                "port": "8443",
                "proto": "TCP",
                "action": "ALLOW",
                "status": "ACTIVE",
                "mode": "ENFORCING",
                "yaml": "apiVersion: cilium.io/v2\nkind: CiliumClusterwideNetworkPolicy\nmetadata:\n  name: pci-vault-zero-trust\nspec:\n  endpointSelector:\n    matchLabels:\n      app: pci-hsm-vault\n  ingress:\n  - fromEndpoints:\n    - matchLabels:\n        app: payment-api\n    toPorts:\n    - ports:\n      - port: \"8443\"\n        protocol: TCP"
            },
            {
                "title": "Block Direct Ingress to Database Tier",
                "desc": "Regra Zero Trust: impede qualquer comunicação vinda da DMZ ou Web diretamente para instâncias do banco de dados (5432/6379)",
                "src_z": "DMZ & Ingress",
                "dst_z": "Database Zone",
                "port": "5432,6379",
                "proto": "TCP",
                "action": "DENY",
                "status": "ACTIVE",
                "mode": "ENFORCING",
                "yaml": "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: block-dmz-to-db\nspec:\n  endpointSelector:\n    matchLabels:\n      tier: database\n  ingress:\n  - fromEndpoints:\n    - matchLabels:\n        tier: dmz\n    toPorts:\n    - ports:\n      - port: \"5432\"\n        protocol: TCP\n  action: DENY"
            }
        ]

        for pd in policies_data:
            pol = MicroNetworkPolicy(
                id=str(uuid.uuid4()),
                title=pd["title"],
                description=pd["desc"],
                source_zone_id=zone_map.get(pd["src_z"]),
                destination_zone_id=zone_map.get(pd["dst_z"]),
                port_range=pd["port"],
                protocol=pd["proto"],
                action=pd["action"],
                status=pd["status"],
                enforcement_mode=pd["mode"],
                auto_generated=False,
                yaml_config=pd["yaml"],
                hits_count=random.randint(120, 4500)
            )
            db.add(pol)

        # 5. Create Attack Path (Lateral Movement from Pentest)
        src_entry = asset_map.get("ingress-nginx-lb-01")
        target_vault = asset_map.get("pci-hsm-vault-vm")
        path = MicroAttackPath(
            id=str(uuid.uuid4()),
            title="Lateral Movement Path: DMZ Ingress -> Mobile Gateway -> PCI Vault",
            description="Caminho de exploração identificado onde um comprometimento inicial no Ingress Nginx permite pivoteamento via gRPC para a API de pagamentos e acesso ao cofre de senhas PCI",
            risk_level="CRITICAL",
            entry_point_asset_id=src_entry.id if src_entry else None,
            target_asset_id=target_vault.id if target_vault else None,
            hops=[
                {"step": 1, "asset_name": "ingress-nginx-lb-01", "ip": "10.0.1.10", "type": "LOAD_BALANCER", "vuln": "CVE-2023-44487 HTTP/2 Rapid Reset"},
                {"step": 2, "asset_name": "mobile-gateway-pod-3c4d", "ip": "10.244.2.11", "type": "K8S_POD", "vuln": "Unauthenticated gRPC reflection debug endpoint"},
                {"step": 3, "asset_name": "payment-api-pod-9a1b", "ip": "10.244.1.22", "type": "K8S_POD", "vuln": "Hardcoded mTLS client key in container image"},
                {"step": 4, "asset_name": "pci-hsm-vault-vm", "ip": "10.0.4.99", "type": "VM_LINUX", "vuln": "Sensitive PCI Cardholder Data Store"}
            ],
            status="ACTIVE"
        )
        db.add(path)

        # 6. Security Alert
        alert = MicroSecurityAlert(
            id=str(uuid.uuid4()),
            title="Tentativa de Movimento Lateral Não Autorizado: DMZ para Database",
            severity="CRITICAL",
            source_asset_name="ingress-nginx-lb-01",
            destination_asset_name="postgres-primary-db",
            description="O ativo ingress-nginx-lb-01 (DMZ) tentou estabelecer uma conexão TCP na porta 5432 diretamente para postgres-primary-db. Conexão bloqueada pela política Zero Trust.",
            is_resolved=False
        )
        db.add(alert)

        # 7. Telemetry Sources
        telemetries = [
            {"name": "Hubble eBPF Cluster Collector", "type": "HUBBLE_EBPF", "url": "grpcs://hubble.prod.k8s.internal:443", "eps": 1250},
            {"name": "AWS VPC Flow Logs Ingestor", "type": "VPC_FLOW_LOGS", "url": "arn:aws:logs:us-east-1:123456789:log-group:vpc-flow", "eps": 3400},
            {"name": "Linux/Windows Node Microsegmentation Agent", "type": "AGENT_COLLECTOR", "url": "https://agent-hub.internal.sec:8443", "eps": 820}
        ]

        for t in telemetries:
            ts = MicroTelemetrySource(
                id=str(uuid.uuid4()),
                name=t["name"],
                source_type=t["type"],
                status="CONNECTED",
                endpoint_url=t["url"],
                events_per_second=t["eps"],
                last_heartbeat=datetime.now(timezone.utc)
            )
            db.add(ts)

        await db.commit()

        return {
            "status": "Success",
            "zones_created": len(zones_data),
            "assets_created": len(assets_data),
            "flows_created": len(flow_samples),
            "policies_created": len(policies_data)
        }

    @staticmethod
    async def get_overview(db: AsyncSession) -> Dict[str, Any]:
        """Calculates executive dashboard metrics."""
        # Ensure demo data exists
        await MicrosegmentationService.seed_demo_data(db)

        # Counts
        total_assets = (await db.execute(select(func.count(MicroAsset.id)))).scalar_one()
        total_zones = (await db.execute(select(func.count(MicroSegmentationZone.id)))).scalar_one()
        total_policies = (await db.execute(select(func.count(MicroNetworkPolicy.id)))).scalar_one()
        active_enforcing_policies = (await db.execute(
            select(func.count(MicroNetworkPolicy.id)).where(MicroNetworkPolicy.enforcement_mode == "ENFORCING")
        )).scalar_one()
        total_flows = (await db.execute(select(func.count(MicroNetworkFlow.id)))).scalar_one()
        blocked_flows = (await db.execute(
            select(func.count(MicroNetworkFlow.id)).where(MicroNetworkFlow.action.in_(["DENY", "VIOLATION", "DROPPED"]))
        )).scalar_one()
        active_attack_paths = (await db.execute(
            select(func.count(MicroAttackPath.id)).where(MicroAttackPath.status == "ACTIVE")
        )).scalar_one()
        unresolved_alerts = (await db.execute(
            select(func.count(MicroSecurityAlert.id)).where(MicroSecurityAlert.is_resolved == False)
        )).scalar_one()

        # Zero Trust Score Calculation
        zero_trust_score = round(min(100.0, max(0.0, (active_enforcing_policies / max(1, total_policies)) * 60.0 + (1.0 - (active_attack_paths * 0.15)) * 40.0)), 1)

        return {
            "health_score": zero_trust_score,
            "total_assets": total_assets,
            "total_zones": total_zones,
            "total_policies": total_policies,
            "active_enforcing_policies": active_enforcing_policies,
            "total_flows_monitored": total_flows,
            "blocked_violations_count": blocked_flows,
            "active_attack_paths": active_attack_paths,
            "unresolved_alerts_count": unresolved_alerts,
            "coverage_percentage": round((active_enforcing_policies / max(1, total_policies)) * 100, 1),
            "telemetry_status": "ONLINE (Hubble eBPF active)"
        }

    @staticmethod
    async def get_network_map(db: AsyncSession) -> Dict[str, Any]:
        """Returns topology graph nodes, edges and zones for interactive map rendering."""
        await MicrosegmentationService.seed_demo_data(db)

        zones = (await db.execute(select(MicroSegmentationZone))).scalars().all()
        assets = (await db.execute(select(MicroAsset))).scalars().all()
        flows = (await db.execute(select(MicroNetworkFlow))).scalars().all()

        nodes = []
        for a in assets:
            nodes.append({
                "id": a.id,
                "name": a.name,
                "ip": a.ip_address,
                "type": a.asset_type,
                "zone_id": a.zone_id,
                "status": a.status,
                "risk_score": a.risk_score,
                "labels": a.labels or {},
                "namespace": a.namespace
            })

        edges = []
        for f in flows:
            edges.append({
                "id": f.id,
                "source_id": f.source_asset_id,
                "source_name": f.source_name,
                "target_id": f.destination_asset_id,
                "target_name": f.destination_name,
                "port": f.destination_port,
                "protocol": f.protocol,
                "action": f.action,
                "is_anomaly": f.is_anomaly,
                "bytes": f.byte_count
            })

        return {
            "zones": [{"id": z.id, "name": z.name, "color": z.color, "strictness": z.strictness_level, "icon": z.icon} for z in zones],
            "nodes": nodes,
            "edges": edges
        }

    @staticmethod
    async def run_blast_radius_simulation(db: AsyncSession, source_zone_id: str, destination_zone_id: str, port: int, action: str) -> Dict[str, Any]:
        """Simulates what services will be impacted if a given policy rule is applied."""
        flows_stmt = select(MicroNetworkFlow)
        result = await db.execute(flows_stmt)
        all_flows = result.scalars().all()

        impacted_flows = [
            f for f in all_flows 
            if f.destination_port == port or port == 0
        ]

        return {
            "simulation_id": str(uuid.uuid4()),
            "proposed_action": action,
            "target_port": port,
            "total_flows_evaluated": len(all_flows),
            "impacted_active_connections": len(impacted_flows),
            "services_broken_count": len(set(f.destination_name for f in impacted_flows if f.destination_name)),
            "impacted_service_names": list(set(f.destination_name for f in impacted_flows if f.destination_name)),
            "safety_verdict": "SAFE_TO_ENFORCE" if len(impacted_flows) == 0 else "WARNING_ACTIVE_TRAFFIC_DETECTED",
            "recommendation": "Aplicação segura. Nenhuma aplicação ativa utiliza este fluxo no momento." if len(impacted_flows) == 0 else f"Atenção: {len(impacted_flows)} conexões ativas serão interrompidas imediatamente!"
        }
