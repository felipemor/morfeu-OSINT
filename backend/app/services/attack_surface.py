"""
Attack Surface Graph Service — Models and queries full attack surface topology

Entities:
  Organization → Project → Domain → Subdomain → IP → Port → Application →
  Technology → Endpoint → Parameter → Authentication → Finding → Evidence
"""
from dataclasses import dataclass, field
from typing import Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import structlog

from app.models import Asset, Endpoint, Finding, Project, Target, Evidence, BusinessCriticality, Severity

logger = structlog.get_logger(__name__)


@dataclass
class GraphNode:
    id: str
    label: str
    node_type: str  # domain, subdomain, ip, port, app, endpoint, finding
    criticality: str = "MEDIUM"
    metadata: dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str  # resolves_to, opens_port, hosts_app, exposes_endpoint, has_finding


class AttackSurfaceService:
    """Service to construct, query, and analyze the Attack Surface Graph."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_attack_surface_graph(self, project_id: str) -> dict[str, Any]:
        """
        Builds the complete node-edge graph representation of the project's attack surface.
        """
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        seen_nodes: set[str] = set()

        def add_node(node_id: str, label: str, n_type: str, criticality: str = "MEDIUM", meta: dict = None):
            if node_id not in seen_nodes:
                seen_nodes.add(node_id)
                nodes.append({
                    "id": node_id,
                    "label": label,
                    "type": n_type,
                    "criticality": criticality,
                    "metadata": meta or {},
                })

        def add_edge(src: str, dst: str, relation: str):
            edges.append({
                "source": src,
                "target": dst,
                "relation": relation,
            })

        # 1. Fetch Assets
        asset_res = await self.db.execute(select(Asset).where(Asset.project_id == project_id))
        assets = asset_res.scalars().all()

        # 2. Fetch Endpoints
        ep_res = await self.db.execute(select(Endpoint).where(Endpoint.project_id == project_id))
        endpoints = ep_res.scalars().all()

        # 3. Fetch Findings
        finding_res = await self.db.execute(select(Finding).where(Finding.project_id == project_id))
        findings = finding_res.scalars().all()

        # Map Assets to graph
        for asset in assets:
            crit_str = asset.business_criticality.value if asset.business_criticality else "MEDIUM"
            asset_node_id = f"asset:{asset.id}"
            add_node(
                node_id=asset_node_id,
                label=asset.value,
                n_type=asset.asset_type.value.lower(),
                criticality=crit_str,
                meta={
                    "ip": asset.ip_address,
                    "port": asset.port,
                    "technologies": asset.technologies,
                    "is_internet_facing": asset.is_internet_facing,
                    "agent_id": asset.agent_id,
                    "hostname": asset.hostname,
                    "os_info": asset.os_info,
                },
            )

            # If agent is attached, create Agent node and link
            if asset.agent_id:
                agent_node_id = f"agent:{asset.agent_id}"
                add_node(
                    node_id=agent_node_id,
                    label=f"Agent ({asset.hostname or asset.value})",
                    n_type="endpoint_agent",
                    criticality=crit_str,
                    meta={"agent_id": asset.agent_id, "os_info": asset.os_info},
                )
                add_edge(src=asset_node_id, dst=agent_node_id, relation="monitored_by")

            # If IP exists, create IP node and link
            if asset.ip_address:
                ip_node_id = f"ip:{asset.ip_address}"
                add_node(
                    node_id=ip_node_id,
                    label=asset.ip_address,
                    n_type="ip",
                    criticality=crit_str,
                )
                add_edge(src=asset_node_id, dst=ip_node_id, relation="resolves_to")

                # If port exists, link port
                if asset.port:
                    port_node_id = f"port:{asset.ip_address}:{asset.port}"
                    add_node(
                        node_id=port_node_id,
                        label=f"{asset.protocol or 'tcp'}:{asset.port}",
                        n_type="port",
                        criticality=crit_str,
                    )
                    add_edge(src=ip_node_id, dst=port_node_id, relation="opens_port")

        # Map Endpoints
        for ep in endpoints:
            ep_node_id = f"endpoint:{ep.id}"
            parent_asset_id = f"asset:{ep.asset_id}"
            add_node(
                node_id=ep_node_id,
                label=f"{ep.method} {ep.path}",
                n_type="endpoint",
                meta={
                    "url": ep.url,
                    "is_api": ep.is_api,
                    "auth_required": ep.auth_required,
                    "parameters": ep.parameters,
                },
            )
            add_edge(src=parent_asset_id, dst=ep_node_id, relation="exposes_endpoint")

        # Map Findings
        for finding in findings:
            f_node_id = f"finding:{finding.id}"
            add_node(
                node_id=f_node_id,
                label=finding.title,
                n_type="finding",
                criticality=finding.severity.value,
                meta={
                    "severity": finding.severity.value,
                    "cwe": finding.cwe_id,
                    "owasp": finding.owasp_category,
                    "status": finding.status.value,
                },
            )
            if finding.endpoint_id:
                add_edge(src=f"endpoint:{finding.endpoint_id}", dst=f_node_id, relation="has_finding")
            elif finding.asset_id:
                add_edge(src=f"asset:{finding.asset_id}", dst=f_node_id, relation="has_finding")

        return {
            "project_id": project_id,
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
        }

    async def get_exposed_assets(self, project_id: str) -> list[dict[str, Any]]:
        """Returns internet-facing assets with exposure details."""
        result = await self.db.execute(
            select(Asset).where(
                Asset.project_id == project_id,
                Asset.is_internet_facing == True,
            )
        )
        assets = result.scalars().all()
        return [
            {
                "id": a.id,
                "value": a.value,
                "type": a.asset_type.value,
                "ip": a.ip_address,
                "port": a.port,
                "technologies": a.technologies,
                "criticality": a.business_criticality.value,
            }
            for a in assets
        ]

    async def get_shared_infrastructure(self, project_id: str) -> dict[str, list[str]]:
        """Identifies domains/subdomains sharing identical IP addresses."""
        result = await self.db.execute(
            select(Asset.ip_address, Asset.value).where(
                Asset.project_id == project_id,
                Asset.ip_address.isnot(None),
            )
        )
        rows = result.all()
        ip_map: dict[str, list[str]] = {}
        for ip, host in rows:
            if ip not in ip_map:
                ip_map[ip] = []
            if host not in ip_map[ip]:
                ip_map[ip].append(host)

        # Filter only IPs with 2+ hosts
        return {ip: hosts for ip, hosts in ip_map.items() if len(hosts) > 1}

    async def get_authenticated_endpoints(self, project_id: str) -> list[dict[str, Any]]:
        """Returns endpoints requiring authentication."""
        result = await self.db.execute(
            select(Endpoint).where(
                Endpoint.project_id == project_id,
                Endpoint.auth_required == True,
            )
        )
        endpoints = result.scalars().all()
        return [
            {
                "id": ep.id,
                "url": ep.url,
                "method": ep.method,
                "path": ep.path,
                "auth_type": ep.auth_type,
            }
            for ep in endpoints
        ]
