"""
FRAUDINTEL — Fraud Graph Service
Interactive relational graph model with typed nodes and edges.
"""

from typing import List, Dict, Any

class FraudGraphService:
    @staticmethod
    def build_case_graph(case_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Builds a full relational graph consisting of typed Nodes and Edges:
        Node types: Person, Company, CNPJ, Bank, Account, Boleto, Domain, IP, ASN, Certificate, URL, Brand, Case, Evidence
        Edge types: IMPERSONATES, RESOLVES_TO, HOSTED_ON, USES_CERT, OWNS, PAYS, RELATED_TO, CONNECTED_TO
        """
        nodes = []
        edges = []
        node_ids = set()

        def add_node(nid: str, label: str, ntype: str, metadata: Dict[str, Any] = None):
            if nid not in node_ids:
                node_ids.add(nid)
                nodes.append({
                    "id": nid,
                    "label": label,
                    "type": ntype,
                    "metadata": metadata or {}
                })

        def add_edge(src: str, tgt: str, rel: str, weight: float = 1.0):
            edges.append({
                "id": f"e-{src}-{tgt}-{rel}",
                "source": src,
                "target": tgt,
                "relation": rel,
                "weight": weight
            })

        # 1. Central Case Node
        cid = case_data.get("id", "FRD-CASE-01")
        add_node(cid, f"Case #{cid}", "Case", {"severity": case_data.get("severity", "HIGH"), "status": case_data.get("status")})

        # 2. Brand Victim Node
        brand_name = case_data.get("brand_victim", "Marca Oficial")
        bid = f"brand-{brand_name.lower().replace(' ', '')}"
        add_node(bid, brand_name, "Brand", {"is_victim": True})

        # 3. Target Asset / Domain
        target_asset = case_data.get("target_asset", "target.com")
        did = f"dom-{target_asset.replace('https://', '').replace('http://', '').split('/')[0]}"
        add_node(did, target_asset, "Domain", {"risk": case_data.get("risk_score", {}).get("score", 85)})

        add_edge(did, bid, "IMPERSONATES", 0.95)
        add_edge(cid, did, "INVESTIGATES", 1.0)

        # 4. Extract Entities
        for ent in case_data.get("entities", []):
            eid = ent.get("id") or f"ent-{ent.get('type')}-{len(nodes)}"
            ename = ent.get("name", "Entidade")
            etype = ent.get("type", "Entity")
            add_node(eid, ename, etype, {"role": ent.get("role")})

            if etype == "IP":
                add_edge(did, eid, "RESOLVES_TO", 0.9)
            elif etype == "ASN":
                add_edge(eid, did, "HOSTED_ON", 0.8)
            elif etype == "Certificate":
                add_edge(did, eid, "USES_CERT", 0.85)
            elif etype == "CNPJ":
                add_edge(did, eid, "DISPLAYS_FOOTER_CNPJ", 0.75)
                add_edge(cid, eid, "EXAMINES", 0.8)
            elif etype == "Boleto":
                add_edge(did, eid, "GENERATES_BOLETO", 0.9)
            else:
                add_edge(cid, eid, "ASSOCIATED_WITH", 0.5)

        # 5. Evidences
        for ev in case_data.get("evidences", []):
            evid = ev.get("id")
            evtype = ev.get("type", "Evidence")
            add_node(evid, f"Evidência: {evid}", "Evidence", {"sha256": ev.get("sha256")})
            add_edge(cid, evid, "PROVES", 1.0)
            add_edge(evid, did, "CAPTURES_ASSET", 0.9)

        return {
            "case_id": cid,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "nodes": nodes,
            "edges": edges
        }

fraud_graph_service = FraudGraphService()
