"""Entity Resolution & Forensic Graph Engine — Counterparty normalization, HHI index, and network analytics."""
import difflib
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple


class EntityGraphEngine:
    """Builds the forensic entity graph, computes HHI concentration, and resolves counterparty aliases."""

    @staticmethod
    def normalize_name(name: Optional[str]) -> str:
        """Standardizes company names for fuzzy clustering."""
        if not name:
            return "ENTIDADE_DESCONHECIDA"
        s = str(name).upper().strip()
        for suffix in [" LTDA", " S.A.", " SA", " S/A", " ME", " EPP", " EIRELI", " - ME", " - EPP"]:
            if s.endswith(suffix):
                s = s[:-len(suffix)].strip()
        return s

    @classmethod
    def resolve_entities(cls, records: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Clusters and normalizes counterparties across the entire dataset."""
        entities: Dict[str, Dict[str, Any]] = {}

        for r in records:
            tax_id = r.get("supplier_tax_id")
            if not tax_id:
                continue

            raw_name = r.get("supplier_name") or f"Fornecedor {tax_id[:4]}...{tax_id[-2:]}"
            norm_name = cls.normalize_name(raw_name)
            amt = r.get("amount", 0.0)

            if tax_id not in entities:
                entities[tax_id] = {
                    "tax_id": tax_id,
                    "canonical_name": raw_name,
                    "normalized_name": norm_name,
                    "aliases": set([raw_name]),
                    "total_volume": 0.0,
                    "transaction_count": 0,
                    "entity_type": "SUPPLIER",
                    "customers": set(),
                }

            entities[tax_id]["total_volume"] += amt
            entities[tax_id]["transaction_count"] += 1
            entities[tax_id]["aliases"].add(raw_name)
            cust_id = r.get("customer_tax_id")
            if cust_id:
                entities[tax_id]["customers"].add(cust_id)

        # Convert sets to lists
        for tax_id, data in entities.items():
            data["aliases"] = list(data["aliases"])
            data["customers"] = list(data["customers"])
            data["average_ticket"] = round(data["total_volume"] / data["transaction_count"], 2) if data["transaction_count"] else 0.0
            data["total_volume"] = round(data["total_volume"], 2)

        return entities

    @classmethod
    def calculate_hhi_concentration(cls, entities: Dict[str, Dict[str, Any]], total_volume: float) -> Dict[str, Any]:
        """Calculates Herfindahl-Hirschman Index (HHI) for spend concentration."""
        if total_volume <= 0:
            return {"hhi_index": 0.0, "classification": "UNCONCENTRATED", "top_shares": []}

        shares = []
        hhi = 0.0
        for tax_id, ent in entities.items():
            share_pct = (ent["total_volume"] / total_volume) * 100.0
            shares.append({
                "tax_id": tax_id,
                "name": ent["canonical_name"],
                "volume": ent["total_volume"],
                "share_pct": round(share_pct, 2),
            })
            hhi += (share_pct ** 2)

        shares.sort(key=lambda x: x["volume"], reverse=True)
        hhi = round(hhi, 1)

        classification = (
            "HIGHLY_CONCENTRATED" if hhi >= 2500 else
            "MODERATELY_CONCENTRATED" if hhi >= 1500 else
            "UNCONCENTRATED"
        )

        return {
            "hhi_index": hhi,
            "classification": classification,
            "top_suppliers": shares[:10],
            "top_1_concentration_pct": shares[0]["share_pct"] if shares else 0.0,
            "top_5_concentration_pct": round(sum(s["share_pct"] for s in shares[:5]), 2) if len(shares) >= 5 else 100.0,
        }

    @classmethod
    def build_network_graph(cls, records: List[Dict[str, Any]], max_nodes: int = 60) -> Dict[str, Any]:
        """Builds interactive node-link graph data (compatible with ECharts & D3)."""
        nodes_dict: Dict[str, Dict[str, Any]] = {}
        links_dict: Dict[Tuple[str, str], float] = defaultdict(float)

        for r in records:
            sup = r.get("supplier_tax_id")
            cust = r.get("customer_tax_id") or "EMPRESA_PRINCIPAL"
            amt = r.get("amount", 0.0)

            if not sup:
                continue

            # Add / update nodes
            if sup not in nodes_dict:
                nodes_dict[sup] = {
                    "id": sup,
                    "name": r.get("supplier_name") or sup,
                    "category": "SUPPLIER",
                    "value": 0.0,
                    "symbolSize": 20,
                }
            nodes_dict[sup]["value"] += amt

            if cust not in nodes_dict:
                nodes_dict[cust] = {
                    "id": cust,
                    "name": r.get("customer_name") or cust,
                    "category": "COMPANY",
                    "value": 0.0,
                    "symbolSize": 35,
                }
            nodes_dict[cust]["value"] += amt

            links_dict[(sup, cust)] += amt

        # Limit to top nodes by volume
        sorted_nodes = sorted(nodes_dict.values(), key=lambda x: x["value"], reverse=True)[:max_nodes]
        allowed_ids = set(n["id"] for n in sorted_nodes)

        # Scale symbol size
        max_val = max((n["value"] for n in sorted_nodes), default=1.0)
        for n in sorted_nodes:
            ratio = n["value"] / max_val if max_val else 0.1
            n["symbolSize"] = int(18 + (ratio * 40))
            n["value"] = round(n["value"], 2)

        links = []
        for (source, target), weight in links_dict.items():
            if source in allowed_ids and target in allowed_ids:
                links.append({
                    "source": source,
                    "target": target,
                    "value": round(weight, 2),
                    "label": f"R$ {weight:,.0f}",
                })

        return {
            "nodes": sorted_nodes,
            "links": links,
            "categories": [
                {"name": "COMPANY"},
                {"name": "SUPPLIER"},
                {"name": "CUSTOMER"},
            ],
        }
