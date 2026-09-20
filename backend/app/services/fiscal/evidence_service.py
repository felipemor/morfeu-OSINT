"""Evidence Vault & Audit Trail Service — Cryptographic custody with SHA-256 integrity."""
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class EvidenceVaultService:
    """Manages immutable evidence snippets with SHA-256 hashes and row-level lineage."""

    @staticmethod
    def compute_sha256(data: Dict[str, Any]) -> str:
        """Computes deterministic SHA-256 hash of a dictionary."""
        s = json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    @classmethod
    def create_evidence_entry(
        cls,
        dataset_id: str,
        finding_id: Optional[str],
        row_number: int,
        raw_row: Dict[str, Any],
        normalized_row: Dict[str, Any],
        source_file: str,
    ) -> Dict[str, Any]:
        """Creates an evidence structure with cryptographic hash for chain-of-custody."""
        evidence_payload = {
            "dataset_id": dataset_id,
            "row_number": row_number,
            "original_snippet": raw_row,
            "normalized_snippet": normalized_row,
            "source_file": source_file,
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }
        sha256_hash = cls.compute_sha256(evidence_payload)

        return {
            **evidence_payload,
            "finding_id": finding_id,
            "sha256_hash": sha256_hash,
            "integrity_verified": True,
        }

    @classmethod
    def verify_evidence_integrity(cls, evidence_dict: Dict[str, Any]) -> bool:
        """Verifies if the evidence hash matches its stored content."""
        stored_hash = evidence_dict.get("sha256_hash")
        if not stored_hash:
            return False

        clone = {k: v for k, v in evidence_dict.items() if k not in ("finding_id", "sha256_hash", "integrity_verified", "id")}
        computed = cls.compute_sha256(clone)
        return computed == stored_hash
