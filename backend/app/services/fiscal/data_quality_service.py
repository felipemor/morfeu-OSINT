"""Data Quality Engine — Pre-audit ingestion validation and quality scoring."""
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


class DataQualityEngine:
    """Validates records, flags data anomalies, and calculates the Data Quality Score."""

    @staticmethod
    def validate_cpf(cpf: str) -> bool:
        """Validates Brazilian CPF check-digits (Módulo 11)."""
        clean = re.sub(r"\D", "", cpf)
        if len(clean) != 11 or clean == clean[0] * 11:
            return False

        # First digit
        s = sum(int(clean[i]) * (10 - i) for i in range(9))
        d1 = 11 - (s % 11)
        d1 = 0 if d1 >= 10 else d1
        if int(clean[9]) != d1:
            return False

        # Second digit
        s = sum(int(clean[i]) * (11 - i) for i in range(10))
        d2 = 11 - (s % 11)
        d2 = 0 if d2 >= 10 else d2
        return int(clean[10]) == d2

    @staticmethod
    def validate_cnpj(cnpj: str) -> bool:
        """Validates Brazilian CNPJ check-digits (Módulo 11)."""
        clean = re.sub(r"\D", "", cnpj)
        if len(clean) != 14 or clean == clean[0] * 14:
            return False

        weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
        weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]

        # First digit
        s1 = sum(int(clean[i]) * weights1[i] for i in range(12))
        r1 = s1 % 11
        d1 = 0 if r1 < 2 else 11 - r1
        if int(clean[12]) != d1:
            return False

        # Second digit
        s2 = sum(int(clean[i]) * weights2[i] for i in range(13))
        r2 = s2 % 11
        d2 = 0 if r2 < 2 else 11 - r2
        return int(clean[13]) == d2

    @classmethod
    def validate_tax_id(cls, tax_id: Optional[str]) -> Tuple[bool, str]:
        """Validates a generic tax ID (CPF or CNPJ)."""
        if not tax_id:
            return False, "MISSING_TAX_ID"
        clean = re.sub(r"\D", "", tax_id)
        if len(clean) == 11:
            return (True, "VALID_CPF") if cls.validate_cpf(clean) else (False, "INVALID_CPF_CHECKSUM")
        elif len(clean) == 14:
            return (True, "VALID_CNPJ") if cls.validate_cnpj(clean) else (False, "INVALID_CNPJ_CHECKSUM")
        return False, "INVALID_TAX_ID_LENGTH"

    @classmethod
    def validate_record(cls, record: Dict[str, Any], seen_keys: set) -> Tuple[bool, List[str]]:
        """Performs multi-rule data quality check on a normalized record."""
        flags: List[str] = []

        # 1. Amount check
        amount = record.get("amount")
        if amount is None:
            flags.append("NULL_AMOUNT")
        elif amount <= 0:
            flags.append("ZERO_OR_NEGATIVE_AMOUNT")

        # 2. Invoice number check
        if not record.get("invoice_number"):
            flags.append("MISSING_INVOICE_NUMBER")

        # 3. Invoice date check
        dt_str = record.get("invoice_date")
        if not dt_str:
            flags.append("MISSING_INVOICE_DATE")
        else:
            try:
                dt = datetime.fromisoformat(dt_str)
                now = datetime.now(timezone.utc).replace(tzinfo=None)
                if dt.year < 1990:
                    flags.append("ANCIENT_DATE")
                elif (dt - now).days > 30:
                    flags.append("FUTURE_DATE")
            except Exception:
                flags.append("INVALID_DATE_FORMAT")

        # 4. Supplier tax ID check
        sup_tax = record.get("supplier_tax_id")
        if sup_tax:
            valid, reason = cls.validate_tax_id(sup_tax)
            if not valid:
                flags.append(reason)
        else:
            flags.append("MISSING_SUPPLIER_TAX_ID")

        # 5. Duplicate check
        key = (
            record.get("invoice_number"),
            record.get("supplier_tax_id"),
            round(record.get("amount", 0.0), 2),
            record.get("invoice_date", "")[:10] if record.get("invoice_date") else "",
        )
        if all(key) and key in seen_keys:
            flags.append("DUPLICATE_RECORD")
        elif all(key):
            seen_keys.add(key)

        is_valid = len([f for f in flags if not f.startswith("VALID_")]) == 0
        return is_valid, flags

    @classmethod
    def evaluate_dataset_quality(cls, normalized_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluates entire dataset quality and generates comprehensive quality metrics."""
        total = len(normalized_records)
        if total == 0:
            return {
                "total_records": 0,
                "valid_records": 0,
                "data_quality_score": 0.0,
                "issues_count": 0,
                "issues_breakdown": {},
            }

        seen_keys = set()
        valid_count = 0
        issues_breakdown: Dict[str, int] = {}

        for rec in normalized_records:
            is_valid, flags = cls.validate_record(rec, seen_keys)
            if is_valid:
                valid_count += 1
            for flag in flags:
                issues_breakdown[flag] = issues_breakdown.get(flag, 0) + 1

        quality_score = round((valid_count / total) * 100.0, 1)

        return {
            "total_records": total,
            "valid_records": valid_count,
            "invalid_records": total - valid_count,
            "data_quality_score": quality_score,
            "issues_count": sum(issues_breakdown.values()),
            "issues_breakdown": issues_breakdown,
            "quality_status": "EXCELLENT" if quality_score >= 95 else "GOOD" if quality_score >= 85 else "WARNING" if quality_score >= 70 else "CRITICAL",
        }
