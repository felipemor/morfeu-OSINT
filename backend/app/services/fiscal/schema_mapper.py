"""Smart Schema Mapper — Auto-detection and normalization for heterogeneous fiscal datasets."""
import re
import difflib
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

CANONICAL_FIELDS = {
    "invoice_number": [
        "numero", "numero_nf", "num_nf", "nf", "n_nf", "documento", "num_doc", "nota_fiscal",
        "n_documento", "invoice_number", "doc_number", "nfe_num", "chave_nfe", "num_fatura"
    ],
    "invoice_date": [
        "data", "data_emissao", "dt_emissao", "emissao", "dt_lancamento", "data_lancamento",
        "data_nota", "dt_doc", "invoice_date", "issue_date", "competencia", "periodo", "data_fato"
    ],
    "amount": [
        "valor", "valor_total", "vl_total", "valor_nota", "vl_nota", "total", "vl_tot_nota",
        "valor_bruto", "vl_bruto", "valor_liquido", "vl_liq", "amount", "invoice_amount", "valor_operacao"
    ],
    "supplier_tax_id": [
        "cnpj_fornecedor", "cnpj_emitente", "cpf_fornecedor", "cnpj_prestador", "tax_id_fornecedor",
        "cnpj_cpf_fornecedor", "cnpj_emit", "cpf_cnpj_fornecedor", "supplier_tax_id", "cnpj_cedente"
    ],
    "supplier_name": [
        "fornecedor", "nome_fornecedor", "razao_social_fornecedor", "emitente", "nome_emitente",
        "razao_social", "prestador", "nome_prestador", "supplier_name", "cedente", "nome_fantasia_forn"
    ],
    "customer_tax_id": [
        "cnpj_cliente", "cnpj_destinatario", "cpf_cliente", "cnpj_tomador", "tax_id_cliente",
        "cnpj_cpf_cliente", "cnpj_dest", "cpf_cnpj_cliente", "customer_tax_id", "cnpj_sacado"
    ],
    "customer_name": [
        "cliente", "nome_cliente", "razao_social_cliente", "destinatario", "nome_destinatario",
        "tomador", "nome_tomador", "customer_name", "sacado", "comprador"
    ],
    "tax_icms": ["icms", "vl_icms", "valor_icms", "vlicms", "tax_icms", "icms_proprio"],
    "tax_ipi": ["ipi", "vl_ipi", "valor_ipi", "vlipi", "tax_ipi"],
    "tax_iss": ["iss", "vl_iss", "valor_iss", "vliss", "tax_iss", "issqn"],
    "tax_pis": ["pis", "vl_pis", "valor_pis", "vlpis", "tax_pis"],
    "tax_cofins": ["cofins", "vl_cofins", "valor_cofins", "vlcofins", "tax_cofins"],
    "cfop": ["cfop", "cod_cfop", "codigo_cfop", "natureza_operacao"],
    "ncm": ["ncm", "cod_ncm", "codigo_ncm", "classificacao_fiscal"],
}


class SmartSchemaMapper:
    """Intelligently detects column types, maps headers with confidence, and normalizes rows."""

    @staticmethod
    def clean_header_name(header: str) -> str:
        s = str(header).lower().strip()
        s = re.sub(r"[^\w\s]", "_", s)
        s = re.sub(r"\s+", "_", s)
        return s

    @classmethod
    def match_column(cls, header: str, sample_values: Optional[List[Any]] = None) -> Tuple[Optional[str], float]:
        """Matches a single header string against canonical fiscal fields."""
        clean = cls.clean_header_name(header)

        # 1. Exact match in canonical lists
        for field, variants in CANONICAL_FIELDS.items():
            if clean in variants:
                return field, 1.0

        # 2. Fuzzy substring / string similarity
        best_field = None
        best_score = 0.0

        for field, variants in CANONICAL_FIELDS.items():
            for var in variants:
                ratio = difflib.SequenceMatcher(None, clean, var).ratio()
                if clean in var or var in clean:
                    ratio = max(ratio, 0.85)
                if ratio > best_score:
                    best_score = ratio
                    best_field = field

        # 3. Content-based heuristic boost if sample values provided
        if sample_values and best_score < 0.80:
            str_samples = [str(v).strip() for v in sample_values if v is not None and str(v).strip()]
            if str_samples:
                # CNPJ / CPF pattern
                if any(re.match(r"^\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}$", s) or re.match(r"^\d{3}\.?\d{3}\.?\d{3}-?\d{2}$", s) for s in str_samples):
                    if "forn" in clean or "emit" in clean or "prest" in clean:
                        return "supplier_tax_id", 0.92
                    elif "cli" in clean or "dest" in clean or "tom" in clean:
                        return "customer_tax_id", 0.92
                    return "supplier_tax_id", 0.85

                # Monetary value pattern
                if any(re.match(r"^R?\$?\s*-?\d{1,3}(\.\d{3})*,\d{2}$", s) or re.match(r"^-?\d+\.\d{2}$", s) for s in str_samples):
                    if "icms" in clean:
                        return "tax_icms", 0.90
                    if "ipi" in clean:
                        return "tax_ipi", 0.90
                    return "amount", 0.88

                # Date pattern
                if any(re.match(r"^\d{2}/\d{2}/\d{4}$", s) or re.match(r"^\d{4}-\d{2}-\d{2}", s) for s in str_samples):
                    return "invoice_date", 0.90

        if best_score >= 0.65:
            return best_field, round(best_score, 2)

        return None, 0.0

    @classmethod
    def map_dataset_columns(cls, headers: List[str], sample_rows: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Dict[str, Any]]:
        """Maps all columns of a dataset and returns mapping details with confidence."""
        mapping: Dict[str, Dict[str, Any]] = {}
        assigned_fields = set()

        for header in headers:
            samples = []
            if sample_rows:
                samples = [row.get(header) for row in sample_rows[:20] if header in row]

            matched_field, confidence = cls.match_column(header, samples)
            if matched_field and matched_field not in assigned_fields and confidence >= 0.65:
                mapping[header] = {
                    "canonical_field": matched_field,
                    "confidence": confidence,
                    "auto_detected": True,
                }
                assigned_fields.add(matched_field)
            else:
                mapping[header] = {
                    "canonical_field": None,
                    "confidence": confidence if matched_field else 0.0,
                    "auto_detected": False,
                }

        return mapping

    @staticmethod
    def parse_numeric(val: Any) -> Optional[float]:
        """Converts strings like '1.250.430,50' or 'R$ 500,00' or 123.45 to float."""
        if val is None or val == "":
            return None
        if isinstance(val, (int, float)):
            return float(val)

        s = str(val).strip()
        s = re.sub(r"[R$\s]", "", s)
        # Check Brazilian format (1.234,56)
        if "," in s and "." in s:
            if s.rfind(",") > s.rfind("."):
                s = s.replace(".", "").replace(",", ".")
            else:
                s = s.replace(",", "")
        elif "," in s:
            s = s.replace(",", ".")

        try:
            return float(s)
        except ValueError:
            return None

    @staticmethod
    def parse_date(val: Any) -> Optional[datetime]:
        """Parses various date formats (DD/MM/YYYY, YYYY-MM-DD, etc)."""
        if val is None or val == "":
            return None
        if isinstance(val, datetime):
            return val

        s = str(val).strip()
        formats = [
            "%d/%m/%Y", "%d/%m/%Y %H:%M:%S", "%Y-%m-%d", "%Y-%m-%d %H:%M:%S",
            "%d-%m-%Y", "%Y/%m/%d", "%d.%m.%Y", "%Y%m%d"
        ]
        for fmt in formats:
            try:
                return datetime.strptime(s.split("T")[0] if "T" in s else s, fmt)
            except ValueError:
                continue
        return None

    @staticmethod
    def clean_tax_id(val: Any) -> Optional[str]:
        """Strips non-digits from CNPJ/CPF and returns standard 11 or 14 char string."""
        if val is None:
            return None
        s = re.sub(r"\D", "", str(val).strip())
        if len(s) in (11, 14):
            return s
        if len(s) < 11 and len(s) > 0:
            return s.zfill(11)
        if len(s) < 14 and len(s) > 11:
            return s.zfill(14)
        return s if s else None

    @classmethod
    def normalize_record(cls, raw_row: Dict[str, Any], mapping: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Transforms a raw data dictionary into canonical fiscal fields."""
        norm: Dict[str, Any] = {
            "invoice_number": None,
            "invoice_date": None,
            "amount": 0.0,
            "supplier_tax_id": None,
            "supplier_name": None,
            "customer_tax_id": None,
            "customer_name": None,
            "tax_icms": None,
            "tax_ipi": None,
            "tax_iss": None,
            "tax_pis": None,
            "tax_cofins": None,
            "cfop": None,
            "ncm": None,
        }

        for col, meta in mapping.items():
            canonical = meta.get("canonical_field")
            if not canonical or canonical not in norm:
                continue
            raw_val = raw_row.get(col)
            if raw_val is None:
                continue

            if canonical in ("amount", "tax_icms", "tax_ipi", "tax_iss", "tax_pis", "tax_cofins"):
                norm[canonical] = cls.parse_numeric(raw_val)
            elif canonical == "invoice_date":
                dt = cls.parse_date(raw_val)
                norm[canonical] = dt.isoformat() if dt else None
            elif canonical in ("supplier_tax_id", "customer_tax_id"):
                norm[canonical] = cls.clean_tax_id(raw_val)
            elif canonical in ("supplier_name", "customer_name"):
                norm[canonical] = str(raw_val).strip()
            elif canonical in ("invoice_number", "cfop", "ncm"):
                norm[canonical] = str(raw_val).strip()

        if norm["amount"] is None:
            norm["amount"] = 0.0

        return norm
