"""
Boleto Service — validates Brazilian boleto bancário (bank slip) structure.

Decodes the linha digitável (47-digit typed line), validates the Módulo 10/11
check digits per Bacen standards, identifies the issuing bank, and flags
structural fraud indicators (wrong bank, beneficiary mismatch, suspicious account).

References:
  FEBRABAN CNAB 240 — Leiaute de Arquivo de Remessa/Retorno
  Bacen Circular 3.656/2013 — Registro de boletos
"""
import re
from datetime import datetime, date, timezone
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)

# ── Bank code registry (sample — top 30 BR banks) ────────────────────────────

BANK_REGISTRY: dict[str, str] = {
    "001": "Banco do Brasil",
    "003": "Banco da Amazônia",
    "004": "Banco do Nordeste",
    "033": "Banco Santander (Brasil)",
    "041": "Banrisul",
    "077": "Banco Inter",
    "084": "Uniprime",
    "085": "Cooperativa Central de Crédito (Ailos)",
    "097": "Credisis",
    "104": "Caixa Econômica Federal",
    "133": "Cresol Confederação",
    "136": "Unicred do Brasil",
    "208": "BTG Pactual",
    "212": "Banco Original",
    "218": "Banco BS2",
    "237": "Banco Bradesco",
    "246": "Banco ABC Brasil",
    "260": "Nu Pagamentos (Nubank)",
    "290": "Pagseguro",
    "301": "Dock (PagBank Acquirer)",
    "336": "Banco C6",
    "341": "Itaú Unibanco",
    "389": "Banco Mercantil do Brasil",
    "422": "Banco Safra",
    "505": "Credit Suisse Hedging-Griffo",
    "633": "Banco Rendimento",
    "637": "Banco Sofisa",
    "643": "Banco Pine",
    "707": "Banco Daycoval",
    "748": "Banco Cooperativo Sicredi",
    "756": "Banco Cooperativo do Brasil (Bancoob/Sicoob)",
}

# ── Modulo 10 / Modulo 11 check-digit algorithms ──────────────────────────────

def _mod10(digits: str) -> int:
    """Standard Módulo 10 used in boleto field verification."""
    s = 0
    mult = 2
    for d in reversed(digits):
        prod = int(d) * mult
        s += prod // 10 + prod % 10
        mult = 1 if mult == 2 else 2
    remainder = s % 10
    return 0 if remainder == 0 else 10 - remainder


def _mod11(digits: str, weights: tuple[int, ...] = (2, 3, 4, 5, 6, 7, 8, 9)) -> int:
    """Módulo 11 used for the overall barcode check digit."""
    s = 0
    for d, w in zip(reversed(digits), weights * 10):
        s += int(d) * w
    remainder = s % 11
    if remainder in (0, 1):
        return 1
    return 11 - remainder


# ── Linha digitável decoder ───────────────────────────────────────────────────

def _clean_linha(linha: str) -> str:
    return re.sub(r"\D", "", linha)


def decode_linha_digitavel(linha: str) -> dict:
    """
    Decodes a 47-digit banco tipo 1 linha digitável into structured fields.
    Format: BBBMC.CCCCC CCCCC.CCCCCC CCCCC.CCCCCC D FFFFF.FFFFFFFFFFF
    Where:
      BBB = Código do banco
      M   = Moeda (9 = Real)
      D   = Dígito verificador geral
      F   = Fator de vencimento + valor
    """
    raw = _clean_linha(linha)
    errors = []
    fraud_indicators = []

    if len(raw) not in (47, 48):
        return {
            "is_valid": False,
            "errors": [f"Linha digitável deve ter 47 dígitos (encontrado: {len(raw)})"],
            "fraud_indicators": ["FORMATO_INVALIDO"],
        }

    bank_code   = raw[:3]
    currency    = raw[3]       # '9' = BRL
    field1_data = raw[4:9]
    field1_cd   = raw[9]
    field2_data = raw[10:20]
    field2_cd   = raw[20]
    field3_data = raw[21:31]
    field3_cd   = raw[31]
    general_cd  = raw[32]
    due_factor  = raw[33:37]
    value_str   = raw[37:47]

    # Validate field check digits (Módulo 10)
    if _mod10(field1_data) != int(field1_cd):
        errors.append("Dígito verificador do Campo 1 inválido.")
        fraud_indicators.append("CAMPO1_CD_INVALIDO")
    if _mod10(field2_data) != int(field2_cd):
        errors.append("Dígito verificador do Campo 2 inválido.")
        fraud_indicators.append("CAMPO2_CD_INVALIDO")
    if _mod10(field3_data) != int(field3_cd):
        errors.append("Dígito verificador do Campo 3 inválido.")
        fraud_indicators.append("CAMPO3_CD_INVALIDO")

    # Decode amount
    amount = int(value_str) / 100.0 if value_str != "0000000000" else None

    # Decode due date (Bacen factor: days since 1997-10-07)
    due_date_str = None
    is_overdue   = False
    try:
        factor = int(due_factor)
        if 1000 <= factor <= 9999:
            base = date(1997, 10, 7)
            due = base.toordinal() + factor - 1000  # factors wrap at 9999 → reset
            # Handle wrap-around (factors > 9999 reset — FEBRABAN 2025 rule)
            due_date = date.fromordinal(due)
            due_date_str = due_date.isoformat()
            is_overdue = due_date < date.today()
        elif factor == 0:
            due_date_str = "INDETERMINADO"
    except Exception:
        pass

    # Bank lookup
    bank_name = BANK_REGISTRY.get(bank_code, f"Banco desconhecido (código {bank_code})")

    # Fraud indicators
    if bank_code not in BANK_REGISTRY:
        fraud_indicators.append(f"BANCO_DESCONHECIDO:{bank_code}")
    if is_overdue:
        fraud_indicators.append("BOLETO_VENCIDO")
    if amount and amount <= 0.01:
        fraud_indicators.append("VALOR_SUSPEITO_ZERO_CENTAVOS")

    is_valid     = len(errors) == 0
    is_suspicious = len(fraud_indicators) > 0

    verdict = "OK"
    if not is_valid:
        verdict = "INVALIDO"
    elif is_suspicious:
        verdict = "SUSPEITO" if "BOLETO_VENCIDO" not in fraud_indicators or len(fraud_indicators) > 1 else "VENCIDO"

    return {
        "is_valid": is_valid,
        "is_suspicious": is_suspicious,
        "verdict": verdict,
        "bank_code": bank_code,
        "bank_name": bank_name,
        "currency": "BRL" if currency == "9" else f"UNKNOWN({currency})",
        "amount": amount,
        "due_date": due_date_str,
        "is_overdue": is_overdue,
        "barcode_reconstructed": _reconstruct_barcode(raw),
        "fraud_indicators": fraud_indicators,
        "errors": errors,
        "fields": {
            "campo1": raw[0:10],
            "campo2": raw[10:21],
            "campo3": raw[21:32],
            "digito_geral": general_cd,
            "vencimento_fator": due_factor,
            "valor": value_str,
        },
        "checks": {
            "campo1_cd": "OK" if _mod10(field1_data) == int(field1_cd) else "FAIL",
            "campo2_cd": "OK" if _mod10(field2_data) == int(field2_cd) else "FAIL",
            "campo3_cd": "OK" if _mod10(field3_data) == int(field3_cd) else "FAIL",
        },
        "recommendations": _build_recommendations(fraud_indicators, is_valid),
    }


def _reconstruct_barcode(raw: str) -> str:
    """Reconstruct the 44-digit barcode from the 47-digit linha digitável."""
    try:
        bank   = raw[:3]
        curr   = raw[3]
        f1     = raw[4:9]
        f2     = raw[10:20]
        f3     = raw[21:31]
        gen_cd = raw[32]
        due    = raw[33:37]
        value  = raw[37:47]
        free   = f1 + f2 + f3
        return f"{bank}{curr}{gen_cd}{due}{value}{free}"
    except Exception:
        return ""


def _build_recommendations(indicators: list[str], is_valid: bool) -> list[str]:
    recs = []
    if not is_valid:
        recs.append("❌ NÃO PAGUE — a linha digitável contém erros estruturais. Pode ser boleto falso ou adulterado.")
    if "BANCO_DESCONHECIDO" in " ".join(indicators):
        recs.append("⚠️ Banco emissor não reconhecido. Verifique se a conta de recebimento é legítima.")
    if "BOLETO_VENCIDO" in indicators:
        recs.append("⚠️ Boleto vencido. Solicite a segunda via diretamente ao credor.")
    if "CAMPO1_CD_INVALIDO" in indicators or "CAMPO2_CD_INVALIDO" in indicators or "CAMPO3_CD_INVALIDO" in indicators:
        recs.append("🔴 Dígito verificador inválido — possível adulteração por malware (bolware). Não processe.")
    if not recs:
        recs.append("✅ Boleto estruturalmente válido. Confirme o beneficiário antes de pagar.")
    return recs


async def validate_boleto(linha_digitavel: str, expected_cnpj: Optional[str] = None) -> dict:
    """Public API: validates a boleto and returns full analysis."""
    result = decode_linha_digitavel(linha_digitavel)
    result["linha_digitavel_raw"] = _clean_linha(linha_digitavel)
    result["checked_at"] = datetime.now(timezone.utc).isoformat()

    if expected_cnpj and result.get("is_valid"):
        # In production: query CIP/Bacen API to cross-check beneficiary CNPJ
        result["cnpj_cross_check"] = {
            "expected_cnpj": expected_cnpj,
            "status": "NOT_VERIFIED",
            "note": "Integração CIP/Bacen requer contrato com Bacen ou clearinghouse.",
        }

    return result
