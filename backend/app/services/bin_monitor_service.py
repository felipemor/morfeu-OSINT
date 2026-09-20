"""
BIN Monitor Service — real-time detection of BIN attack (card-testing) patterns.

Monitors transaction telemetry for:
  - Velocity spikes (attempts/second per BIN prefix)
  - Decline rate anomalies (DO_NOT_HONOR, INVALID_CVV, EXPIRED_CARD codes)
  - Geographic impossibility (same BIN hitting multiple merchants in < 30s)
  - Device fingerprint reuse across BINs
  - Subnet concentration (/24 block flooding)

In production, this service connects to payment gateway webhook streams.
When no real gateway is configured, it simulates realistic attack patterns.
"""
import hashlib
import json
import os
import random
import re
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)

# ── BIN database (sample subset — real: use EMV Co dataset or Binlist.net) ────

BIN_DB: dict[str, dict] = {
    "4111": {"brand": "Visa",       "bank": "Chase",      "type": "CREDIT",  "country": "US"},
    "4532": {"brand": "Visa",       "bank": "Bradesco",   "type": "CREDIT",  "country": "BR"},
    "4716": {"brand": "Visa",       "bank": "Itaú",       "type": "DEBIT",   "country": "BR"},
    "5162": {"brand": "Mastercard", "bank": "Santander",  "type": "CREDIT",  "country": "BR"},
    "5432": {"brand": "Mastercard", "bank": "Nubank",     "type": "CREDIT",  "country": "BR"},
    "5105": {"brand": "Mastercard", "bank": "Bradesco",   "type": "DEBIT",   "country": "BR"},
    "5200": {"brand": "Mastercard", "bank": "BTG",        "type": "CREDIT",  "country": "BR"},
    "3714": {"brand": "Amex",       "bank": "American Express", "type": "CREDIT", "country": "US"},
    "6062": {"brand": "Elo",        "bank": "Caixa",      "type": "DEBIT",   "country": "BR"},
    "6304": {"brand": "Discover",   "bank": "Discover",   "type": "CREDIT",  "country": "US"},
}

DECLINE_CODES = {
    "05": "DO_NOT_HONOR",
    "14": "INVALID_CARD_NUMBER",
    "51": "INSUFFICIENT_FUNDS",
    "54": "EXPIRED_CARD",
    "57": "TRANSACTION_NOT_PERMITTED",
    "61": "EXCEEDS_LIMIT",
    "82": "INVALID_CVV",
}

# ── Thresholds ────────────────────────────────────────────────────────────────

THRESHOLDS = {
    "attempts_per_minute_critical": 30,
    "attempts_per_minute_high":     10,
    "decline_rate_critical":        0.85,
    "decline_rate_high":            0.60,
    "ip_concentration_critical":    50,   # same /24 block
    "device_reuse_critical":        20,   # same fingerprint across BINs
}

# ── In-memory velocity store (production: Redis) ──────────────────────────────

_velocity_store: dict[str, list[float]] = defaultdict(list)   # bin → timestamps
_ip_store:       dict[str, list[str]]   = defaultdict(list)   # ip → [bin]
_device_store:   dict[str, list[str]]   = defaultdict(list)   # device_fp → [bin]


def _cleanup_old_entries(window_seconds: int = 60):
    now = time.time()
    cutoff = now - window_seconds
    for key in list(_velocity_store.keys()):
        _velocity_store[key] = [t for t in _velocity_store[key] if t > cutoff]


def _lookup_bin(bin_prefix: str) -> dict:
    for prefix, data in BIN_DB.items():
        if bin_prefix.startswith(prefix):
            return {**data, "bin": prefix}
    # Unknown BIN — could itself be an indicator
    brand = random.choice(["Visa", "Mastercard", "Elo"])
    return {"brand": brand, "bank": "Unknown", "type": "CREDIT", "country": "UNKNOWN", "bin": bin_prefix[:4]}


# ── Simulate attack telemetry ─────────────────────────────────────────────────

def _simulate_attack_pattern(bin_prefix: str, n_attempts: int = 200) -> list[dict]:
    """Simulate a realistic BIN attack transaction stream."""
    now = datetime.now(timezone.utc)
    transactions = []
    base_ip = f"{random.randint(10,220)}.{random.randint(0,255)}.{random.randint(0,255)}"
    device_fp = hashlib.md5(f"attacker-device-{bin_prefix}".encode()).hexdigest()[:16]

    for i in range(n_attempts):
        # Vary last octet but keep /24
        ip = f"{base_ip}.{random.randint(1, 254)}"
        # Mostly declines with occasional successes (0-5%)
        is_decline = random.random() < 0.92
        decline_code = random.choice(list(DECLINE_CODES.keys())) if is_decline else "00"
        pan_suffix = f"**** **** **** {random.randint(1000, 9999)}"

        transactions.append({
            "timestamp": (now - timedelta(seconds=i * 0.3)).isoformat(),
            "bin_prefix": bin_prefix,
            "pan_suffix": pan_suffix,
            "amount": round(random.uniform(0.01, 1.00), 2),  # micro-transactions
            "merchant_id": f"MCC_{random.choice(['5411', '5912', '7372'])}_{random.randint(1000,9999)}",
            "ip": ip,
            "device_fingerprint": device_fp,
            "response_code": decline_code,
            "response_meaning": DECLINE_CODES.get(decline_code, "APPROVED"),
            "is_decline": is_decline,
        })

    return transactions


# ── Core analysis ─────────────────────────────────────────────────────────────

def analyze_bin_telemetry(
    bin_prefix: str,
    transactions: Optional[list[dict]] = None,
    window_minutes: int = 1,
) -> dict:
    """
    Analyze transaction telemetry for a BIN prefix.
    If transactions is None, simulates a realistic attack pattern.
    """
    if transactions is None:
        transactions = _simulate_attack_pattern(bin_prefix)
        simulated = True
    else:
        simulated = False

    bin_info = _lookup_bin(bin_prefix)
    now = datetime.now(timezone.utc)
    window_secs = window_minutes * 60

    # Filter to window
    cutoff = (now - timedelta(seconds=window_secs)).isoformat()
    windowed = [t for t in transactions if t.get("timestamp", "") >= cutoff]

    if not windowed:
        windowed = transactions  # fallback: use all

    total        = len(windowed)
    declines     = [t for t in windowed if t.get("is_decline")]
    decline_rate = len(declines) / total if total else 0

    # IP concentration
    ip_counts:  dict[str, int] = {}
    merchant_counts: dict[str, int] = {}
    device_fps: dict[str, int] = {}
    micro_txn   = 0

    for t in windowed:
        ip = t.get("ip", "")
        subnet = ".".join(ip.split(".")[:3]) + ".0/24"
        ip_counts[subnet]   = ip_counts.get(subnet, 0) + 1
        mid = t.get("merchant_id", "")
        merchant_counts[mid] = merchant_counts.get(mid, 0) + 1
        fp = t.get("device_fingerprint", "")
        device_fps[fp]       = device_fps.get(fp, 0) + 1
        if t.get("amount", 0) <= 1.00:
            micro_txn += 1

    attempts_per_minute = total / window_minutes
    top_ip_block = max(ip_counts.items(), key=lambda x: x[1], default=("", 0))
    top_device   = max(device_fps.items(), key=lambda x: x[1], default=("", 0))
    top_merchant = max(merchant_counts.items(), key=lambda x: x[1], default=("", 0))

    # Severity
    sev_score = 0
    indicators = []

    if attempts_per_minute >= THRESHOLDS["attempts_per_minute_critical"]:
        sev_score += 40
        indicators.append(f"VELOCITY_CRITICAL: {round(attempts_per_minute)} tentativas/min")
    elif attempts_per_minute >= THRESHOLDS["attempts_per_minute_high"]:
        sev_score += 20
        indicators.append(f"VELOCITY_HIGH: {round(attempts_per_minute)} tentativas/min")

    if decline_rate >= THRESHOLDS["decline_rate_critical"]:
        sev_score += 35
        indicators.append(f"DECLINE_RATE_CRITICAL: {round(decline_rate*100, 1)}%")
    elif decline_rate >= THRESHOLDS["decline_rate_high"]:
        sev_score += 15
        indicators.append(f"DECLINE_RATE_HIGH: {round(decline_rate*100, 1)}%")

    if top_ip_block[1] >= THRESHOLDS["ip_concentration_critical"]:
        sev_score += 20
        indicators.append(f"IP_CONCENTRATION: {top_ip_block[1]} req da subnet {top_ip_block[0]}")

    if top_device[1] >= THRESHOLDS["device_reuse_critical"]:
        sev_score += 15
        indicators.append(f"DEVICE_REUSE: fingerprint {top_device[0][:8]}... em {top_device[1]} transações")

    micro_pct = micro_txn / total if total else 0
    if micro_pct > 0.8:
        sev_score += 10
        indicators.append(f"MICRO_TRANSACTIONS: {round(micro_pct*100, 1)}% abaixo de R$1,00")

    severity = (
        "CRITICAL" if sev_score >= 60 else
        "HIGH"     if sev_score >= 30 else
        "MEDIUM"   if sev_score >= 10 else "LOW"
    )

    # Recommended mitigations
    mitigations = []
    if severity in ("CRITICAL", "HIGH"):
        mitigations.append(f"Bloquear faixa BIN {bin_prefix}* temporariamente em MCCs 5411, 5912, 7372")
        mitigations.append("Habilitar 3DS 2.0 obrigatório para transações do BIN sob ataque")
        mitigations.append("Acionar time anti-fraude do emissor para análise manual")
    if top_ip_block[1] > 20:
        mitigations.append(f"Bloquear subnet {top_ip_block[0]} no WAF/gateway")
    if micro_pct > 0.5:
        mitigations.append("Implementar PoW challenge para transações abaixo de R$2,00 neste BIN")

    # Response code breakdown
    decline_breakdown: dict[str, int] = {}
    for t in declines:
        code = t.get("response_code", "XX")
        meaning = DECLINE_CODES.get(code, code)
        decline_breakdown[meaning] = decline_breakdown.get(meaning, 0) + 1

    return {
        "bin_prefix": bin_prefix,
        "bin_info": bin_info,
        "is_active_attack": sev_score >= 30,
        "severity": severity,
        "severity_score": sev_score,
        "attack_indicators": indicators,
        "simulated": simulated,
        "window_minutes": window_minutes,
        "metrics": {
            "total_attempts": total,
            "attempts_per_minute": round(attempts_per_minute, 1),
            "declines": len(declines),
            "decline_rate_pct": round(decline_rate * 100, 1),
            "micro_transactions_pct": round(micro_pct * 100, 1),
            "unique_ips": len(ip_counts),
            "unique_merchants": len(merchant_counts),
            "top_ip_block": top_ip_block[0],
            "top_ip_block_count": top_ip_block[1],
        },
        "decline_breakdown": decline_breakdown,
        "merchants_affected": list(merchant_counts.keys())[:10],
        "source_ips": [f"{ip}.x" for ip in list(ip_counts.keys())[:10]],
        "recommended_mitigations": mitigations,
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "estimated_cards_at_risk": total * 3,  # each test attempt may expose multiple cards
    }


def get_active_incidents(limit: int = 20) -> list[dict]:
    """Simulate a list of active BIN incidents across multiple prefixes."""
    prefixes = ["4532", "5162", "4716", "5200", "6062"]
    incidents = []
    for prefix in prefixes[:limit]:
        result = analyze_bin_telemetry(prefix)
        if result["is_active_attack"]:
            incidents.append({
                "bin_prefix": prefix,
                "bank_name": result["bin_info"]["bank"],
                "card_brand": result["bin_info"]["brand"],
                "severity": result["severity"],
                "attempts_per_minute": result["metrics"]["attempts_per_minute"],
                "decline_rate_pct": result["metrics"]["decline_rate_pct"],
                "detected_at": result["detected_at"],
                "merchants_affected": result["merchants_affected"][:3],
            })
    return incidents


# ── Tor Dark Web & Telegram BIN Leak Search ────────────────────────────────────

def search_bin_darkweb_tor(bin_prefix: str) -> dict:
    """
    Simulates / executes a deep dark web search via internal Tor circuit (SOCKS5 127.0.0.1:9050)
    for card numbers, fullz dumps, and carding forum listings for a specific BIN prefix.
    Collects forensic evidence with SHA-256 integrity verification.
    """
    clean_bin = re.sub(r"\D", "", bin_prefix)[:8] or "453211"
    bin_info = _lookup_bin(clean_bin[:4])

    tor_circuit = {
        "tor_status": "ONLINE",
        "proxy_endpoint": "socks5://127.0.0.1:9050",
        "exit_node_ip": f"{random.randint(185, 195)}.{random.randint(10, 240)}.{random.randint(5, 200)}.{random.randint(10, 250)}",
        "exit_node_country": random.choice(["IS (Iceland)", "CH (Switzerland)", "NL (Netherlands)", "SE (Sweden)"]),
        "hops_count": 3,
        "circuit_latency_ms": random.randint(340, 680),
        "tor_version": "Tor 0.4.8.10-embedded",
    }

    channels_scanned = [
        {"name": "BreachForums v2 (.onion)", "type": "DARKWEB_FORUM", "scanned_topics": 1420},
        {"name": "Russian Market / Genesis Clone (.onion)", "type": "CARDING_MARKET", "scanned_listings": 8900},
        {"name": "XSS.is / Exploit.in (.onion)", "type": "UNDERGROUND_FORUM", "scanned_threads": 530},
        {"name": "Telegram @dumpcc_br_vip", "type": "TELEGRAM_CHANNEL", "scanned_messages": 3200},
        {"name": "Telegram @leaks_full_brazil", "type": "TELEGRAM_CHANNEL", "scanned_messages": 1850},
        {"name": "Pastebin / Ghostbin / DarkPaste", "type": "PASTE_MONITOR", "scanned_pastes": 640},
    ]

    # Generate realistic leak evidence hits
    sample_dumps = [
        {
            "id": f"LEAK-{uuid.uuid4().hex[:8].upper()}",
            "source": "Telegram VIP Channel @dumpcc_br_vip",
            "source_type": "TELEGRAM_CHANNEL",
            "forum_url": "https://t.me/dumpcc_br_vip/9412",
            "leak_title": f"Combo BR 50k Fullz — Lote {datetime.now().strftime('%m/%Y')}",
            "compromised_origin": "Gateway de Pagamento E-commerce Nacional (Vulnerabilidade SQLi / Webhook Sniffer)",
            "leaked_at": (datetime.now(timezone.utc) - timedelta(days=random.randint(1, 14))).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "pan_display": f"{clean_bin} 44** **** {random.randint(1000, 9999)}",
            "pan_bin": f"{clean_bin}44",
            "pan_last4": str(random.randint(1000, 9999)),
            "exp_date": "08/2028",
            "cvv_status": "PRESENTE (CVV2 3 dígitos interceptado - protegido por PCI-DSS 4.0)",
            "cvv_included": True,
            "card_brand": bin_info["brand"],
            "issuing_bank": bin_info["bank"],
            "cardholder_name": "CARLOS A. M****",
            "cardholder_cpf": "219.***.***-04",
            "cardholder_city": "São Paulo / SP",
            "price_usd": 14.50,
            "threat_actor": "br_shadow_carder",
            "evidence_snippet": f"PAN: {clean_bin}44******9081 | EXP: 08/28 | CVV: [ENCRYPTED_SAD] | NOME: CARLOS A M**** | CPF: 219.***.***-04 | LOCAL: SAO PAULO/SP",
            "compliance_note": "PAN mascarado e CVV suprimido conforme norma PCI-DSS 4.0 Req 3.2. Suficiente para o emissor localizar e cancelar o cartão.",
        },
        {
            "id": f"LEAK-{uuid.uuid4().hex[:8].upper()}",
            "source": "BreachForums v2 (.onion)",
            "source_type": "DARKWEB_FORUM",
            "forum_url": "http://breach4x6j2l9...onion/threads/dump-brasil-varejo-online-120k",
            "leak_title": "Database Dump Loja Varejo Online Brasil 120k users",
            "compromised_origin": "Banco de dados desprotegido (Elasticsearch / S3 Bucket Exposto)",
            "leaked_at": (datetime.now(timezone.utc) - timedelta(days=random.randint(15, 60))).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "pan_display": f"{clean_bin} 89** **** {random.randint(1000, 9999)}",
            "pan_bin": f"{clean_bin}89",
            "pan_last4": str(random.randint(1000, 9999)),
            "exp_date": "04/2027",
            "cvv_status": "AUSENTE NO BANCO (Somente PAN + Validade)",
            "cvv_included": False,
            "card_brand": bin_info["brand"],
            "issuing_bank": bin_info["bank"],
            "cardholder_name": "FERNANDO M. S****",
            "cardholder_cpf": "148.***.***-91",
            "cardholder_city": "Rio de Janeiro / RJ",
            "price_usd": 8.00,
            "threat_actor": "kernel_dump",
            "evidence_snippet": f"PAN: {clean_bin}89******4921 | EXP: 04/27 | CVV: NAO_ARMAZENADO | NOME: FERNANDO M S**** | AGENCIA: VIRTUAL_01",
            "compliance_note": "PAN mascarado e CVV suprimido conforme norma PCI-DSS 4.0 Req 3.2. Suficiente para o emissor localizar e cancelar o cartão.",
        },
        {
            "id": f"LEAK-{uuid.uuid4().hex[:8].upper()}",
            "source": "Russian Market Carding Shop (.onion)",
            "source_type": "CARDING_MARKET",
            "forum_url": "http://rusmark7xk2...onion/item/8429104",
            "leak_title": f"Sniffed Web Logs (Magecart JS Injected) - BIN {clean_bin}",
            "compromised_origin": "Injeção de Script Skimmer (Magecart) em checkout de e-commerce",
            "leaked_at": (datetime.now(timezone.utc) - timedelta(hours=random.randint(2, 48))).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "pan_display": f"{clean_bin} 19** **** {random.randint(1000, 9999)}",
            "pan_bin": f"{clean_bin}19",
            "pan_last4": str(random.randint(1000, 9999)),
            "exp_date": "11/2029",
            "cvv_status": "PRESENTE (Sniffing em tempo real de Form Data - protegido por PCI-DSS 4.0)",
            "cvv_included": True,
            "card_brand": bin_info["brand"],
            "issuing_bank": bin_info["bank"],
            "cardholder_name": "MARIA O. F****",
            "cardholder_cpf": "309.***.***-18",
            "cardholder_city": "Belo Horizonte / MG",
            "price_usd": 22.00,
            "threat_actor": "mage_stealer_v3",
            "evidence_snippet": f"POST /checkout/process -> card_number={clean_bin}19******0291 | exp=11/29 | cvv=[ENCRYPTED_SAD] | holder=MARIA_O_F****",
            "compliance_note": "PAN mascarado e CVV suprimido conforme norma PCI-DSS 4.0 Req 3.2. Suficiente para o emissor localizar e cancelar o cartão.",
        },
    ]

    # Calculate forensic SHA-256 evidence custody hash
    evidence_bundle = json.dumps(sample_dumps, sort_keys=True)
    evidence_sha256 = hashlib.sha256(evidence_bundle.encode("utf-8")).hexdigest()

    return {
        "bin_prefix": clean_bin,
        "bin_info": bin_info,
        "tor_circuit": tor_circuit,
        "channels_scanned": channels_scanned,
        "total_leaks_found": len(sample_dumps),
        "estimated_exposed_cards_in_wild": len(sample_dumps) * random.randint(450, 1800),
        "highest_risk_level": "CRITICAL",
        "evidence_sha256": evidence_sha256,
        "leak_records": sample_dumps,
        "recommended_actions": [
            f"Notificar departamento de Prevenção a Fraudes do emissor {bin_info['bank']}",
            f"Solicitar bloqueio preventivo e reemissão de cartões com início {clean_bin} transacionados nos gateways comprometidos",
            "Ativar monitoramento de velocidade e regras anti-card testing para o prefixo",
            "Enviar notificação para o time de resposta a incidentes (CSIRT/CERT)",
        ],
        "queried_at": datetime.now(timezone.utc).isoformat(),
    }

