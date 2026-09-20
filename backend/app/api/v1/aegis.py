"""AegisLattice Control Plane — PQC crypto scanner and CBOM management."""
import json
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, desc
from typing import Optional

from app.api.deps import CurrentUser, DbSession
from app.models import AegisScanResult, CryptoRiskLevel
from app.services import aegis_service as svc

router = APIRouter()


class ScanRequest(BaseModel):
    targets: list[str]
    port: int = 443


class SingleScanRequest(BaseModel):
    host: str
    port: int = 443


class PolicyRequest(BaseModel):
    host: str
    action: str  # "quarantine" | "force_tls13" | "enable_pqc_proxy"
    reason: Optional[str] = None


@router.post("/scan", status_code=status.HTTP_200_OK)
async def scan_portfolio(body: ScanRequest, current_user: CurrentUser, db: DbSession):
    """
    Scan a list of hosts for TLS/crypto posture and generate a portfolio CBOM.
    Classifies each host into: QUANTUM_RESISTANT | HARVEST_NOW_DECRYPT | CRITICAL_VULNERABLE.
    """
    if not body.targets:
        raise HTTPException(status_code=400, detail="At least one target is required.")

    result = await svc.scan_subnet(body.targets, body.port)

    # Persist individual scan results
    for r in result.get("results", []):
        risk = {
            "QUANTUM_RESISTANT":   CryptoRiskLevel.QUANTUM_RESISTANT,
            "HARVEST_NOW_DECRYPT": CryptoRiskLevel.HARVEST_NOW_DECRYPT,
            "CRITICAL_VULNERABLE": CryptoRiskLevel.CRITICAL_VULNERABLE,
        }.get(r.get("risk_level", ""), CryptoRiskLevel.UNKNOWN)

        cert_dt = None
        if r.get("cert_not_after"):
            try:
                cert_dt = datetime.fromisoformat(r["cert_not_after"])
            except Exception:
                pass

        row = AegisScanResult(
            host=r["host"],
            port=r["port"],
            tls_version=r.get("tls_version"),
            cipher_suite=r.get("cipher_suite"),
            key_exchange=r.get("key_exchange"),
            cert_algo=r.get("cert_algo"),
            cert_key_bits=r.get("cert_key_bits"),
            cert_not_after=cert_dt,
            risk_level=risk,
            risk_score=r.get("risk_score", 0.0),
            cbom=r.get("cbom", {}),
            pqc_supported=r.get("pqc_supported", False),
            remediation=r.get("remediation"),
            initiated_by=current_user.id,
        )
        db.add(row)

    await db.commit()
    return result


@router.post("/scan/single", status_code=status.HTTP_200_OK)
async def scan_single(body: SingleScanRequest, current_user: CurrentUser, db: DbSession):
    """Scan a single host for TLS/crypto posture."""
    if not body.host:
        raise HTTPException(status_code=400, detail="host is required.")
    result = await svc.scan_host(body.host, body.port)

    risk = {
        "QUANTUM_RESISTANT":   CryptoRiskLevel.QUANTUM_RESISTANT,
        "HARVEST_NOW_DECRYPT": CryptoRiskLevel.HARVEST_NOW_DECRYPT,
        "CRITICAL_VULNERABLE": CryptoRiskLevel.CRITICAL_VULNERABLE,
    }.get(result.get("risk_level", ""), CryptoRiskLevel.UNKNOWN)

    cert_dt = None
    if result.get("cert_not_after"):
        try:
            cert_dt = datetime.fromisoformat(result["cert_not_after"])
        except Exception:
            pass

    row = AegisScanResult(
        host=result["host"],
        port=result["port"],
        tls_version=result.get("tls_version"),
        cipher_suite=result.get("cipher_suite"),
        key_exchange=result.get("key_exchange"),
        cert_algo=result.get("cert_algo"),
        cert_key_bits=result.get("cert_key_bits"),
        cert_not_after=cert_dt,
        risk_level=risk,
        risk_score=result.get("risk_score", 0.0),
        cbom=result.get("cbom", {}),
        pqc_supported=result.get("pqc_supported", False),
        remediation=result.get("remediation"),
        initiated_by=current_user.id,
    )
    db.add(row)
    await db.commit()
    return result


@router.get("/cbom", status_code=status.HTTP_200_OK)
async def export_cbom(current_user: CurrentUser, db: DbSession, format: str = "json"):
    """
    Export the consolidated portfolio CBOM in CycloneDX 1.6 format.
    Aggregates all scanned hosts.
    """
    res = await db.execute(select(AegisScanResult).order_by(desc(AegisScanResult.scanned_at)).limit(200))
    rows = res.scalars().all()

    components = []
    for r in rows:
        components.extend(r.cbom.get("components", []))

    total = len(rows)
    risk_counts = {"QUANTUM_RESISTANT": 0, "HARVEST_NOW_DECRYPT": 0,
                   "CRITICAL_VULNERABLE": 0, "UNKNOWN": 0}
    for r in rows:
        k = r.risk_level.value if r.risk_level else "UNKNOWN"
        risk_counts[k] = risk_counts.get(k, 0) + 1

    import uuid
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "MorfeuSecurity", "name": "AegisLattice", "version": "1.0.0"}],
        },
        "components": components,
        "aegisExtension": {
            "portfolio_summary": {
                "total_hosts_scanned": total,
                "risk_distribution": risk_counts,
                "pct_quantum_resistant":   round(risk_counts["QUANTUM_RESISTANT"] / total * 100, 1) if total else 0,
                "pct_harvest_now_decrypt": round(risk_counts["HARVEST_NOW_DECRYPT"] / total * 100, 1) if total else 0,
                "pct_critical_vulnerable": round(risk_counts["CRITICAL_VULNERABLE"] / total * 100, 1) if total else 0,
                "cnsa20_compliant":        round(risk_counts["QUANTUM_RESISTANT"] / total * 100, 1) if total else 0,
                "generated_at":            datetime.now(timezone.utc).isoformat(),
            }
        },
    }
    return cbom


@router.get("/metrics/executive", status_code=status.HTTP_200_OK)
async def executive_metrics(current_user: CurrentUser, db: DbSession):
    """Executive dashboard metrics for AegisLattice posture."""
    res = await db.execute(select(AegisScanResult).order_by(desc(AegisScanResult.scanned_at)).limit(500))
    rows = res.scalars().all()
    total = len(rows)

    if total == 0:
        return {"message": "Nenhum scan realizado ainda. Execute POST /scan primeiro."}

    risk_counts = {}
    for r in rows:
        k = r.risk_level.value if r.risk_level else "UNKNOWN"
        risk_counts[k] = risk_counts.get(k, 0) + 1

    pqc_pct  = risk_counts.get("QUANTUM_RESISTANT", 0) / total * 100
    hndl_pct = risk_counts.get("HARVEST_NOW_DECRYPT", 0) / total * 100
    crit_pct = risk_counts.get("CRITICAL_VULNERABLE", 0) / total * 100

    return {
        "total_hosts_in_portfolio": total,
        "risk_distribution": risk_counts,
        "pct_quantum_resistant":    round(pqc_pct, 1),
        "pct_harvest_now_decrypt":  round(hndl_pct, 1),
        "pct_critical_vulnerable":  round(crit_pct, 1),
        "cnsa20_compliance_score":  round(pqc_pct, 1),
        "nist_pqc_readiness_grade": "A" if pqc_pct >= 80 else "B" if pqc_pct >= 50 else "C" if pqc_pct >= 20 else "F",
        "priority_action": (
            "CRÍTICO: Desabilitar TLS 1.0/1.1 nos hosts marcados CRITICAL_VULNERABLE" if crit_pct > 5
            else "IMPORTANTE: Iniciar migração para KEM híbrido X25519+ML-KEM-768 (FIPS 203)"
        ),
        "estimated_quantum_threat_year": 2030,
    }


@router.post("/remediate/policy", status_code=status.HTTP_200_OK)
async def apply_remediation_policy(body: PolicyRequest, current_user: CurrentUser):
    """
    Apply a remediation policy to a host.
    In production: triggers aegis-proxy config update or Kubernetes admission controller.
    """
    valid_actions = ["quarantine", "force_tls13", "enable_pqc_proxy", "revoke_cert"]
    if body.action not in valid_actions:
        raise HTTPException(status_code=400, detail=f"action must be one of {valid_actions}")

    action_descriptions = {
        "quarantine":       "Host isolado — tráfego bloqueado até remediação.",
        "force_tls13":      "Política TLS 1.3 mínimo aplicada. Ciphers legados desabilitados.",
        "enable_pqc_proxy": "Proxy híbrido PQC (aegis-proxy) provisionado na frente do host.",
        "revoke_cert":      "Certificado marcado para revogação e re-emissão com chave >= RSA-4096.",
    }

    return {
        "host": body.host,
        "action": body.action,
        "description": action_descriptions[body.action],
        "applied_at": datetime.now(timezone.utc).isoformat(),
        "applied_by": current_user.email if hasattr(current_user, "email") else current_user.id,
        "reason": body.reason,
        "status": "APPLIED",
        "note": "Em produção: atualiza aegis-proxy config e reinicia listener PQC.",
    }


@router.get("/results", status_code=status.HTTP_200_OK)
async def list_scan_results(current_user: CurrentUser, db: DbSession, limit: int = 50):
    """List recent TLS scan results."""
    res = await db.execute(select(AegisScanResult).order_by(desc(AegisScanResult.scanned_at)).limit(limit))
    rows = res.scalars().all()
    return [
        {
            "id": r.id, "host": r.host, "port": r.port,
            "tls_version": r.tls_version, "cipher_suite": r.cipher_suite,
            "risk_level": r.risk_level.value if r.risk_level else "UNKNOWN",
            "risk_score": r.risk_score, "pqc_supported": r.pqc_supported,
            "cert_key_bits": r.cert_key_bits, "cert_algo": r.cert_algo,
            "remediation": r.remediation,
            "scanned_at": r.scanned_at.isoformat(),
        }
        for r in rows
    ]
