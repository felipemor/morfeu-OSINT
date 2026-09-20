"""Boleto Router — boleto bancário validation and fraud detection."""
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, desc
from typing import Optional

from app.api.deps import CurrentUser, DbSession
from app.models import BoletoCheck
from app.services import boleto_service as svc

router = APIRouter()


class ValidateRequest(BaseModel):
    linha_digitavel: str
    expected_cnpj: Optional[str] = None


@router.post("/validate", status_code=status.HTTP_200_OK)
async def validate_boleto(body: ValidateRequest, current_user: CurrentUser, db: DbSession):
    """
    Validates a Brazilian boleto bancário (typed line) using Módulo 10/11 algorithms.
    Detects structural fraud, wrong bank codes, corrupted check digits (bolware signatures).
    """
    if not body.linha_digitavel or len(body.linha_digitavel.strip()) < 40:
        raise HTTPException(status_code=400, detail="linha_digitavel deve ter pelo menos 47 dígitos.")

    result = await svc.validate_boleto(body.linha_digitavel, body.expected_cnpj)

    # Persist check
    check = BoletoCheck(
        linha_digitavel=body.linha_digitavel,
        bank_code=result.get("bank_code"),
        bank_name=result.get("bank_name"),
        amount=result.get("amount"),
        due_date=result.get("due_date"),
        is_valid=result.get("is_valid", False),
        is_suspicious=result.get("is_suspicious", False),
        fraud_indicators=result.get("fraud_indicators", []),
        verdict=result.get("verdict", "UNKNOWN"),
        checked_by=current_user.id,
    )
    db.add(check)
    await db.commit()
    await db.refresh(check)

    result["check_id"] = check.id
    return result


@router.get("/checks", status_code=status.HTTP_200_OK)
async def list_checks(current_user: CurrentUser, db: DbSession, limit: int = 50, suspicious_only: bool = False):
    """List boleto validation history."""
    q = select(BoletoCheck).order_by(desc(BoletoCheck.checked_at)).limit(limit)
    if suspicious_only:
        q = q.where(BoletoCheck.is_suspicious == True)  # noqa: E712
    res = await db.execute(q)
    checks = res.scalars().all()
    return [
        {
            "id": c.id, "bank_code": c.bank_code, "bank_name": c.bank_name,
            "amount": c.amount, "due_date": c.due_date,
            "is_valid": c.is_valid, "is_suspicious": c.is_suspicious,
            "verdict": c.verdict, "fraud_indicators": c.fraud_indicators,
            "checked_at": c.checked_at.isoformat(),
        }
        for c in checks
    ]


@router.get("/checks/{check_id}", status_code=status.HTTP_200_OK)
async def get_check(check_id: str, current_user: CurrentUser, db: DbSession):
    """Get boleto validation check details."""
    res = await db.execute(select(BoletoCheck).where(BoletoCheck.id == check_id))
    check = res.scalar_one_or_none()
    if not check:
        raise HTTPException(status_code=404, detail="Check not found.")
    return {
        "id": check.id,
        "linha_digitavel": check.linha_digitavel[:10] + "..." + check.linha_digitavel[-10:],
        "bank_code": check.bank_code, "bank_name": check.bank_name,
        "amount": check.amount, "due_date": check.due_date,
        "is_valid": check.is_valid, "is_suspicious": check.is_suspicious,
        "verdict": check.verdict, "fraud_indicators": check.fraud_indicators,
        "checked_at": check.checked_at.isoformat(),
    }


@router.get("/banks", status_code=status.HTTP_200_OK)
async def list_banks(current_user: CurrentUser):
    """Return the BIN/bank code registry used for validation."""
    return {"banks": svc.BANK_REGISTRY}
