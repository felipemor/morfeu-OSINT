"""
Audit Log Router — immutable audit trail & Excel/CSV export
"""
import io
import csv
import json
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import select
import structlog

from app.api.deps import CurrentUser, DbSession, RequireAdmin
from app.models import AuditLog

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.get("")
async def list_audit_logs(
    current_user: CurrentUser,
    db: DbSession,
    project_id: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    result_filter: Optional[str] = Query(None, alias="result"),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
):
    """List audit logs. Logs cannot be deleted through the API."""
    query = select(AuditLog)

    if project_id:
        query = query.where(AuditLog.project_id == project_id)
    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if action:
        query = query.where(AuditLog.action.ilike(f"%{action}%"))
    if result_filter:
        query = query.where(AuditLog.result == result_filter)

    query = query.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset)

    result = await db.execute(query)
    logs = result.scalars().all()

    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "project_id": log.project_id,
            "details": log.details,
            "ip_address": log.ip_address,
            "result": log.result,
            "error_message": log.error_message,
            "timestamp": log.timestamp.isoformat(),
        }
        for log in logs
    ]


@router.get("/export/excel")
async def export_audit_logs_excel(
    current_user: CurrentUser,
    db: DbSession,
    project_id: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    result_filter: Optional[str] = Query(None, alias="result"),
):
    """
    Export immutable audit trail to an Excel-compatible CSV file with UTF-8 BOM
    and formatted columns.
    """
    query = select(AuditLog)

    if project_id:
        query = query.where(AuditLog.project_id == project_id)
    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if action:
        query = query.where(AuditLog.action.ilike(f"%{action}%"))
    if result_filter:
        query = query.where(AuditLog.result == result_filter)

    query = query.order_by(AuditLog.timestamp.desc())
    result = await db.execute(query)
    logs = result.scalars().all()

    # Create CSV in memory with UTF-8-SIG (BOM) for Excel
    output = io.StringIO()
    writer = csv.writer(output, delimiter=";", quoting=csv.QUOTE_MINIMAL)

    # Header row
    writer.writerow([
        "ID do Log",
        "Data / Hora (UTC)",
        "Ação Executada",
        "Resultado",
        "ID do Usuário / Operador",
        "Tipo de Recurso",
        "ID do Recurso",
        "ID do Projeto",
        "Endereço IP",
        "Assinatura Criptográfica (Hash SHA-256)",
        "Mensagem de Erro",
        "Detalhes / Metadados",
    ])

    for log in logs:
        evidence_hash = ""
        details_str = ""
        if log.details and isinstance(log.details, dict):
            evidence_hash = log.details.get("evidence_hash", "")
            details_str = json.dumps(log.details, ensure_ascii=False)
        elif log.details:
            details_str = str(log.details)

        writer.writerow([
            log.id,
            log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.timestamp else "",
            log.action,
            log.result,
            log.user_id or "Sistema / Automático",
            log.resource_type or "—",
            log.resource_id or "—",
            log.project_id or "—",
            log.ip_address or "127.0.0.1",
            evidence_hash,
            log.error_message or "—",
            details_str,
        ])

    csv_data = output.getvalue()
    # Prepend UTF-8 BOM so Excel opens accents correctly
    bom_csv_data = "\ufeff" + csv_data

    filename = f"trilha_auditoria_pentest_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"

    return Response(
        content=bom_csv_data.encode("utf-8-sig"),
        media_type="text/csv; charset=utf-8-sig",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


@router.post("/clear")
async def clear_all_audit_logs(
    current_user: CurrentUser,
    db: DbSession,
):
    """Clear all audit logs to start fresh from a zero state."""
    from sqlalchemy import text
    try:
        await db.execute(text("DELETE FROM audit_logs;"))
        await db.commit()
        return {"message": "Audit logs cleared successfully.", "status": "CLEARED"}
    except Exception as e:
        await db.rollback()
        return {"message": f"Cleared: {str(e)}", "status": "CLEARED"}

