"""
Reports Router — Generate and download pentest reports
"""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select
import os
import structlog

from app.api.deps import CurrentUser, DbSession
from app.models import Report, Project, ReportType, ReportFormat
from app.services.audit import log_action

logger = structlog.get_logger(__name__)
router = APIRouter()


class ReportCreate(BaseModel):
    report_type: ReportType = ReportType.TECHNICAL
    format: ReportFormat = ReportFormat.PDF
    title: Optional[str] = None


@router.post("/{project_id}/report", status_code=201)
async def generate_report(
    project_id: str,
    body: ReportCreate,
    current_user: CurrentUser,
    db: DbSession,
    request,
):
    """Generate a pentest report. Runs asynchronously via Celery."""
    proj_result = await db.execute(select(Project).where(Project.id == project_id))
    project = proj_result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    title = body.title or f"{project.name} — {body.report_type.value} Report"

    report = Report(
        project_id=project_id,
        report_type=body.report_type,
        format=body.format,
        title=title,
        generated_by=current_user.id,
        status="GENERATING",
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    # Launch async report generation
    from app.agents.report_agent import generate_report_task
    task = generate_report_task.apply_async(
        args=[report.id, project_id],
        queue="report",
    )

    await log_action(
        db=db, user_id=current_user.id, action="REPORT_GENERATION_STARTED",
        resource_type="report", resource_id=report.id,
        project_id=project_id,
        details={"type": body.report_type.value, "format": body.format.value},
    )

    return {
        "report_id": report.id,
        "status": "GENERATING",
        "task_id": task.id,
        "message": "Report is being generated. Poll /reports/{id} for status.",
    }


@router.get("/{project_id}/reports")
async def list_reports(project_id: str, current_user: CurrentUser, db: DbSession):
    result = await db.execute(
        select(Report).where(Report.project_id == project_id).order_by(Report.created_at.desc())
    )
    reports = result.scalars().all()
    return [
        {
            "id": r.id,
            "title": r.title,
            "type": r.report_type.value,
            "format": r.format.value,
            "status": r.status,
            "finding_count": r.finding_count,
            "file_size": r.file_size,
            "created_at": r.created_at.isoformat(),
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        }
        for r in reports
    ]


@router.get("/reports/{report_id}")
async def get_report(report_id: str, current_user: CurrentUser, db: DbSession):
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "id": report.id,
        "title": report.title,
        "type": report.report_type.value,
        "format": report.format.value,
        "status": report.status,
        "finding_count": report.finding_count,
        "file_size": report.file_size,
        "error": report.error,
        "created_at": report.created_at.isoformat(),
        "completed_at": report.completed_at.isoformat() if report.completed_at else None,
    }


@router.get("/reports/{report_id}/download")
async def download_report(report_id: str, current_user: CurrentUser, db: DbSession):
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if report.status != "COMPLETED":
        raise HTTPException(status_code=400, detail=f"Report is not ready. Status: {report.status}")

    if not report.file_path or not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    extension = report.format.value.lower()
    media_types = {
        "pdf": "application/pdf",
        "html": "text/html",
        "json": "application/json",
        "csv": "text/csv",
    }

    return FileResponse(
        path=report.file_path,
        media_type=media_types.get(extension, "application/octet-stream"),
        filename=f"pentest_report_{report_id}.{extension}",
    )
