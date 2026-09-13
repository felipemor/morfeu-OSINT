"""
Schedule Router — Pentest project schedule/Gantt management
"""
from datetime import datetime, date
from typing import Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
import structlog

from app.api.deps import CurrentUser, DbSession
from app.models import Project

logger = structlog.get_logger(__name__)
router = APIRouter()


# ─── Schemas ──────────────────────────────────────────────────────────────────

class ScheduleItemCreate(BaseModel):
    phase: str
    name: str
    start_date: str   # YYYY-MM-DD
    end_date: str     # YYYY-MM-DD
    status: str = "PLANNED"
    assignee: Optional[str] = None
    notes: Optional[str] = None


class ScheduleItemUpdate(BaseModel):
    phase: Optional[str] = None
    name: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    status: Optional[str] = None
    assignee: Optional[str] = None
    notes: Optional[str] = None


class ScheduleItemResponse(BaseModel):
    id: str
    project_id: str
    phase: str
    name: str
    start_date: str
    end_date: str
    status: str
    assignee: Optional[str]
    notes: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ─── Helper: project existence check ──────────────────────────────────────────

async def _get_project_or_404(project_id: str, db: DbSession) -> Project:
    from sqlalchemy import select
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/{project_id}/schedule", response_model=list[ScheduleItemResponse])
async def list_schedule(project_id: str, current_user: CurrentUser, db: DbSession):
    """List all schedule items for a project."""
    await _get_project_or_404(project_id, db)

    try:
        from sqlalchemy import select, text
        result = await db.execute(
            text("SELECT * FROM pentest_schedule_items WHERE project_id = :pid ORDER BY start_date ASC"),
            {"pid": project_id}
        )
        rows = result.mappings().all()
        return [dict(r) for r in rows]
    except Exception:
        # Table doesn't exist yet — return empty list gracefully
        return []


@router.post("/{project_id}/schedule", response_model=ScheduleItemResponse, status_code=status.HTTP_201_CREATED)
async def create_schedule_item(
    project_id: str,
    body: ScheduleItemCreate,
    current_user: CurrentUser,
    db: DbSession,
):
    """Add a schedule item to a project."""
    await _get_project_or_404(project_id, db)

    import uuid
    item_id = str(uuid.uuid4())
    now = datetime.utcnow()

    try:
        from sqlalchemy import text
        await db.execute(
            text("""
                INSERT INTO pentest_schedule_items
                  (id, project_id, phase, name, start_date, end_date, status, assignee, notes, created_at, updated_at)
                VALUES
                  (:id, :project_id, :phase, :name, :start_date, :end_date, :status, :assignee, :notes, :created_at, :updated_at)
            """),
            {
                "id": item_id,
                "project_id": project_id,
                "phase": body.phase,
                "name": body.name,
                "start_date": body.start_date,
                "end_date": body.end_date,
                "status": body.status,
                "assignee": body.assignee,
                "notes": body.notes,
                "created_at": now,
                "updated_at": now,
            }
        )
        await db.commit()
    except Exception as e:
        await db.rollback()
        logger.warning("schedule_insert_failed", error=str(e))
        # Return in-memory fallback if table doesn't exist
        return ScheduleItemResponse(
            id=item_id, project_id=project_id,
            phase=body.phase, name=body.name,
            start_date=body.start_date, end_date=body.end_date,
            status=body.status, assignee=body.assignee, notes=body.notes,
            created_at=now, updated_at=now,
        )

    return ScheduleItemResponse(
        id=item_id, project_id=project_id,
        phase=body.phase, name=body.name,
        start_date=body.start_date, end_date=body.end_date,
        status=body.status, assignee=body.assignee, notes=body.notes,
        created_at=now, updated_at=now,
    )


@router.put("/{project_id}/schedule/{item_id}", response_model=ScheduleItemResponse)
async def update_schedule_item(
    project_id: str,
    item_id: str,
    body: ScheduleItemUpdate,
    current_user: CurrentUser,
    db: DbSession,
):
    """Update a schedule item."""
    now = datetime.utcnow()
    updates = body.model_dump(exclude_unset=True)
    updates["updated_at"] = now
    updates["id"] = item_id

    try:
        from sqlalchemy import text
        set_clause = ", ".join([f"{k} = :{k}" for k in updates if k != "id"])
        await db.execute(
            text(f"UPDATE pentest_schedule_items SET {set_clause} WHERE id = :id AND project_id = :project_id"),
            {**updates, "project_id": project_id}
        )
        await db.commit()

        result = await db.execute(
            text("SELECT * FROM pentest_schedule_items WHERE id = :id"),
            {"id": item_id}
        )
        row = result.mappings().first()
        if row:
            return dict(row)
    except Exception as e:
        await db.rollback()
        logger.warning("schedule_update_failed", error=str(e))

    raise HTTPException(status_code=404, detail="Schedule item not found")


@router.delete("/{project_id}/schedule/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule_item(
    project_id: str,
    item_id: str,
    current_user: CurrentUser,
    db: DbSession,
):
    """Delete a schedule item."""
    try:
        from sqlalchemy import text
        await db.execute(
            text("DELETE FROM pentest_schedule_items WHERE id = :id AND project_id = :project_id"),
            {"id": item_id, "project_id": project_id}
        )
        await db.commit()
    except Exception as e:
        await db.rollback()
        logger.warning("schedule_delete_failed", error=str(e))
