"""
Users Router — User management (ADMIN only for most operations)
"""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
import structlog

from app.api.deps import CurrentUser, DbSession, RequireAdmin
from app.core.security import get_password_hash
from app.models import User, UserRole
from app.services.audit import log_action

logger = structlog.get_logger(__name__)
router = APIRouter()


class UserCreate(BaseModel):
    email: str
    password: str
    full_name: str
    role: UserRole = UserRole.ANALYST


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


@router.get("", response_model=list[UserResponse], dependencies=[RequireAdmin])
async def list_users(db: DbSession, current_user: CurrentUser):
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return result.scalars().all()


@router.post("", response_model=UserResponse, status_code=201, dependencies=[RequireAdmin])
async def create_user(body: UserCreate, db: DbSession, current_user: CurrentUser, request: Request):
    # Check duplicate email
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        email=body.email,
        hashed_password=get_password_hash(body.password),
        full_name=body.full_name,
        role=body.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    await log_action(
        db=db, user_id=current_user.id, action="USER_CREATED",
        resource_type="user", resource_id=user.id,
        details={"email": user.email, "role": user.role.value},
        ip_address=request.client.host if request.client else None,
    )

    return user


@router.put("/{user_id}/deactivate", dependencies=[RequireAdmin])
async def deactivate_user(user_id: str, db: DbSession, current_user: CurrentUser, request: Request):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")

    user.is_active = False
    await db.commit()

    await log_action(
        db=db, user_id=current_user.id, action="USER_DEACTIVATED",
        resource_type="user", resource_id=user_id,
        ip_address=request.client.host if request.client else None,
    )
    return {"message": "User deactivated"}
