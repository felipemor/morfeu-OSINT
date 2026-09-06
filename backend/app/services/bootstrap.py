"""
Bootstrap Service — Create admin user on first startup
"""
import structlog
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.core.security import get_password_hash
from app.core.config import settings
from app.models import User, UserRole

logger = structlog.get_logger(__name__)


async def bootstrap_admin_user():
    """Create the default admin user if no users exist."""
    async with AsyncSessionLocal() as db:
        try:
            result = await db.execute(select(User).limit(1))
            existing_user = result.scalar_one_or_none()

            if existing_user:
                logger.info("Admin user already exists, skipping bootstrap")
                return

            admin = User(
                email=settings.ADMIN_EMAIL,
                hashed_password=get_password_hash(settings.ADMIN_PASSWORD),
                full_name=settings.ADMIN_FULL_NAME,
                role=UserRole.ADMIN,
                is_active=True,
            )
            db.add(admin)
            await db.commit()

            logger.info(
                "✅ Admin user created",
                email=settings.ADMIN_EMAIL,
                note="Change the default password immediately!",
            )
        except Exception as e:
            logger.error("Failed to bootstrap admin user", error=str(e))
            await db.rollback()
