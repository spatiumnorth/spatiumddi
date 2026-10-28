"""A signed-in caller for tests of routes that answer everyone but tell a
signed-in caller more (#2935: ``/api/v1/version``, ``/health/platform``,
``/api/openapi.json``)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User


async def signed_in_headers(db: AsyncSession) -> dict[str, str]:
    """Commit a plain active user (no roles) and return its Bearer header."""
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Signed in",
        hashed_password=hash_password("OldPass123!"),
        auth_source="local",
        is_active=True,
        is_superadmin=False,
        force_password_change=False,
        password_changed_at=datetime.now(UTC),
    )
    db.add(user)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
