"""Operator Copilot read tool for the per-table retention overview (#2274).

Sister to ``find_retention_settings`` (which lists the windows): this one
lists, per table, the size, the row estimate, the window that governs it and
the oldest row, so "what is eating my disk?" has one answer. Read-only, and
cheap: row counts are estimates and the oldest row is read only where its
column is indexed. No secrets.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.services.ai.tools.base import register_tool
from app.services.retention_overview import build_retention_overview


class FindDataRetentionArgs(BaseModel):
    """No arguments."""


@register_tool(
    name="find_data_retention",
    permission="superadmin",
    description=(
        "List, for each table that has a retention policy, its on-disk size, "
        "estimated row count, the retention setting and window that govern "
        "it (or that it is never pruned), and its oldest row. Biggest first. "
        "Use for 'what is eating my database?', 'why is the database so big?' "
        "or 'how far back does this table go?'. Row counts are estimates; the "
        "oldest row is omitted for a table whose timestamp is not indexed."
    ),
    args_model=FindDataRetentionArgs,
    category="admin",
    default_enabled=True,
)
async def find_data_retention(
    db: AsyncSession, user: User, args: FindDataRetentionArgs
) -> dict[str, Any]:
    rows = await build_retention_overview(db)
    return {"count": len(rows), "tables": rows}
