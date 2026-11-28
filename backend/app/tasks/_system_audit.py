"""Audit rows for mutations a Celery task makes on its own (#1257).

Non-negotiable #4: every mutation is audited. A task has no request and no
user, so its row carries the same synthetic ``<system>`` actor as the other
task-written rows (``dns-sync``, ``trash-purge``, ...), and a task that
touches many rows writes ONE summary row per run, never one per row.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog


def add_system_audit(
    db: AsyncSession,
    *,
    action: str,
    resource_type: str,
    resource_id: str,
    resource_display: str,
    new_value: dict[str, Any],
    result: str = "success",
) -> None:
    """Queue a system-actor audit row on ``db``; the caller commits."""
    db.add(
        AuditLog(
            user_display_name="<system>",
            auth_source="system",
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_display=resource_display,
            result=result,
            new_value=new_value,
        )
    )
