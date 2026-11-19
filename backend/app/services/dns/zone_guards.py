"""Zone-level write guards shared by the REST router and the copilot (#2652).

Each helper returns a refusal string (or ``None``) so a REST handler can wrap
it in an ``HTTPException`` and a copilot operation in ``ValueError`` without
the two paths carrying separate copies of the rule.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dns_names import (
    admin_email_error,
    contains_zonefile_unsafe,
    primary_ns_error,
)


def soa_field_error(value: str | None, field: str | None = None) -> str | None:
    """Why a zone SOA ``primary_ns`` / ``admin_email`` cannot be stored, or None."""
    if not value:
        return None
    if contains_zonefile_unsafe(value):
        return (
            "must be a bare domain name — no whitespace, control characters, "
            "or zone-file syntax (e.g. ';' '$' '@')"
        )
    if field == "primary_ns":
        # #2075 — a Primary NS BIND's check-names refuses stops the zone
        # being served at all, so it is a host name or it is not stored.
        err = primary_ns_error(value)
        if err is not None:
            return f"Primary NS (primary_ns) {err}"
    if field == "admin_email":
        # #2916 — the SOA RNAME is checked by BIND too (check-names).
        err = admin_email_error(value)
        if err is not None:
            return f"Admin Email (admin_email) {err}"
    return None


async def zone_name_taken(
    db: AsyncSession, group_id: uuid.UUID, view_id: uuid.UUID | None, name: str
) -> bool:
    """True when a live zone of that name exists in the group/view.

    The ``(group_id, view_id, name)`` unique constraint cannot catch this when
    ``view_id`` is NULL (NULLs are distinct), so the check is the only guard.
    """
    from app.models.dns import DNSZone  # noqa: PLC0415

    row = (
        await db.execute(
            select(DNSZone.id).where(
                DNSZone.group_id == group_id,
                DNSZone.view_id == view_id,  # == None renders IS NULL
                DNSZone.name == name,
                DNSZone.deleted_at.is_(None),
            )
        )
    ).first()
    return row is not None
