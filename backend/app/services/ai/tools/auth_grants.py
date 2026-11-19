"""Time-bound RBAC grant tools for the Operator Copilot — issue #65.

* ``find_time_bound_grants`` (read) — superadmin-only, surfaces the temporary
  grants in effect so an admin can ask "what temporary access is live right
  now?" or "show grants for group X, including expired".
* ``propose_grant_temporary_access`` (write proposal) — default-disabled,
  mints a temporary grant via the preview / apply proposal flow. The
  underlying operation is itself superadmin-gated at apply time.

Both are tagged ``category='admin'`` because the surface is
security-sensitive RBAC metadata / mutation.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import is_effective_superadmin
from app.models.auth import Group, User
from app.models.time_bound_grant import TimeBoundGrant
from app.services.ai.operations import GrantTemporaryAccessArgs
from app.services.ai.tools.base import register_tool


def _superadmin_gate(user: User) -> dict[str, Any] | None:
    if not is_effective_superadmin(user):
        return {
            "error": (
                "This tool returns security-sensitive RBAC grant metadata, "
                "so it's restricted to superadmin users. Ask your platform "
                "admin to run the query."
            )
        }
    return None


# ── find_time_bound_grants ─────────────────────────────────────────────


class FindTimeBoundGrantsArgs(BaseModel):
    group_id: str | None = Field(
        default=None,
        description="Filter to grants attached to this group (UUID).",
    )
    include_expired: bool = Field(
        default=False,
        description=(
            "When True, also return revoked / expired grants (audit history). "
            "Default returns only live grants."
        ),
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_time_bound_grants",
    permission="superadmin",
    description=(
        "List time-bound (temporary, auto-expiring) RBAC grants (superadmin "
        "only — issue #65). Each row carries the group, the granted "
        "action / resource_type / optional resource_id, expires_at, "
        "revoked_at, whether it's still live, the reason, and who granted "
        "it. Use for 'what temporary access is live right now?' or 'show "
        "expired grants for group X'."
    ),
    args_model=FindTimeBoundGrantsArgs,
    category="admin",
)
async def find_time_bound_grants(
    db: AsyncSession, user: User, args: FindTimeBoundGrantsArgs
) -> list[dict[str, Any]]:
    gate = _superadmin_gate(user)
    if gate:
        return [gate]

    stmt = select(TimeBoundGrant).order_by(TimeBoundGrant.created_at.desc())
    if args.group_id:
        try:
            gid = uuid.UUID(args.group_id)
        except (ValueError, AttributeError):
            return [{"error": f"Invalid group_id: {args.group_id!r}"}]
        stmt = stmt.where(TimeBoundGrant.group_id == gid)
    if not args.include_expired:
        now = datetime.now(UTC)
        stmt = stmt.where(TimeBoundGrant.revoked_at.is_(None)).where(
            TimeBoundGrant.expires_at > now
        )
    stmt = stmt.limit(args.limit)
    rows = list((await db.execute(stmt)).scalars().all())

    # Resolve group names in one round-trip.
    group_ids = {r.group_id for r in rows}
    names: dict[uuid.UUID, str] = {}
    if group_ids:
        for g in (await db.execute(select(Group).where(Group.id.in_(group_ids)))).scalars().all():
            names[g.id] = g.name

    now = datetime.now(UTC)
    out: list[dict[str, Any]] = []
    for r in rows:
        expires = r.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        out.append(
            {
                "id": str(r.id),
                "group_id": str(r.group_id),
                "group_name": names.get(r.group_id),
                "action": r.action,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "expires_at": r.expires_at.isoformat(),
                "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
                "is_active": r.revoked_at is None and expires > now,
                "reason": r.reason,
                "granted_by_user_id": (str(r.granted_by_user_id) if r.granted_by_user_id else None),
            }
        )
    return out


# ── propose_grant_temporary_access ─────────────────────────────────────


@register_tool(
    name="propose_grant_temporary_access",
    permission=("admin", "group"),
    description=(
        "Prepare a proposal to grant a group temporary, auto-expiring RBAC "
        "access (issue #65). Superadmin only. Returns a kind='proposal' "
        "payload — surface the preview to the operator and wait for them to "
        "click Apply. Never applies the grant directly."
    ),
    args_model=GrantTemporaryAccessArgs,
    writes=False,  # the propose tool is read-only; apply is the write.
    category="admin",
    default_enabled=False,
)
async def propose_grant_temporary_access(
    db: AsyncSession, user: User, args: GrantTemporaryAccessArgs
) -> dict[str, Any]:
    # Local import avoids a circular at module import time (proposals imports
    # the tool base which imports operations which is fine, but keeping the
    # heavier proposals helper lazy mirrors the other propose_* shims).
    from app.services.ai.tools.proposals import _propose_via

    return await _propose_via(db=db, user=user, operation_name="grant_temporary_access", args=args)
