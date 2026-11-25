"""Operator Copilot tool for resource locks (#3361).

* ``find_locked_resources`` — read-only. Lists the IPAM / DNS / DHCP objects
  that carry an edit or delete lock: type, name, level, who locked it, when,
  why, and when it lapses. Filtered to the types the caller may read.
  Default-enabled (discovery, no secrets, read-only).

There is deliberately no ``propose_lock`` and no ``propose_unlock``: removing
a lock is a decision a person makes, with a reason, through the lock API or
the UI. The ``propose_*`` tools that change objects (the delete operations)
refuse a locked target with the lock's reason, because the check lives in the
operation itself (``app.services.locks``), not in the tool.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import user_has_permission
from app.models.auth import User
from app.services import locks as lock_svc
from app.services.ai.tools.base import register_tool


class FindLockedResourcesArgs(BaseModel):
    resource_type: str | None = Field(
        default=None,
        description=(
            "Only this type: ip_space, ip_block, subnet, ip_address, dns_group, "
            "dns_view, dns_zone, dns_record, dhcp_scope or dhcp_static."
        ),
    )
    level: str | None = Field(
        default=None, description="Only locks of this level: 'edit' or 'delete'."
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_locked_resources",
    permission="authenticated",
    description=(
        "List IPAM, DNS and DHCP objects that are locked against editing or "
        "deletion (change freezes, audit holds). Each row gives the object's "
        "type, id and name, the lock level ('edit' freezes operative fields "
        "and blocks delete; 'delete' blocks delete only), who set it, when, "
        "the reason, and when it lapses. Use it before proposing a change, "
        "to see why one is refused. Read-only."
    ),
    args_model=FindLockedResourcesArgs,
    category="ipam",
    default_enabled=True,
    module=None,
)
async def find_locked_resources(
    db: AsyncSession, user: User, args: FindLockedResourcesArgs
) -> dict[str, Any]:
    if args.resource_type is not None and args.resource_type not in lock_svc.SPECS:
        return {"error": f"{args.resource_type!r} is not lockable", "items": []}
    types = [args.resource_type] if args.resource_type else list(lock_svc.SPECS)
    items: list[dict[str, Any]] = []
    for rtype in types:
        spec = lock_svc.SPECS[rtype]
        if not user_has_permission(user, "read", spec.permission_type):
            continue
        stmt: Select[Any] = select(spec.model).where(lock_svc.active_lock_where(spec.model))
        if args.level:
            stmt = stmt.where(spec.model.lock_level == args.level)  # type: ignore[attr-defined]
        for obj in (await db.execute(stmt.limit(args.limit))).scalars().all():
            info = lock_svc.active_lock(obj)
            if info is None:
                continue
            items.append(
                {
                    "resource_type": rtype,
                    "resource_id": str(obj.id),  # type: ignore[attr-defined]
                    "name": lock_svc.display(rtype, obj),
                    "level": info.level,
                    "locked_by": info.locked_by,
                    "locked_at": info.locked_at.isoformat() if info.locked_at else None,
                    "reason": info.reason,
                    "expires_at": info.expires_at.isoformat() if info.expires_at else None,
                }
            )
    return {"count": len(items[: args.limit]), "items": items[: args.limit]}
