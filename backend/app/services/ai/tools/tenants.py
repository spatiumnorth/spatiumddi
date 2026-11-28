"""Operator Copilot tool for tenants (#4263, multi-tenancy phase 1).

``find_tenants`` lists tenants with how many IP spaces, groups and API tokens
belong to each. Superadmin-only, like the ``/tenants`` REST routes, and not
``tenant_aware``: a tenant user is never offered it. Read-only, no secrets, so
default-enabled; the tenants module gates it.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import APIToken, Group, User
from app.models.ipam import IPSpace
from app.models.tenant import Tenant
from app.services.ai.tools.base import register_tool


class FindTenantsArgs(BaseModel):
    search: str | None = Field(default=None, description="Substring match on the tenant name.")
    limit: int = Field(default=100, ge=1, le=500, description="Max rows to return (1-500).")


@register_tool(
    name="find_tenants",
    permission="superadmin",
    description=(
        "List tenants (multi-tenancy). A tenant owns IP spaces; groups bound to it make "
        "their members tenant users, confined to those spaces. Returns each tenant's name, "
        "description and how many IP spaces, groups and API tokens belong to it. Read-only."
    ),
    args_model=FindTenantsArgs,
    category="ipam",
    default_enabled=True,
    module="ipam.tenants",
)
async def find_tenants(db: AsyncSession, user: User, args: FindTenantsArgs) -> dict[str, Any]:
    stmt = select(Tenant).order_by(func.lower(Tenant.name)).limit(args.limit)
    if args.search:
        stmt = stmt.where(Tenant.name.ilike(f"%{args.search}%"))
    rows = list((await db.execute(stmt)).scalars())
    out: list[dict[str, Any]] = []
    for t in rows:
        counts: dict[str, int] = {}
        for key, col in (
            ("ip_spaces", IPSpace.tenant_id),
            ("groups", Group.tenant_id),
            ("api_tokens", APIToken.tenant_id),
        ):
            counts[key] = int(
                await db.scalar(
                    select(func.count())
                    .select_from(col.class_)
                    .where(col == t.id)
                    .execution_options(include_deleted=True)
                )
                or 0
            )
        out.append({"id": str(t.id), "name": t.name, "description": t.description, **counts})
    return {"tenants": out}
