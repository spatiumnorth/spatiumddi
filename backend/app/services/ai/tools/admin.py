"""Tier 2 RBAC / administration read tools for the Operator Copilot
(issue #101).

Surfaces the auth subsystem — Users / Groups / Roles — so admins
can ask "who has write access to the prod space?", "list every
group with the DNS Editor role", or "show me the permissions for
the Auditor role".

All three tools are **superadmin-only** because the surface includes
security-sensitive metadata (auth source, MFA enrollment, login
history, RBAC permission JSON). Non-superadmin callers get a clear
error message rather than a silent empty list — the chat
orchestrator will surface the message and the LLM can explain how
to escalate.

If a deployment wants to grant a custom group access to these tools
without granting full superadmin, the cleanest path today is the
per-provider tool allowlist on the AI Provider modal (narrow the
provider to non-admin tools for everyone except the SRE team's
provider).
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.permissions import is_effective_superadmin
from app.models.auth import Group, Role, User
from app.models.auth_provider import AuthProvider
from app.services.ai.tools.base import register_tool


def _try_uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError):
        return None


def _superadmin_gate(user: User) -> dict[str, Any] | None:
    """Returns an error dict the caller should bubble up if the
    requesting user isn't a superadmin; ``None`` when the call is
    allowed. Tools wrap their list/dict return as a single-element
    error response so the orchestrator's "tool result" message reads
    as a clear refusal rather than an empty payload."""
    if not is_effective_superadmin(user):
        return {
            "error": (
                "This tool returns security-sensitive RBAC and login "
                "metadata, so it's restricted to superadmin users. "
                "Ask your platform admin to run the query."
            )
        }
    return None


# ── list_users ────────────────────────────────────────────────────────


class ListUsersArgs(BaseModel):
    search: str | None = Field(
        default=None,
        description="Substring match on username, email, or display name.",
    )
    auth_source: str | None = Field(
        default=None,
        description="Filter by auth source: local / ldap / oidc / saml / radius / tacacs.",
    )
    is_active: bool | None = Field(
        default=None, description="Filter by active flag (True / False)."
    )
    superadmin_only: bool = Field(
        default=False,
        description="When True, return only superadmin users — useful for 'who has admin'.",
    )
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="list_users",
    permission="superadmin",
    description=(
        "List users (superadmin only). Each row carries username, "
        "email, display_name, is_active, is_superadmin, auth_source, "
        "auth_provider (the provider an external account belongs to, or "
        "null), MFA enrollment flag, last_login_at + IP, lockout state, "
        "and the names of the auth groups they belong to. An external "
        "account with a null auth_provider cannot sign in until an admin "
        "links it (#1235). Use for 'who has admin', 'list locked-out "
        "accounts', 'which accounts need linking', or 'who hasn't "
        "logged in this quarter'."
    ),
    args_model=ListUsersArgs,
    category="admin",
)
async def list_users(db: AsyncSession, user: User, args: ListUsersArgs) -> list[dict[str, Any]]:
    gate = _superadmin_gate(user)
    if gate:
        return [gate]
    stmt = select(User).options(selectinload(User.groups))
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(User.username).like(like),
                func.lower(User.email).like(like),
                func.lower(User.display_name).like(like),
            )
        )
    if args.auth_source:
        stmt = stmt.where(User.auth_source == args.auth_source.lower())
    if args.is_active is not None:
        stmt = stmt.where(User.is_active.is_(args.is_active))
    if args.superadmin_only:
        stmt = stmt.where(User.is_superadmin.is_(True))
    stmt = stmt.order_by(User.username.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().unique().all()
    provider_names = {
        pid: name for pid, name in (await db.execute(select(AuthProvider.id, AuthProvider.name)))
    }
    return [
        {
            "id": str(r.id),
            "username": r.username,
            "email": r.email,
            "display_name": r.display_name,
            "is_active": r.is_active,
            "is_superadmin": r.is_superadmin,
            "auth_source": r.auth_source,
            "auth_provider": provider_names.get(r.auth_provider_id),
            "totp_enabled": r.totp_enabled,
            "last_login_at": r.last_login_at.isoformat() if r.last_login_at else None,
            "last_login_ip": r.last_login_ip,
            "failed_login_count": r.failed_login_count,
            "locked_until": (
                r.failed_login_locked_until.isoformat() if r.failed_login_locked_until else None
            ),
            "groups": sorted(g.name for g in r.groups),
        }
        for r in rows
    ]


# ── list_groups ───────────────────────────────────────────────────────


class ListGroupsArgs(BaseModel):
    search: str | None = Field(
        default=None,
        description="Substring match on group name or description.",
    )
    auth_source: str | None = Field(
        default=None, description="Filter by auth source (local / ldap / oidc / saml)."
    )
    has_role: str | None = Field(
        default=None,
        description="Return only groups that hold the named role (exact match).",
    )
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="list_groups",
    permission="superadmin",
    description=(
        "List auth groups + their role assignments + member counts "
        "(superadmin only). Each row carries id, name, description, "
        "auth_source, external_dn (for LDAP-mapped groups), member_count, "
        "and the names of the roles assigned to the group. Use for "
        "'which groups have the DNS Editor role' or 'list LDAP-mapped "
        "groups'."
    ),
    args_model=ListGroupsArgs,
    category="admin",
)
async def list_groups(db: AsyncSession, user: User, args: ListGroupsArgs) -> list[dict[str, Any]]:
    gate = _superadmin_gate(user)
    if gate:
        return [gate]
    stmt = select(Group).options(
        selectinload(Group.roles),
        selectinload(Group.users),
    )
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Group.name).like(like),
                func.lower(Group.description).like(like),
            )
        )
    if args.auth_source:
        stmt = stmt.where(Group.auth_source == args.auth_source.lower())
    stmt = stmt.order_by(Group.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().unique().all()
    if args.has_role:
        target = args.has_role.lower()
        rows = [g for g in rows if any(r.name.lower() == target for r in g.roles)]
    return [
        {
            "id": str(g.id),
            "name": g.name,
            "description": g.description,
            "auth_source": g.auth_source,
            "external_dn": g.external_dn,
            "member_count": len(g.users),
            "roles": sorted(r.name for r in g.roles),
        }
        for g in rows
    ]


# ── list_roles ────────────────────────────────────────────────────────


class ListRolesArgs(BaseModel):
    search: str | None = Field(
        default=None, description="Substring match on role name or description."
    )
    builtin: Literal["only", "exclude"] | None = Field(
        default=None,
        description=(
            "``only`` returns just the built-in seeded roles (Superadmin, "
            "Viewer, …). ``exclude`` returns just operator-authored "
            "custom roles. Default returns both."
        ),
    )
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="list_roles",
    permission="superadmin",
    description=(
        "List RBAC roles + their permission grants + group "
        "assignments (superadmin only). Each row carries id, name, "
        "description, is_builtin, the permissions JSON array (each "
        "entry has action / resource_type / optional resource_id), "
        "and the names of groups that hold the role. Use for "
        "'show the permissions for role X' or 'list custom roles'."
    ),
    args_model=ListRolesArgs,
    category="admin",
)
async def list_roles(db: AsyncSession, user: User, args: ListRolesArgs) -> list[dict[str, Any]]:
    gate = _superadmin_gate(user)
    if gate:
        return [gate]
    stmt = select(Role).options(selectinload(Role.groups))
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Role.name).like(like),
                func.lower(Role.description).like(like),
            )
        )
    if args.builtin == "only":
        stmt = stmt.where(Role.is_builtin.is_(True))
    elif args.builtin == "exclude":
        stmt = stmt.where(Role.is_builtin.is_(False))
    stmt = stmt.order_by(Role.is_builtin.desc(), Role.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().unique().all()
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "description": r.description,
            "is_builtin": r.is_builtin,
            "permission_count": len(r.permissions or []),
            "permissions": r.permissions or [],
            "groups": sorted(g.name for g in r.groups),
        }
        for r in rows
    ]
