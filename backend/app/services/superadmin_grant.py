"""Who would become an effective superadmin through a change (#1412).

#1355 put the operator step-up on the ``is_superadmin`` flag: creating or
promoting a superadmin, or resetting one's password. But a user is also an
effective superadmin when one of their groups holds a role carrying the
``*`` / ``*`` permission (the built-in Superadmin role, or a clone), or a
live time-bound ``*`` / ``*`` grant. So a stolen superadmin session could
still make an account it controls a superadmin by adding it to such a group,
giving such a role to its group, or adding ``*`` / ``*`` to a role its group
already holds, and that account's password would pass every later step-up.

The check is on the effect, not the endpoint: :func:`newly_superadmin`
builds the current answer from the database, applies the change to an
in-memory copy, and returns the users who are superadmins afterwards and
were not before. A role edit that reaches fifty users needs one step-up, and
an edit that only touches people who are already superadmins needs none.

``is_active`` is deliberately ignored. ``is_effective_superadmin`` answers
False for a disabled account whose superadmin comes from a role, because the
role path goes through ``user_has_permission``, which requires an active
user. Judged that way, a stolen session could disable such an account, reset
its password with no step-up, and re-enable it.
"""

from __future__ import annotations

import copy
import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import inspect as sa_inspect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import Role, User, group_role, user_group
from app.models.time_bound_grant import TimeBoundGrant


def permissions_grant_superadmin(permissions: list[dict[str, Any]] | None) -> bool:
    """True when a permission list carries the unscoped ``*`` / ``*`` grant."""
    return any(
        p.get("action") == "*" and p.get("resource_type") == "*" and not p.get("resource_id")
        for p in permissions or []
    )


@dataclass
class SuperadminModel:
    """Every input to "who is a superadmin", detached from the session."""

    flagged: set[uuid.UUID] = field(default_factory=set)
    group_members: dict[uuid.UUID, set[uuid.UUID]] = field(default_factory=lambda: defaultdict(set))
    group_roles: dict[uuid.UUID, set[uuid.UUID]] = field(default_factory=lambda: defaultdict(set))
    role_wildcard: dict[uuid.UUID, bool] = field(default_factory=dict)
    granted_groups: set[uuid.UUID] = field(default_factory=set)

    def group_grants_superadmin(self, group_id: uuid.UUID) -> bool:
        return group_id in self.granted_groups or any(
            self.role_wildcard.get(r, False) for r in self.group_roles.get(group_id, ())
        )

    def superadmins(self) -> set[uuid.UUID]:
        out = set(self.flagged)
        for group_id, members in self.group_members.items():
            if self.group_grants_superadmin(group_id):
                out |= members
        return out


async def load_model(db: AsyncSession) -> SuperadminModel:
    model = SuperadminModel()
    model.flagged = set(
        (await db.execute(select(User.id).where(User.is_superadmin.is_(True)))).scalars()
    )
    for user_id, group_id in await db.execute(select(user_group.c.user_id, user_group.c.group_id)):
        model.group_members[group_id].add(user_id)
    for group_id, role_id in await db.execute(select(group_role.c.group_id, group_role.c.role_id)):
        model.group_roles[group_id].add(role_id)
    for role_id, permissions in await db.execute(select(Role.id, Role.permissions)):
        model.role_wildcard[role_id] = permissions_grant_superadmin(permissions)
    model.granted_groups = set(
        (
            await db.execute(
                select(TimeBoundGrant.group_id).where(
                    TimeBoundGrant.revoked_at.is_(None),
                    TimeBoundGrant.expires_at > datetime.now(UTC),
                    TimeBoundGrant.action == "*",
                    TimeBoundGrant.resource_type == "*",
                    TimeBoundGrant.resource_id.is_(None),
                )
            )
        ).scalars()
    )
    return model


async def newly_superadmin(
    db: AsyncSession, change: Callable[[SuperadminModel], None]
) -> set[uuid.UUID]:
    """Users the change would make effective superadmins who are not now.

    ``change`` mutates an in-memory copy, so call this BEFORE writing
    anything: a refused step-up then has nothing to roll back."""
    before = await load_model(db)
    after = copy.deepcopy(before)
    change(after)
    return after.superadmins() - before.superadmins()


def loaded_user_holds_superadmin(user: User) -> bool:
    """The flag or a ``*`` / ``*`` role among the user's LOADED groups,
    regardless of ``is_active``. For sync contexts (a response validator)
    that must not trigger a lazy load; a group or role relationship that is
    not loaded counts as absent. Live time-bound grants need the database,
    so they are :func:`holds_superadmin`'s alone."""
    if user.is_superadmin:
        return True
    if "groups" in sa_inspect(user).unloaded:
        return False
    for group in user.groups:
        if "roles" in sa_inspect(group).unloaded:
            continue
        if any(permissions_grant_superadmin(r.permissions) for r in group.roles):
            return True
    return False


async def holds_superadmin(db: AsyncSession, user_id: uuid.UUID) -> bool:
    """Whether the user is a superadmin by any path, active or not."""
    return user_id in (await load_model(db)).superadmins()


__all__ = [
    "SuperadminModel",
    "holds_superadmin",
    "load_model",
    "loaded_user_holds_superadmin",
    "newly_superadmin",
    "permissions_grant_superadmin",
]
