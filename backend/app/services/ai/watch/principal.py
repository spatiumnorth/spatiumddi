"""The identity Copilot Watch runs as (issue #4405).

A built-in ``user`` row that cannot sign in: it has no password and no
identity provider, and its ``auth_source`` is ``service``, which no
sign-in path accepts. It is not a superadmin. What it may read comes from
the roles of one group, ``Copilot Watch``, which starts with the built-in
``Viewer`` role (read on everything). An operator narrows Watch by giving
that group narrower roles; the roles are assigned once, when the group is
created, and never rewritten afterwards.

Every tool call of a run is dispatched as this user, so the tool
registry's permission check is the gate, exactly as it is for a person in
the chat. A run is refused while the identity holds anything beyond
``read`` (see :func:`principal_problem`): the group is the operator's to
edit, and Watch must not quietly become a writer because someone attached
the wrong role to it.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.audit import AuditLog
from app.models.auth import Group, Role, User

WATCH_PRINCIPAL_USERNAME = "copilot-watch"
WATCH_PRINCIPAL_DISPLAY = "Copilot Watch"
WATCH_PRINCIPAL_AUTH_SOURCE = "service"
WATCH_GROUP_NAME = "Copilot Watch"
# The role the group starts with. Built-in, so it exists on every install.
WATCH_DEFAULT_ROLE = "Viewer"

# The value Watch puts under ``via`` in the audit rows it writes itself.
AUDIT_VIA = "ai_watch"


def is_service_account(user: User) -> bool:
    """Whether ``user`` is a built-in service identity, which the user
    admin routes must not turn into something a person can sign in as."""
    return user.auth_source == WATCH_PRINCIPAL_AUTH_SOURCE


async def get_watch_principal(db: AsyncSession) -> User | None:
    return (
        await db.execute(
            select(User)
            .where(User.username == WATCH_PRINCIPAL_USERNAME)
            .where(User.auth_source == WATCH_PRINCIPAL_AUTH_SOURCE)
            .options(selectinload(User.groups).selectinload(Group.roles))
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def ensure_watch_principal(db: AsyncSession) -> User:
    """Return the Watch identity, creating it and its group on first use.

    Flushes, does not commit. Creation is audited. An existing account
    that happens to be called ``copilot-watch`` but is not the service
    identity is left alone and refused: Watch never adopts a person's
    account.
    """
    existing = await get_watch_principal(db)
    if existing is not None:
        return existing

    clash = await db.scalar(select(User).where(User.username == WATCH_PRINCIPAL_USERNAME))
    if clash is not None:
        raise WatchPrincipalError(
            f"An account named '{WATCH_PRINCIPAL_USERNAME}' already exists and is not the "
            "Copilot Watch service identity. Rename or remove it first."
        )

    group = await db.scalar(
        select(Group).where(Group.name == WATCH_GROUP_NAME).options(selectinload(Group.roles))
    )
    if group is None:
        group = Group(
            name=WATCH_GROUP_NAME,
            description=(
                "What Copilot Watch may read. Its only member is the built-in "
                "copilot-watch service identity. Replace the Viewer role with "
                "narrower read-only roles to limit what Watch can see."
            ),
        )
        viewer = await db.scalar(select(Role).where(Role.name == WATCH_DEFAULT_ROLE))
        group.roles = [viewer] if viewer is not None else []
        db.add(group)

    user = User(
        username=WATCH_PRINCIPAL_USERNAME,
        email="",
        display_name=WATCH_PRINCIPAL_DISPLAY,
        hashed_password=None,
        auth_source=WATCH_PRINCIPAL_AUTH_SOURCE,
        is_active=True,
        is_superadmin=False,
        force_password_change=False,
    )
    user.groups = [group]
    db.add(user)
    await db.flush()
    db.add(
        AuditLog(
            user_id=None,
            user_display_name="<system>",
            auth_source="system",
            action="create",
            resource_type="user",
            resource_id=str(user.id),
            resource_display=WATCH_PRINCIPAL_USERNAME,
            new_value={
                "auth_source": WATCH_PRINCIPAL_AUTH_SOURCE,
                "group": WATCH_GROUP_NAME,
                "roles": [r.name for r in group.roles],
                "via": AUDIT_VIA,
            },
        )
    )
    await db.flush()
    found = await get_watch_principal(db)
    assert found is not None  # just created in this session
    return found


class WatchPrincipalError(Exception):
    """The Watch identity cannot be created."""


def principal_problem(user: User) -> str | None:
    """Why ``user`` must not be used for a run, or None when it may be.

    The identity has to be active, must not be a superadmin, and every
    permission it holds must be a plain ``read``. ``admin`` and ``*``
    imply write and delete, so they are refused too.
    """
    if not user.is_active:
        return "principal_disabled"
    if user.is_superadmin:
        return "principal_not_read_only"
    for group in user.groups:
        for role in group.roles:
            for perm in role.permissions or []:
                if not isinstance(perm, dict) or perm.get("action") != "read":
                    return "principal_not_read_only"
    return None


def principal_summary(user: User) -> dict[str, object]:
    """What the settings page shows about the identity."""
    roles = sorted({r.name for g in user.groups for r in g.roles})
    return {
        "id": str(user.id),
        "username": user.username,
        "is_active": user.is_active,
        "group": WATCH_GROUP_NAME,
        "roles": roles,
        "problem": principal_problem(user),
    }


__all__ = [
    "AUDIT_VIA",
    "WATCH_GROUP_NAME",
    "WATCH_PRINCIPAL_AUTH_SOURCE",
    "WATCH_PRINCIPAL_USERNAME",
    "WatchPrincipalError",
    "ensure_watch_principal",
    "get_watch_principal",
    "is_service_account",
    "principal_problem",
    "principal_summary",
]
