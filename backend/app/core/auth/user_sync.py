"""Reconcile an authenticated external subject (LDAP / OIDC / SAML) into the
local User + Group tables.

Called from both the password-grant LDAP branch in ``/auth/login`` and the
OIDC / SAML redirect callbacks.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import Group, User
from app.models.auth_provider import AuthGroupMapping, AuthProvider

logger = structlog.get_logger(__name__)


@dataclass
class ExternalAuthResult:
    """Normalised success payload from any external IdP.

    ``external_id`` is the stable, per-provider user identifier — LDAP DN,
    OIDC ``sub`` claim, or SAML ``NameID``. ``groups`` lists the raw
    group identifiers from the IdP (DNs for LDAP, claim values for OIDC).
    """

    external_id: str
    username: str
    email: str | None = None
    display_name: str | None = None
    groups: list[str] = field(default_factory=list)


class ExternalSyncRejected(Exception):
    """Raised when we refuse to provision or update a user.

    ``user`` is the existing account the refusal is about, when there is
    one, so the caller's ``denied`` audit row is linked to it — filtering
    the audit log by a disabled account shows the attempts to use it.
    """

    def __init__(self, reason: str, detail: str = "", *, user: User | None = None) -> None:
        self.reason = reason
        self.detail = detail
        self.user = user
        super().__init__(detail or reason)


async def _matched_internal_groups(
    db: AsyncSession, provider_id: uuid.UUID, user_group_identifiers: list[str]
) -> list[Group]:
    """Resolve the user's external group identifiers to internal Group rows,
    matching case-insensitively against the provider's mapping table."""
    if not user_group_identifiers:
        return []
    map_res = await db.execute(
        select(AuthGroupMapping).where(AuthGroupMapping.provider_id == provider_id)
    )
    mappings = map_res.unique().scalars().all()
    wanted = {g.lower() for g in user_group_identifiers}
    matched_ids = [m.internal_group_id for m in mappings if m.external_group.lower() in wanted]
    if not matched_ids:
        return []
    group_res = await db.execute(select(Group).where(Group.id.in_(matched_ids)))
    return list(group_res.unique().scalars().all())


async def sync_external_user(
    db: AsyncSession, provider: AuthProvider, result: ExternalAuthResult
) -> User:
    """Create or update the local user for an authenticated external subject.

    ``provider.type`` is used as the value for ``User.auth_source`` ("ldap",
    "oidc", or "saml"). Raises ``ExternalSyncRejected`` if the login should
    be refused (no mapping match, same-username local user, auto-create off,
    or a disabled account).
    """
    key = (result.external_id or "").strip()
    if not key:
        raise ExternalSyncRejected("invalid_external_response", "IdP returned empty external id")

    # 1) Group-mapping resolution — fail closed.
    groups = await _matched_internal_groups(db, provider.id, result.groups)
    if not groups:
        raise ExternalSyncRejected(
            "no_group_mapping_match",
            "User's external groups do not match any configured mapping",
        )

    auth_source = provider.type

    # 2) Look up existing row by (auth_source, external_id).
    res = await db.execute(
        select(User).where(User.auth_source == auth_source, User.external_id == key)
    )
    user: User | None = res.scalar_one_or_none()

    # 3) Username collision — must not clobber a local user.
    username = (result.username or "").strip() or key
    if user is None:
        name_res = await db.execute(select(User).where(User.username == username))
        collision = name_res.scalar_one_or_none()
        if collision is not None and collision.auth_source != auth_source:
            raise ExternalSyncRejected(
                "username_collision",
                f"A {collision.auth_source} user named {username!r} already exists",
            )
        if collision is not None:
            user = collision

    # 3b) A disabled account is refused HERE, before anything is minted
    # (#1242). Every later request already 403s on ``is_active``, so no data
    # was ever reachable — but the login itself completed: a session row, a
    # token pair and a ``login`` / ``success`` audit row for a login that was
    # never allowed. Raising routes it through each caller's existing
    # ``denied`` audit instead. Checked before the refresh below so a
    # disabled account's profile and group membership are not rewritten by
    # an attempt to use it either.
    if user is not None and not user.is_active:
        raise ExternalSyncRejected("account_disabled", "User account is disabled", user=user)

    # 4) Create or refresh.
    if user is None:
        if not provider.auto_create_users:
            raise ExternalSyncRejected(
                "auto_create_disabled",
                "Provider does not permit auto-creating users",
            )
        user = User(
            username=username,
            email=result.email or "",
            display_name=result.display_name or username,
            hashed_password=None,
            auth_source=auth_source,
            external_id=key,
            is_active=True,
            is_superadmin=False,
            force_password_change=False,
        )
        db.add(user)
        await db.flush()
        logger.info(
            "external_user_provisioned",
            username=user.username,
            auth_source=auth_source,
            provider=provider.name,
            external_id=key[:80],
        )
    else:
        user.external_id = key
        if provider.auto_update_users:
            if result.email and user.email != result.email:
                user.email = result.email
            if result.display_name and user.display_name != result.display_name:
                user.display_name = result.display_name

    # 5) Replace group membership with the mapped set.
    # SQLAlchemy's collection setter computes a diff against the currently
    # loaded collection, which triggers a lazy-load if we haven't touched
    # `user.groups` yet. Under an AsyncSession that lazy-load raises
    # MissingGreenlet. `awaitable_attrs` is the async-safe way to force the
    # load in an await-context; after this, the plain assignment is safe.
    await user.awaitable_attrs.groups
    user.groups = groups

    return user
