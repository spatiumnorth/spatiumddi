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


async def _find_linked_user(
    db: AsyncSession, provider: AuthProvider, key: str, username: str
) -> User | None:
    """The account this provider's subject ``key`` signs in as, or None if it
    has none yet. Raises ``ExternalSyncRejected`` when an account exists but
    cannot be attributed to this provider safely (#1235).

    External accounts are keyed on the PROVIDER, not its type. Keying on the
    type (``auth_source``) let a second provider of one type sign in as the
    first one's users: two LDAP domains or two OIDC IdPs are two
    authorities, and a subject or username in one says nothing about the
    other. So, in order:

    1. the account linked to this provider with this external id;
    2. an account an administrator linked to this provider but that has not
       signed in since (``external_id`` NULL), claimed by username: the
       admin's link is what authorises the name match;
    3. an account from before the provider column (``auth_provider_id``
       NULL, same type, same external id) is REFUSED until an administrator
       links it. The migration (``f4a8c2e71d09``) already linked every
       account it could prove came from its provider, so one still NULL is
       one it could not: its provider may have been deleted before the
       upgrade, and adopting it here would hand it to whoever holds the same
       identifier at the survivor (found by QA on #1289). An account whose
       provider was deleted after the upgrade has its ``external_id``
       cleared, so it never matches this step at all.

    An account is never adopted by username alone, whatever its type.
    """
    linked = (
        (
            await db.execute(
                select(User)
                .where(User.auth_provider_id == provider.id, User.external_id == key)
                .order_by(User.created_at)
                .limit(1)
            )
        )
        .scalars()
        .first()
    )
    if linked is not None:
        return linked

    pending = (
        await db.execute(
            select(User).where(
                User.auth_provider_id == provider.id,
                User.external_id.is_(None),
                User.username == username,
            )
        )
    ).scalar_one_or_none()
    if pending is not None:
        return pending

    legacy = (
        (
            await db.execute(
                select(User)
                .where(
                    User.auth_provider_id.is_(None),
                    User.auth_source == provider.type,
                    User.external_id == key,
                )
                .order_by(User.created_at)
                .limit(1)
            )
        )
        .scalars()
        .first()
    )
    if legacy is None:
        return None
    raise ExternalSyncRejected(
        "account_link_required",
        f"{legacy.username!r} is a {provider.type} account not linked to a provider, "
        "and it cannot be shown to come from this one; an administrator must link it",
        user=legacy,
    )


async def sync_external_user(
    db: AsyncSession, provider: AuthProvider, result: ExternalAuthResult
) -> User:
    """Create or update the local user for an authenticated external subject.

    ``provider.type`` is used as the value for ``User.auth_source`` and
    ``provider.id`` for ``User.auth_provider_id``. Raises
    ``ExternalSyncRejected`` if the login should be refused (no mapping
    match, username already taken, an unlinked account, auto-create off,
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
    username = (result.username or "").strip() or key

    # 2) The account this subject is linked to, if any.
    user = await _find_linked_user(db, provider, key, username)

    # 3) Username collision. The name belongs to another account (local, or
    # another provider's), and adopting it would hand this subject that
    # account, superadmin flag and all (#1235).
    if user is None:
        collision = (
            await db.execute(select(User).where(User.username == username))
        ).scalar_one_or_none()
        if collision is not None:
            raise ExternalSyncRejected(
                "username_collision",
                f"A {collision.auth_source} user named {username!r} already exists and is "
                "not linked to this provider",
                user=collision,
            )

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
            auth_provider_id=provider.id,
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
        if user.auth_provider_id != provider.id or user.external_id != key:
            logger.info(
                "external_user_linked",
                username=user.username,
                provider=provider.name,
                external_id=key[:80],
            )
        user.auth_provider_id = provider.id
        user.auth_source = auth_source
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
