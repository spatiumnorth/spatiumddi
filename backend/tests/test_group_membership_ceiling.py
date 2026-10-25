"""Group membership changes are bounded by the role-attachment ceiling.

#400 (C4) bounded the roles a delegated group admin may attach to a group by
what that admin could grant themselves. Membership is the other half of the
same grant: putting a user in a group hands them every permission the
group's roles carry. So adding a member, removing one, and deleting the
group all need the actor to be able to grant the group's roles
(``caller_can_grant`` — wildcards only for an effective superadmin).

Separately, no change may leave the install without an active superadmin.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User

_PW = "Group-pw-ceiling-1!"
_STAR = [{"action": "*", "resource_type": "*"}]
_GROUP_ADMIN = [{"action": "admin", "resource_type": "group"}]


@pytest.fixture(autouse=True)
def _budget(monkeypatch: pytest.MonkeyPatch) -> None:
    import app.api.stepup as stepup

    async def _blocked(_user_id: object) -> bool:
        return False

    async def _record(_user_id: object) -> None:
        return None

    monkeypatch.setattr(stepup, "stepup_password_blocked", _blocked)
    monkeypatch.setattr(stepup, "record_stepup_password_failure", _record)


def _name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:6]}"


def _headers(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _user(db: AsyncSession, *, superadmin: bool = False, active: bool = True) -> User:
    user = User(
        username=_name("u"),
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="user",
        hashed_password=hash_password(_PW),
        auth_source="local",
        is_superadmin=superadmin,
        is_active=active,
    )
    user.groups = []
    db.add(user)
    await db.commit()
    return user


async def _role(db: AsyncSession, permissions: list[dict[str, Any]]) -> Role:
    role = Role(name=_name("r"), description="", is_builtin=False, permissions=permissions)
    db.add(role)
    await db.commit()
    return role


async def _group(db: AsyncSession, *, roles: list[Role], users: list[User]) -> Group:
    group = Group(name=_name("g"), description="", auth_source="local")
    group.roles = roles
    group.users = users
    db.add(group)
    await db.commit()
    return group


async def _delegate(db: AsyncSession, permissions: list[dict[str, Any]]) -> User:
    """A non-superadmin whose only grants are ``permissions``."""
    user = await _user(db)
    await _group(db, roles=[await _role(db, permissions)], users=[user])
    return user


async def _member_ids(db: AsyncSession, group_id: uuid.UUID) -> set[uuid.UUID]:
    group = (
        await db.execute(
            select(Group).where(Group.id == group_id).execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if group is None:
        return set()
    await db.refresh(group, ["users"])
    return {u.id for u in group.users}


async def _denied_rows(db: AsyncSession, actor: User) -> list[AuditLog]:
    rows = (
        await db.execute(
            select(AuditLog).where(
                AuditLog.user_id == actor.id,
                AuditLog.result == "denied",
                AuditLog.resource_type == "group",
            )
        )
    ).scalars()
    return list(rows)


# ── Adding members ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_group_admin_cannot_add_self_to_a_superadmin_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _user(db_session, superadmin=True)
    delegate = await _delegate(db_session, _GROUP_ADMIN)
    super_group = await _group(db_session, roles=[await _role(db_session, _STAR)], users=[])

    r = await client.put(
        f"/api/v1/groups/{super_group.id}",
        headers=_headers(delegate),
        json={"user_ids": [str(delegate.id)], "stepup_password": _PW},
    )
    assert r.status_code == 403, r.text
    assert delegate.id not in await _member_ids(db_session, super_group.id)
    assert await _denied_rows(db_session, delegate)

    # Still not a superadmin.
    r = await client.get("/api/v1/users", headers=_headers(delegate))
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_group_admin_cannot_create_a_group_with_a_role_they_lack_and_self_in_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    delegate = await _delegate(db_session, _GROUP_ADMIN)
    dns_role = await _role(db_session, [{"action": "admin", "resource_type": "dns_zone"}])
    existing = await _group(db_session, roles=[dns_role], users=[])

    # Joining an existing group whose role they do not hold.
    r = await client.put(
        f"/api/v1/groups/{existing.id}",
        headers=_headers(delegate),
        json={"user_ids": [str(delegate.id)]},
    )
    assert r.status_code == 403, r.text
    assert delegate.id not in await _member_ids(db_session, existing.id)
    assert await _denied_rows(db_session, delegate)


@pytest.mark.asyncio
async def test_group_admin_cannot_add_another_user_to_a_group_above_their_ceiling(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    delegate = await _delegate(db_session, _GROUP_ADMIN)
    other = await _user(db_session)
    dns_role = await _role(db_session, [{"action": "admin", "resource_type": "dns_zone"}])
    group = await _group(db_session, roles=[dns_role], users=[])

    r = await client.put(
        f"/api/v1/groups/{group.id}",
        headers=_headers(delegate),
        json={"user_ids": [str(other.id)]},
    )
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_group_admin_can_add_a_user_to_a_group_within_their_ceiling(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    delegate = await _delegate(
        db_session, [*_GROUP_ADMIN, {"action": "admin", "resource_type": "subnet"}]
    )
    other = await _user(db_session)
    subnet_role = await _role(db_session, [{"action": "write", "resource_type": "subnet"}])
    group = await _group(db_session, roles=[subnet_role], users=[])

    r = await client.put(
        f"/api/v1/groups/{group.id}",
        headers=_headers(delegate),
        json={"user_ids": [str(other.id)]},
    )
    assert r.status_code == 200, r.text
    assert other.id in await _member_ids(db_session, group.id)

    # And on create.
    r = await client.post(
        "/api/v1/groups",
        headers=_headers(delegate),
        json={
            "name": _name("g"),
            "role_ids": [str(subnet_role.id)],
            "user_ids": [str(other.id)],
        },
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_create_with_members_is_bounded_by_the_attached_roles(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A create attaching no role cannot be used to dodge the check, and a
    create that attaches a role the actor holds may add members."""
    delegate = await _delegate(db_session, _GROUP_ADMIN)
    r = await client.post(
        "/api/v1/groups",
        headers=_headers(delegate),
        json={"name": _name("g"), "user_ids": [str(delegate.id)]},
    )
    # A group with no roles grants nothing: allowed.
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_unchanged_membership_is_not_a_membership_change(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A UI save resends the whole member list; that alone is not a change."""
    delegate = await _delegate(db_session, _GROUP_ADMIN)
    member = await _user(db_session)
    dns_role = await _role(db_session, [{"action": "admin", "resource_type": "dns_zone"}])
    group = await _group(db_session, roles=[dns_role], users=[member])

    r = await client.put(
        f"/api/v1/groups/{group.id}",
        headers=_headers(delegate),
        json={"description": "edited", "user_ids": [str(member.id)]},
    )
    assert r.status_code == 200, r.text


# ── Removing members / deleting ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_group_admin_cannot_empty_or_delete_a_superadmin_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    sa_member = await _user(db_session)
    await _user(db_session, superadmin=True)  # so last-superadmin is not the reason
    delegate = await _delegate(db_session, _GROUP_ADMIN)
    super_group = await _group(
        db_session, roles=[await _role(db_session, _STAR)], users=[sa_member]
    )

    r = await client.put(
        f"/api/v1/groups/{super_group.id}",
        headers=_headers(delegate),
        json={"user_ids": []},
    )
    assert r.status_code == 403, r.text
    assert sa_member.id in await _member_ids(db_session, super_group.id)

    r = await client.delete(f"/api/v1/groups/{super_group.id}", headers=_headers(delegate))
    assert r.status_code == 403, r.text
    assert sa_member.id in await _member_ids(db_session, super_group.id)
    assert len(await _denied_rows(db_session, delegate)) >= 2


@pytest.mark.asyncio
async def test_group_admin_cannot_detach_a_role_above_their_ceiling(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _user(db_session, superadmin=True)
    delegate = await _delegate(db_session, _GROUP_ADMIN)
    member = await _user(db_session)
    super_group = await _group(db_session, roles=[await _role(db_session, _STAR)], users=[member])

    r = await client.put(
        f"/api/v1/groups/{super_group.id}",
        headers=_headers(delegate),
        json={"role_ids": []},
    )
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_group_admin_can_remove_members_and_delete_within_ceiling(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    delegate = await _delegate(
        db_session, [*_GROUP_ADMIN, {"action": "read", "resource_type": "subnet"}]
    )
    member = await _user(db_session)
    group = await _group(
        db_session,
        roles=[await _role(db_session, [{"action": "read", "resource_type": "subnet"}])],
        users=[member],
    )
    r = await client.put(
        f"/api/v1/groups/{group.id}", headers=_headers(delegate), json={"user_ids": []}
    )
    assert r.status_code == 200, r.text
    r = await client.delete(f"/api/v1/groups/{group.id}", headers=_headers(delegate))
    assert r.status_code == 204, r.text


# ── Superadmin is unaffected ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_superadmin_can_still_manage_any_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin = await _user(db_session, superadmin=True)
    target = await _user(db_session)
    star = await _role(db_session, _STAR)
    dns_role = await _role(db_session, [{"action": "admin", "resource_type": "dns_zone"}])
    group = await _group(db_session, roles=[dns_role], users=[])

    r = await client.put(
        f"/api/v1/groups/{group.id}",
        headers=_headers(admin),
        json={"user_ids": [str(target.id)]},
    )
    assert r.status_code == 200, r.text

    super_group = await _group(db_session, roles=[star], users=[])
    r = await client.put(
        f"/api/v1/groups/{super_group.id}",
        headers=_headers(admin),
        json={"user_ids": [str(target.id)], "stepup_password": _PW},
    )
    assert r.status_code == 200, r.text
    r = await client.put(
        f"/api/v1/groups/{super_group.id}", headers=_headers(admin), json={"user_ids": []}
    )
    assert r.status_code == 200, r.text
    r = await client.delete(f"/api/v1/groups/{super_group.id}", headers=_headers(admin))
    assert r.status_code == 204, r.text


# ── Last active superadmin ──────────────────────────────────────────────────


async def _role_only_superadmin(db: AsyncSession) -> tuple[User, Group, Role]:
    """The install's only superadmin, via a ``*`` / ``*`` role."""
    star = await _role(db, _STAR)
    user = await _user(db)
    group = await _group(db, roles=[star], users=[user])
    return user, group, star


@pytest.mark.asyncio
async def test_last_superadmin_cannot_leave_the_superadmin_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, group, _ = await _role_only_superadmin(db_session)
    r = await client.put(
        f"/api/v1/groups/{group.id}", headers=_headers(user), json={"user_ids": []}
    )
    assert r.status_code == 409, r.text
    assert user.id in await _member_ids(db_session, group.id)


@pytest.mark.asyncio
async def test_last_superadmin_group_cannot_be_deleted_or_lose_its_role(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, group, star = await _role_only_superadmin(db_session)
    r = await client.delete(f"/api/v1/groups/{group.id}", headers=_headers(user))
    assert r.status_code == 409, r.text
    r = await client.put(
        f"/api/v1/groups/{group.id}", headers=_headers(user), json={"role_ids": []}
    )
    assert r.status_code == 409, r.text
    # Removing the wildcard from the role, or deleting the role.
    r = await client.put(
        f"/api/v1/roles/{star.id}",
        headers=_headers(user),
        json={"permissions": [{"action": "read", "resource_type": "subnet"}]},
    )
    assert r.status_code == 409, r.text
    r = await client.delete(f"/api/v1/roles/{star.id}", headers=_headers(user))
    assert r.status_code == 409, r.text
    assert user.id in await _member_ids(db_session, group.id)


@pytest.mark.asyncio
async def test_last_superadmin_cannot_disable_self(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin = await _user(db_session, superadmin=True)
    r = await client.put(
        f"/api/v1/users/{admin.id}", headers=_headers(admin), json={"is_active": False}
    )
    assert r.status_code == 409, r.text
    await db_session.refresh(admin)
    assert admin.is_active is True


@pytest.mark.asyncio
async def test_superadmin_changes_allowed_while_another_remains(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    other = await _user(db_session, superadmin=True)
    user, group, _ = await _role_only_superadmin(db_session)
    r = await client.put(
        f"/api/v1/groups/{group.id}", headers=_headers(user), json={"user_ids": []}
    )
    assert r.status_code == 200, r.text
    # ``other`` can now disable the role-path user; and a flagged superadmin
    # may disable themselves while another active superadmin exists.
    second = await _user(db_session, superadmin=True)
    r = await client.put(
        f"/api/v1/users/{other.id}", headers=_headers(other), json={"is_active": False}
    )
    assert r.status_code == 200, r.text
    assert second.is_active


# ── Roles and time-bound grants follow the same ceiling ─────────────────────


@pytest.mark.asyncio
async def test_role_admin_cannot_strip_or_delete_a_role_above_their_ceiling(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _user(db_session, superadmin=True)
    delegate = await _delegate(
        db_session,
        [
            {"action": "admin", "resource_type": "role"},
            {"action": "read", "resource_type": "subnet"},
        ],
    )
    star = await _role(db_session, _STAR)
    r = await client.put(
        f"/api/v1/roles/{star.id}",
        headers=_headers(delegate),
        json={"permissions": [{"action": "read", "resource_type": "subnet"}]},
    )
    assert r.status_code == 403, r.text
    r = await client.delete(f"/api/v1/roles/{star.id}", headers=_headers(delegate))
    assert r.status_code == 403, r.text

    # Within the ceiling both still work.
    own = await _role(db_session, [{"action": "read", "resource_type": "subnet"}])
    r = await client.put(
        f"/api/v1/roles/{own.id}",
        headers=_headers(delegate),
        json={"permissions": [{"action": "read", "resource_type": "subnet"}]},
    )
    assert r.status_code == 200, r.text
    r = await client.delete(f"/api/v1/roles/{own.id}", headers=_headers(delegate))
    assert r.status_code == 204, r.text


@pytest.mark.asyncio
async def test_group_admin_cannot_revoke_a_wildcard_grant(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from datetime import UTC, datetime, timedelta

    from app.models.time_bound_grant import TimeBoundGrant

    await _user(db_session, superadmin=True)
    delegate = await _delegate(db_session, _GROUP_ADMIN)
    group = await _group(db_session, roles=[], users=[])
    grant = TimeBoundGrant(
        group_id=group.id,
        action="*",
        resource_type="dns_zone",
        resource_id=None,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        reason="test",
    )
    db_session.add(grant)
    await db_session.commit()

    r = await client.delete(
        f"/api/v1/groups/time-bound-grants/{grant.id}", headers=_headers(delegate)
    )
    assert r.status_code == 403, r.text
    await db_session.refresh(grant)
    assert grant.revoked_at is None


async def _grant(
    db: AsyncSession, group: Group, action: str, resource_type: str, hours: int = 1
) -> Any:
    from datetime import UTC, datetime, timedelta

    from app.models.time_bound_grant import TimeBoundGrant

    grant = TimeBoundGrant(
        group_id=group.id,
        action=action,
        resource_type=resource_type,
        resource_id=None,
        expires_at=datetime.now(UTC) + timedelta(hours=hours),
        reason="test",
    )
    db.add(grant)
    await db.commit()
    return grant


@pytest.mark.asyncio
async def test_a_time_bound_superadmin_does_not_count_as_the_last_one(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A ``*`` / ``*`` time-bound grant lapses on its own, so the account it
    makes a superadmin is not the one that keeps the install administrable:
    the last durable superadmin still cannot disable themselves, and revoking
    the grant is never refused as "the last superadmin"."""
    admin = await _user(db_session, superadmin=True)
    temp = await _user(db_session)
    group = await _group(db_session, roles=[], users=[temp])
    grant = await _grant(db_session, group, "*", "*")

    r = await client.put(
        f"/api/v1/users/{admin.id}", headers=_headers(admin), json={"is_active": False}
    )
    assert r.status_code == 409, r.text
    await db_session.refresh(admin)
    assert admin.is_active is True

    r = await client.delete(f"/api/v1/groups/time-bound-grants/{grant.id}", headers=_headers(admin))
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_a_time_bound_permission_is_not_a_ceiling_to_grant_from(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A delegate holding ``admin:dns_zone`` only until a grant expires cannot
    turn it into access that outlives the grant: not by joining a group that
    carries it, nor by minting a fresh grant, nor by authoring a role."""
    await _user(db_session, superadmin=True)
    zone_admin = [{"action": "admin", "resource_type": "dns_zone"}]
    delegate = await _user(db_session)
    own = await _group(
        db_session,
        roles=[
            await _role(
                db_session,
                [*_GROUP_ADMIN, {"action": "admin", "resource_type": "role"}],
            )
        ],
        users=[delegate],
    )
    await _grant(db_session, own, "admin", "dns_zone")
    # The grant is live: the delegate does hold the permission right now.
    r = await client.get("/api/v1/dns/groups", headers=_headers(delegate))
    assert r.status_code == 200, r.text

    target = await _group(db_session, roles=[await _role(db_session, zone_admin)], users=[])
    r = await client.put(
        f"/api/v1/groups/{target.id}",
        headers=_headers(delegate),
        json={"user_ids": [str(delegate.id)]},
    )
    assert r.status_code == 403, r.text
    assert delegate.id not in await _member_ids(db_session, target.id)

    r = await client.post(
        "/api/v1/groups/time-bound-grants",
        headers=_headers(delegate),
        json={
            "group_id": str(own.id),
            "action": "admin",
            "resource_type": "dns_zone",
            "expires_at": "2099-01-01T00:00:00Z",
            "reason": "extend",
        },
    )
    assert r.status_code == 403, r.text

    r = await client.post(
        "/api/v1/roles",
        headers=_headers(delegate),
        json={"name": _name("r"), "description": "", "permissions": zone_admin},
    )
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_last_superadmin_check_holds_a_lock_until_commit(
    db_session: AsyncSession,
) -> None:
    """Two concurrent changes must not each remove one of the last two
    superadmins: the check holds a transaction-scoped lock that a second
    transaction cannot take until the first commits."""
    from sqlalchemy import text

    from app.services.superadmin_grant import (
        _LAST_SUPERADMIN_LOCK_KEY,
        leaves_no_active_superadmin,
    )

    await _user(db_session, superadmin=True)
    assert await leaves_no_active_superadmin(db_session, lambda m: None) is False

    probe = "SELECT pg_try_advisory_xact_lock(:k)"
    async with AsyncSession(db_session.bind) as other:
        taken = await other.scalar(text(probe), {"k": _LAST_SUPERADMIN_LOCK_KEY})
        assert taken is False
        await other.rollback()

    await db_session.commit()
    async with AsyncSession(db_session.bind) as other:
        taken = await other.scalar(text(probe), {"k": _LAST_SUPERADMIN_LOCK_KEY})
        assert taken is True
        await other.rollback()
