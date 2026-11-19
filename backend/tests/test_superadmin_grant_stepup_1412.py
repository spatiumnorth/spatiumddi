"""Granting effective superadmin through a group's role needs the step-up (#1412).

#1355 put the operator step-up on the ``is_superadmin`` flag. A user is also
a superadmin through a group holding a ``*`` / ``*`` role, or a live
``*`` / ``*`` time-bound grant, so those paths need it too. The check is on
the effect: only a change that makes someone a superadmin who was not one.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.auth_provider import AuthGroupMapping, AuthProvider
from app.services.superadmin_grant import (
    SuperadminModel,
    holds_superadmin,
    permissions_grant_superadmin,
)

_PW = "Admin-pw-1412!"
_STAR = [{"action": "*", "resource_type": "*"}]


@pytest.fixture(autouse=True)
def _budget(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    import app.api.stepup as stepup

    state: dict[str, object] = {"failures": []}

    async def _blocked(_user_id: object) -> bool:
        return False

    async def _record(user_id: object) -> None:
        state["failures"].append(user_id)  # type: ignore[union-attr]

    monkeypatch.setattr(stepup, "stepup_password_blocked", _blocked)
    monkeypatch.setattr(stepup, "record_stepup_password_failure", _record)
    return state


def _name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:6]}"


async def _admin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=_name("a"),
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="admin",
        hashed_password=hash_password(_PW),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.commit()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _plain_user(db: AsyncSession, *, active: bool = True) -> User:
    user = User(
        username=_name("u"),
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="plain",
        hashed_password=hash_password("Plain-pw-1412!"),
        auth_source="local",
        is_superadmin=False,
        is_active=active,
    )
    user.groups = []
    db.add(user)
    await db.commit()
    return user


async def _role(db: AsyncSession, permissions: list[dict[str, str]]) -> Role:
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


async def _member_ids(db: AsyncSession, group_id: uuid.UUID) -> set[uuid.UUID]:
    group = await db.get(Group, group_id)
    assert group is not None
    await db.refresh(group, ["users"])
    return {u.id for u in group.users}


# ── The model ───────────────────────────────────────────────────────────────


def test_only_an_unscoped_star_star_grants_superadmin() -> None:
    assert permissions_grant_superadmin(_STAR)
    assert not permissions_grant_superadmin([{"action": "*", "resource_type": "subnet"}])
    assert not permissions_grant_superadmin(
        [{"action": "*", "resource_type": "*", "resource_id": "abc"}]
    )
    assert not permissions_grant_superadmin(None)


def test_the_model_counts_every_path() -> None:
    u1, u2, u3, u4 = (uuid.uuid4() for _ in range(4))
    g_role, g_grant, g_plain, star, other = (uuid.uuid4() for _ in range(5))
    model = SuperadminModel(flagged={u1})
    model.group_members.update({g_role: {u2}, g_grant: {u3}, g_plain: {u4}})
    model.group_roles.update({g_role: {star}, g_plain: {other}})
    model.role_wildcard.update({star: True, other: False})
    model.granted_groups.add(g_grant)
    assert model.superadmins() == {u1, u2, u3}


# ── Groups ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_adding_a_user_to_a_superadmin_group_needs_the_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    target = await _plain_user(db_session)
    group = await _group(db_session, roles=[await _role(db_session, _STAR)], users=[])
    url = f"/api/v1/groups/{group.id}"

    r = await client.put(url, headers=headers, json={"user_ids": [str(target.id)]})

    assert r.status_code == 403, r.text
    assert r.headers.get("X-Stepup-Required") == "true"
    assert await _member_ids(db_session, group.id) == set()
    assert not await holds_superadmin(db_session, target.id)

    r = await client.put(
        url, headers=headers, json={"user_ids": [str(target.id)], "stepup_password": _PW}
    )
    assert r.status_code == 200, r.text
    assert await holds_superadmin(db_session, target.id)
    row = (
        (
            await db_session.execute(
                select(AuditLog)
                .where(AuditLog.resource_type == "group", AuditLog.result == "success")
                .order_by(AuditLog.timestamp.desc())
            )
        )
        .scalars()
        .first()
    )
    assert row is not None
    assert row.new_value == {"granted_superadmin": 1, "stepup_method": "password"}


@pytest.mark.asyncio
async def test_a_wrong_step_up_changes_nothing(
    client: AsyncClient, db_session: AsyncSession, _budget: dict[str, object]
) -> None:
    admin, headers = await _admin(db_session)
    target = await _plain_user(db_session)
    group = await _group(db_session, roles=[await _role(db_session, _STAR)], users=[])

    r = await client.put(
        f"/api/v1/groups/{group.id}",
        headers=headers,
        json={"name": "renamed", "user_ids": [str(target.id)], "stepup_password": "wrong"},
    )

    assert r.status_code == 403, r.text
    assert _budget["failures"] == [admin.id]
    refreshed = await db_session.get(Group, group.id)
    assert refreshed is not None
    await db_session.refresh(refreshed)
    assert refreshed.name == group.name  # the rename did not ride along
    assert await _member_ids(db_session, group.id) == set()


@pytest.mark.asyncio
async def test_giving_a_star_role_to_a_group_with_members_needs_the_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    target = await _plain_user(db_session)
    star = await _role(db_session, _STAR)
    group = await _group(db_session, roles=[], users=[target])

    r = await client.put(
        f"/api/v1/groups/{group.id}", headers=headers, json={"role_ids": [str(star.id)]}
    )

    assert r.status_code == 403, r.text
    assert r.headers.get("X-Stepup-Required") == "true"


@pytest.mark.asyncio
async def test_creating_a_superadmin_group_with_members_needs_the_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    target = await _plain_user(db_session)
    star = await _role(db_session, _STAR)
    body = {"name": _name("g"), "role_ids": [str(star.id)], "user_ids": [str(target.id)]}

    r = await client.post("/api/v1/groups", headers=headers, json=body)
    assert r.status_code == 403, r.text
    assert (
        await db_session.execute(select(Group).where(Group.name == body["name"]))
    ).first() is None

    r = await client.post("/api/v1/groups", headers=headers, json={**body, "stepup_password": _PW})
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_edits_that_make_nobody_a_superadmin_need_no_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin, headers = await _admin(db_session)
    target = await _plain_user(db_session)
    star = await _role(db_session, _STAR)
    super_group = await _group(db_session, roles=[star], users=[target])

    # Renaming a superadmin group, and removing a member from it.
    r = await client.put(
        f"/api/v1/groups/{super_group.id}", headers=headers, json={"name": _name("g")}
    )
    assert r.status_code == 200, r.text
    r = await client.put(f"/api/v1/groups/{super_group.id}", headers=headers, json={"user_ids": []})
    assert r.status_code == 200, r.text

    # Adding someone who is already a superadmin through the flag.
    r = await client.put(
        f"/api/v1/groups/{super_group.id}",
        headers=headers,
        json={"user_ids": [str(admin.id)]},
    )
    assert r.status_code == 200, r.text

    # A group without a star role.
    plain_group = await _group(db_session, roles=[], users=[])
    r = await client.put(
        f"/api/v1/groups/{plain_group.id}",
        headers=headers,
        json={"user_ids": [str(target.id)]},
    )
    assert r.status_code == 200, r.text


# ── Roles ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_adding_star_star_to_a_held_role_needs_the_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    target = await _plain_user(db_session)
    role = await _role(db_session, [{"action": "read", "resource_type": "subnet"}])
    await _group(db_session, roles=[role], users=[target])
    url = f"/api/v1/roles/{role.id}"

    r = await client.put(url, headers=headers, json={"permissions": _STAR})
    assert r.status_code == 403, r.text
    assert r.headers.get("X-Stepup-Required") == "true"
    assert not await holds_superadmin(db_session, target.id)

    r = await client.put(url, headers=headers, json={"permissions": _STAR, "stepup_password": _PW})
    assert r.status_code == 200, r.text
    assert await holds_superadmin(db_session, target.id)


@pytest.mark.asyncio
async def test_a_star_role_nobody_holds_needs_no_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    role = await _role(db_session, [{"action": "read", "resource_type": "subnet"}])

    r = await client.put(f"/api/v1/roles/{role.id}", headers=headers, json={"permissions": _STAR})

    assert r.status_code == 200, r.text


# ── Time-bound grants ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_star_star_grant_to_a_group_with_members_needs_the_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    target = await _plain_user(db_session)
    group = await _group(db_session, roles=[], users=[target])
    body = {
        "group_id": str(group.id),
        "action": "*",
        "resource_type": "*",
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    }

    r = await client.post("/api/v1/groups/time-bound-grants", headers=headers, json=body)
    assert r.status_code == 403, r.text
    assert r.headers.get("X-Stepup-Required") == "true"

    r = await client.post(
        "/api/v1/groups/time-bound-grants",
        headers=headers,
        json={**body, "stepup_password": _PW},
    )
    assert r.status_code == 201, r.text
    assert await holds_superadmin(db_session, target.id)


# ── Password reset of a disabled role-only superadmin ───────────────────────


@pytest.mark.asyncio
async def test_resetting_a_disabled_role_only_superadmin_needs_the_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Disable, reset with no step-up, re-enable: the path the #1412 comment
    found, because ``is_effective_superadmin`` requires an active user."""
    _, headers = await _admin(db_session)
    target = await _plain_user(db_session, active=False)
    await _group(db_session, roles=[await _role(db_session, _STAR)], users=[target])

    r = await client.post(
        f"/api/v1/users/{target.id}/reset-password",
        headers=headers,
        json={"new_password": "Brand-new-pw-1412-Xyz!"},
    )

    assert r.status_code == 403, r.text
    assert r.headers.get("X-Stepup-Required") == "true"


# ── The Copilot's grant cannot ask for a step-up, so it refuses ──────────────


@pytest.mark.asyncio
async def test_the_copilot_grant_refuses_one_that_makes_superadmins(
    db_session: AsyncSession,
) -> None:
    from app.services.ai.operations import (
        GrantTemporaryAccessArgs,
        _apply_grant_temporary_access,
        _preview_grant_temporary_access,
    )

    admin, _ = await _admin(db_session)
    target = await _plain_user(db_session)
    group = await _group(db_session, roles=[], users=[target])
    star = GrantTemporaryAccessArgs(group_id=str(group.id), action="*", resource_type="*")

    preview = await _preview_grant_temporary_access(db_session, admin, star)
    assert preview.ok is False
    assert "superadmin" in preview.detail
    with pytest.raises(ValueError, match="superadmin"):
        await _apply_grant_temporary_access(db_session, admin, star)
    assert not await holds_superadmin(db_session, target.id)

    # An ordinary grant still goes through.
    read = GrantTemporaryAccessArgs(group_id=str(group.id), action="read", resource_type="subnet")
    assert (await _preview_grant_temporary_access(db_session, admin, read)).ok is True


# ── Auth-provider group mappings (#1476) ─────────────────────────────────────


async def _provider(db: AsyncSession) -> AuthProvider:
    prov = AuthProvider(
        name=_name("ldap"),
        type="ldap",
        is_enabled=True,
        priority=100,
        config={},
        auto_create_users=True,
        auto_update_users=True,
    )
    db.add(prov)
    await db.commit()
    return prov


async def _mappings(db: AsyncSession, provider_id: uuid.UUID) -> list[AuthGroupMapping]:
    rows = await db.execute(
        select(AuthGroupMapping).where(AuthGroupMapping.provider_id == provider_id)
    )
    return list(rows.scalars())


@pytest.mark.asyncio
async def test_mapping_an_idp_group_into_a_superadmin_group_needs_the_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Nobody is a superadmin yet, and nobody needs to be: the next sign-in
    from the external group would be one."""
    _, headers = await _admin(db_session)
    prov = await _provider(db_session)
    group = await _group(db_session, roles=[await _role(db_session, _STAR)], users=[])
    url = f"/api/v1/auth-providers/{prov.id}/mappings"
    body = {"external_group": "CN=Admins,DC=example,DC=com", "internal_group_id": str(group.id)}

    r = await client.post(url, headers=headers, json=body)
    assert r.status_code == 403, r.text
    assert r.headers.get("X-Stepup-Required") == "true"
    assert await _mappings(db_session, prov.id) == []

    r = await client.post(url, headers=headers, json={**body, "stepup_password": _PW})
    assert r.status_code == 201, r.text
    row = (
        (
            await db_session.execute(
                select(AuditLog)
                .where(
                    AuditLog.resource_type == "auth_group_mapping",
                    AuditLog.result == "success",
                )
                .order_by(AuditLog.timestamp.desc())
            )
        )
        .scalars()
        .first()
    )
    assert row is not None
    assert row.new_value["grants_superadmin"] is True
    assert row.new_value["stepup_method"] == "password"


@pytest.mark.asyncio
async def test_mapping_into_an_ordinary_group_needs_no_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    prov = await _provider(db_session)
    viewers = await _group(
        db_session,
        roles=[await _role(db_session, [{"action": "read", "resource_type": "*"}])],
        users=[],
    )
    r = await client.post(
        f"/api/v1/auth-providers/{prov.id}/mappings",
        headers=headers,
        json={"external_group": "CN=Viewers", "internal_group_id": str(viewers.id)},
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_repointing_a_mapping_at_a_superadmin_group_needs_the_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    prov = await _provider(db_session)
    plain = await _group(db_session, roles=[], users=[])
    star = await _group(db_session, roles=[await _role(db_session, _STAR)], users=[])
    mapping = AuthGroupMapping(
        provider_id=prov.id, external_group="CN=Ops", internal_group_id=plain.id
    )
    db_session.add(mapping)
    await db_session.commit()
    url = f"/api/v1/auth-providers/{prov.id}/mappings/{mapping.id}"

    r = await client.put(url, headers=headers, json={"internal_group_id": str(star.id)})
    assert r.status_code == 403, r.text
    assert r.headers.get("X-Stepup-Required") == "true"
    await db_session.refresh(mapping)
    assert mapping.internal_group_id == plain.id

    r = await client.put(
        url, headers=headers, json={"internal_group_id": str(star.id), "stepup_password": _PW}
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_renaming_the_external_group_of_a_superadmin_mapping_needs_the_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A new external group is a new set of IdP accounts becoming superadmins."""
    _, headers = await _admin(db_session)
    prov = await _provider(db_session)
    star = await _group(db_session, roles=[await _role(db_session, _STAR)], users=[])
    mapping = AuthGroupMapping(
        provider_id=prov.id, external_group="CN=Admins", internal_group_id=star.id
    )
    db_session.add(mapping)
    await db_session.commit()
    url = f"/api/v1/auth-providers/{prov.id}/mappings/{mapping.id}"

    r = await client.put(url, headers=headers, json={"external_group": "CN=Everyone"})
    assert r.status_code == 403, r.text
    await db_session.refresh(mapping)
    assert mapping.external_group == "CN=Admins"


@pytest.mark.asyncio
async def test_a_priority_or_unchanged_edit_of_a_superadmin_mapping_needs_no_step_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Every matching mapping applies on sign-in, so the priority changes who
    is a superadmin not at all; nor does resubmitting the same values."""
    _, headers = await _admin(db_session)
    prov = await _provider(db_session)
    star = await _group(db_session, roles=[await _role(db_session, _STAR)], users=[])
    mapping = AuthGroupMapping(
        provider_id=prov.id, external_group="CN=Admins", internal_group_id=star.id
    )
    db_session.add(mapping)
    await db_session.commit()
    url = f"/api/v1/auth-providers/{prov.id}/mappings/{mapping.id}"

    r = await client.put(url, headers=headers, json={"priority": 5})
    assert r.status_code == 200, r.text
    r = await client.put(
        url,
        headers=headers,
        json={"external_group": "CN=Admins", "internal_group_id": str(star.id)},
    )
    assert r.status_code == 200, r.text
