"""A client class / device policy a pool still names cannot be renamed or deleted (#2285).

Kea accepts a pool bound to a class it does not define and the pool simply
matches nobody, so nothing fails: these tests pin that the API refuses the
change, that a typo'd restriction is refused on create, and that if a dangling
reference reaches the bundle anyway it is kept (fail closed) and logged.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import (
    DHCPClientClass,
    DHCPPool,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
)
from app.models.dhcp_device_policy import DHCPDevicePolicy
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp.config_bundle import build_config_bundle


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _v4_scope(db: AsyncSession) -> tuple[DHCPServerGroup, DHCPScope, DHCPServer]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.77.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.77.1.0/24", name="s")
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([subnet, grp])
    await db.flush()
    scope = DHCPScope(subnet_id=subnet.id, group_id=grp.id, name="quarantine")
    srv = DHCPServer(
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=67,
        server_group_id=grp.id,
    )
    db.add_all([scope, srv])
    await db.flush()
    return grp, scope, srv


def _pool(scope: DHCPScope, cls: str | None) -> DHCPPool:
    return DHCPPool(
        scope_id=scope.id, start_ip="10.77.1.10", end_ip="10.77.1.20", class_restriction=cls
    )


async def test_renaming_a_referenced_class_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, scope, _ = await _v4_scope(db_session)
    cc = DHCPClientClass(group_id=grp.id, name="iot", match_expression="")
    db_session.add_all([cc, _pool(scope, "iot")])
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/dhcp/client-classes/{cc.id}", headers=h, json={"name": "iot2"}
    )
    assert resp.status_code == 409, resp.text
    assert "10.77.1.10-10.77.1.20" in resp.json()["detail"]
    await db_session.refresh(cc)
    assert cc.name == "iot"

    # Editing something other than the name is unaffected.
    resp = await client.put(
        f"/api/v1/dhcp/client-classes/{cc.id}", headers=h, json={"description": "x"}
    )
    assert resp.status_code == 200, resp.text


async def test_deleting_a_referenced_class_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, scope, _ = await _v4_scope(db_session)
    cc = DHCPClientClass(group_id=grp.id, name="iot", match_expression="")
    db_session.add_all([cc, _pool(scope, "iot")])
    await db_session.commit()

    resp = await client.delete(f"/api/v1/dhcp/client-classes/{cc.id}", headers=h)
    assert resp.status_code == 409, resp.text
    assert "quarantine" in resp.json()["detail"]
    assert await db_session.get(DHCPClientClass, cc.id) is not None


async def test_a_class_another_class_tests_with_member_is_protected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, _, _ = await _v4_scope(db_session)
    base = DHCPClientClass(group_id=grp.id, name="base", match_expression="")
    dep = DHCPClientClass(group_id=grp.id, name="dep", match_expression="member('base')")
    db_session.add_all([base, dep])
    await db_session.commit()

    resp = await client.delete(f"/api/v1/dhcp/client-classes/{base.id}", headers=h)
    assert resp.status_code == 409, resp.text
    assert "dep" in resp.json()["detail"]


async def test_an_unreferenced_class_renames_and_deletes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, scope, _ = await _v4_scope(db_session)
    cc = DHCPClientClass(group_id=grp.id, name="free", match_expression="")
    # A pool bound to a same-named class in ANOTHER group must not count.
    other_grp, other_scope, _ = await _v4_scope(db_session)
    db_session.add_all([cc, _pool(other_scope, "free"), _pool(scope, None)])
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/dhcp/client-classes/{cc.id}", headers=h, json={"name": "free2"}
    )
    assert resp.status_code == 200, resp.text
    resp = await client.delete(f"/api/v1/dhcp/client-classes/{cc.id}", headers=h)
    assert resp.status_code == 204, resp.text


async def test_deleting_a_device_policy_a_pool_binds_to_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, scope, _ = await _v4_scope(db_session)
    pol = DHCPDevicePolicy(
        group_id=grp.id,
        name="quarantine-iot",
        class_name="spatium-device-iot",
        device_classes=["Printer"],
        enabled=True,
    )
    free = DHCPDevicePolicy(
        group_id=grp.id,
        name="free",
        class_name="spatium-device-free",
        device_classes=["Printer"],
        enabled=True,
    )
    db_session.add_all([pol, free, _pool(scope, "spatium-device-iot")])
    await db_session.commit()

    resp = await client.delete(f"/api/v1/dhcp/device-policies/{pol.id}", headers=h)
    assert resp.status_code == 409, resp.text
    assert "spatium-device-iot" in resp.json()["detail"]
    resp = await client.delete(f"/api/v1/dhcp/device-policies/{free.id}", headers=h)
    assert resp.status_code == 204, resp.text


async def test_a_typo_in_a_pool_class_is_refused_on_create_and_update(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, scope, _ = await _v4_scope(db_session)
    db_session.add(DHCPClientClass(group_id=grp.id, name="iot", match_expression=""))
    await db_session.commit()
    body = {"start_ip": "10.77.1.10", "end_ip": "10.77.1.20"}

    resp = await client.post(
        f"/api/v1/dhcp/scopes/{scope.id}/pools",
        headers=h,
        json={**body, "class_restriction": "ioot"},
    )
    assert resp.status_code == 422, resp.text
    assert "does not exist" in resp.json()["detail"]

    for ok in ("iot", "KNOWN"):
        resp = await client.post(
            f"/api/v1/dhcp/scopes/{scope.id}/pools",
            headers=h,
            json={"start_ip": "10.77.1.30", "end_ip": "10.77.1.40", "class_restriction": ok},
        )
        assert resp.status_code == 201, resp.text
        await client.delete(f"/api/v1/dhcp/pools/{resp.json()['id']}", headers=h)

    pool = _pool(scope, None)
    db_session.add(pool)
    await db_session.commit()
    resp = await client.put(
        f"/api/v1/dhcp/pools/{pool.id}", headers=h, json={"class_restriction": "ioot"}
    )
    assert resp.status_code == 422, resp.text


async def test_a_dangling_restriction_is_kept_and_logged_in_the_bundle(
    db_session: AsyncSession,
) -> None:
    """Fail closed: the restriction ships as stored (the pool matches nobody)
    rather than being dropped, which would open a quarantine pool to everyone."""
    grp, scope, srv = await _v4_scope(db_session)
    db_session.add_all(
        [
            DHCPClientClass(group_id=grp.id, name="defined", match_expression=""),
            _pool(scope, "ghost"),
            DHCPPool(
                scope_id=scope.id,
                start_ip="10.77.1.30",
                end_ip="10.77.1.40",
                class_restriction="defined",
            ),
        ]
    )
    await db_session.commit()

    with capture_logs() as logs:
        bundle = await build_config_bundle(db_session, srv)

    restrictions = {p.class_restriction for s in bundle.scopes for p in s.pools}
    assert restrictions == {"ghost", "defined"}
    warned = [e for e in logs if e["event"] == "dhcp_pool_restricted_to_undefined_class"]
    assert [(e["client_class"], e["pool"]) for e in warned] == [("ghost", "10.77.1.10-10.77.1.20")]

    # Rebuilt on every long-poll: the same dangling set is not re-reported.
    with capture_logs() as again:
        await build_config_bundle(db_session, srv)
    assert not [e for e in again if e["event"] == "dhcp_pool_restricted_to_undefined_class"]


def test_member_references_are_matched_as_the_call() -> None:
    """``member('x')`` counts in any spelling Kea accepts; the bare quoted
    name elsewhere in a test that also uses member() does not."""
    from app.services.dhcp.class_refs import calls_member as refs

    assert refs("member('iot')", "iot")
    assert refs("not member( 'iot' )", "iot")
    assert refs("member ('a') or (member('iot') and pkt4.mac == 0x01)", "iot")
    assert refs('member("iot")', "iot")
    assert not refs("member('a') and option[60].text == 'iot'", "iot")
    assert not refs("member('iot2')", "iot")
    assert not refs("member('i.t')", "iot")
    assert not refs("nonmember('iot')", "iot")


async def test_a_string_literal_is_not_a_member_reference(
    db_session: AsyncSession,
) -> None:
    from app.services.dhcp.class_refs import classes_testing_membership

    grp, _scope, _srv = await _v4_scope(db_session)
    db_session.add_all(
        [
            DHCPClientClass(
                group_id=grp.id,
                name="vendor",
                match_expression="member('KNOWN') and option[60].text == 'printers'",
            ),
            DHCPClientClass(
                group_id=grp.id, name="child", match_expression="not member( 'printers' )"
            ),
        ]
    )
    await db_session.commit()
    assert await classes_testing_membership(db_session, grp.id, "printers") == ["child"]
