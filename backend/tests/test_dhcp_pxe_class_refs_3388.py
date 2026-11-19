"""A pool can never be left restricted to a class the bundle does not define (#3388)."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPPool, DHCPScope
from app.services.dhcp.config_bundle import build_config_bundle
from tests.test_dhcp_pxe_rule_ids_3374 import _m, _setup


async def test_disabling_profile_with_pool_bound_class_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, srv, prof, _rule, cls = await _setup(client, db_session)
    resp = await client.put(
        f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h, json={"enabled": False}
    )
    assert resp.status_code == 409, resp.text
    assert cls in resp.json()["detail"]
    assert "10.0.20.10-10.0.20.50" in resp.json()["detail"]
    bundle = await build_config_bundle(db_session, srv)
    assert cls in {c.name for c in bundle.pxe_classes}

    # Once the pool lets go, disabling is fine.
    pool = (await db_session.execute(DHCPPool.__table__.select())).first()
    assert pool is not None
    await db_session.execute(DHCPPool.__table__.update().values(class_restriction=None))
    await db_session.commit()
    resp = await client.put(
        f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h, json={"enabled": False}
    )
    assert resp.status_code == 200, resp.text


async def test_unbinding_profile_from_last_scope_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, srv, prof, _rule, cls = await _setup(client, db_session)
    scope = (await db_session.execute(DHCPScope.__table__.select())).first()
    assert scope is not None
    url = f"/api/v1/dhcp/scopes/{scope.id}"
    resp = await client.put(url, headers=h, json={"clear_pxe_profile": True})
    assert resp.status_code == 409, resp.text
    assert cls in resp.json()["detail"]
    bundle = await build_config_bundle(db_session, srv)
    assert cls in {c.name for c in bundle.pxe_classes}


async def test_pool_naming_nonexistent_generated_class_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, _srv, prof, _rule, cls = await _setup(client, db_session)
    scope = (await db_session.execute(DHCPScope.__table__.select())).first()
    assert scope is not None
    url = f"/api/v1/dhcp/scopes/{scope.id}/pools"
    body = {"start_ip": "10.0.20.100", "end_ip": "10.0.20.120", "pool_type": "dynamic"}
    for bad in ("pxe-deadbeef-deadbeef", "voip-deadbeef", f"pxe-{prof['id'][:8]}-00000000"):
        r = await client.post(url, headers=h, json={**body, "class_restriction": bad})
        assert r.status_code == 422, (bad, r.text)
    ok = await client.post(url, headers=h, json={**body, "class_restriction": cls})
    assert ok.status_code == 201, ok.text

    # Edit path.
    pid = ok.json()["id"]
    r = await client.put(
        f"/api/v1/dhcp/pools/{pid}", headers=h, json={"class_restriction": "pxe-deadbeef-deadbeef"}
    )
    assert r.status_code == 422, r.text


async def test_duplicate_selectors_in_one_profile_are_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, _srv, prof, _rule, _cls = await _setup(client, db_session)
    r = await client.post(
        f"/api/v1/dhcp/server-groups/{prof['group_id']}/pxe-profiles",
        headers=h,
        json={
            "name": "dup",
            "next_server": "10.0.0.7",
            "matches": [_m(10, 7, "a.efi"), _m(20, 7, "b.efi")],
        },
    )
    assert r.status_code == 422, r.text
