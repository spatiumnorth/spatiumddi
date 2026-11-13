"""A class delete counts pools sitting in the Trash (#3928).

Deleting a scope trashes its pools with it, and a restore brings them back with
their ``class_restriction``. The reference guard used to count live pools only,
so the class could be deleted meanwhile and the restored pool would name a class
nothing defines (Kea never matches it).
"""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPClientClass, DHCPPool, DHCPScope
from app.models.dhcp_device_policy import DHCPDevicePolicy
from tests.test_dhcp_phone_profiles import _make_group_server_scope
from tests.test_dhcp_pxe_vendor_match_validation import _headers


async def _trashed_pool_scope(client: AsyncClient, db: AsyncSession):
    h = await _headers(db)
    _grp, _srv, scope = await _make_group_server_scope(db)
    cc = DHCPClientClass(
        group_id=scope.group_id, name="quarantine", match_expression="option[60].text == 'x'"
    )
    db.add(cc)
    db.add(
        DHCPPool(
            scope_id=scope.id,
            start_ip="10.0.9.10",
            end_ip="10.0.9.50",
            pool_type="dynamic",
            class_restriction="quarantine",
        )
    )
    await db.commit()
    scope_name = scope.name
    r = await client.delete(f"/api/v1/dhcp/scopes/{scope.id}", headers=h)
    assert r.status_code == 204, r.text
    return h, cc, scope_name


async def test_client_class_delete_refused_while_a_trashed_scope_pool_names_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, cc, scope_name = await _trashed_pool_scope(client, db_session)
    r = await client.delete(f"/api/v1/dhcp/client-classes/{cc.id}", headers=h)
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert "quarantine" in detail and scope_name in detail and "in Trash" in detail


async def test_client_class_delete_allowed_once_nothing_names_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    _grp, _srv, scope = await _make_group_server_scope(db_session)
    cc = DHCPClientClass(
        group_id=scope.group_id, name="unused", match_expression="option[60].text == 'x'"
    )
    db_session.add(cc)
    await db_session.commit()
    r = await client.delete(f"/api/v1/dhcp/client-classes/{cc.id}", headers=h)
    assert r.status_code == 204, r.text


# ── Every caller of the helper passes the flag (#3928) ───────────────────


async def _pool_on(db: AsyncSession, scope, cls: str) -> None:
    db.add(
        DHCPPool(
            scope_id=scope.id,
            start_ip="10.0.20.10",
            end_ip="10.0.20.50",
            pool_type="dynamic",
            class_restriction=cls,
        )
    )
    await db.commit()


async def test_refusal_names_the_way_out(client: AsyncClient, db_session: AsyncSession) -> None:
    h, cc, _ = await _trashed_pool_scope(client, db_session)
    r = await client.delete(f"/api/v1/dhcp/client-classes/{cc.id}", headers=h)
    assert r.status_code == 409
    assert "purge their scope from Administration > Trash" in r.json()["detail"]


async def test_class_rename_refused_while_a_trashed_scope_pool_names_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, cc, _ = await _trashed_pool_scope(client, db_session)
    r = await client.put(
        f"/api/v1/dhcp/client-classes/{cc.id}", headers=h, json={"name": "renamed"}
    )
    assert r.status_code == 409, r.text
    assert "in Trash" in r.json()["detail"]


async def test_device_policy_delete_refused_while_a_trashed_scope_pool_names_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, _srv, scope = await _make_group_server_scope(db_session)
    pol = DHCPDevicePolicy(
        group_id=grp.id, name="pol", class_name="spatium-device-abc", device_classes=["Printer"]
    )
    db_session.add(pol)
    await _pool_on(db_session, scope, "spatium-device-abc")
    r = await client.delete(f"/api/v1/dhcp/scopes/{scope.id}", headers=h)
    assert r.status_code == 204, r.text
    r = await client.delete(f"/api/v1/dhcp/device-policies/{pol.id}", headers=h)
    assert r.status_code == 409, r.text
    assert "in Trash" in r.json()["detail"]


async def test_pxe_profile_delete_refused_while_a_trashed_scope_pool_names_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, _srv, scope = await _make_group_server_scope(db_session)
    r = await client.post(
        f"/api/v1/dhcp/server-groups/{grp.id}/pxe-profiles",
        headers=h,
        json={
            "name": "px",
            "next_server": "10.0.0.5",
            "matches": [
                {"vendor_class_match": "PXEClient", "arch_codes": [7], "boot_filename": "a.efi"}
            ],
        },
    )
    assert r.status_code == 201, r.text
    prof = r.json()
    cname = f"pxe-{prof['id'][:8]}-{prof['matches'][0]['id'][:8]}"
    await _pool_on(db_session, scope, cname)
    assert (await client.delete(f"/api/v1/dhcp/scopes/{scope.id}", headers=h)).status_code == 204
    r = await client.delete(f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h)
    assert r.status_code == 409, r.text
    assert "in Trash" in r.json()["detail"]


async def test_phone_profile_delete_refused_while_a_trashed_scope_pool_names_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, _srv, scope = await _make_group_server_scope(db_session)
    r = await client.post(
        f"/api/v1/dhcp/server-groups/{grp.id}/phone-profiles", headers=h, json={"name": "desk"}
    )
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    await _pool_on(db_session, scope, f"voip-{pid[:8]}")
    assert (await client.delete(f"/api/v1/dhcp/scopes/{scope.id}", headers=h)).status_code == 204
    r = await client.delete(f"/api/v1/dhcp/phone-profiles/{pid}", headers=h)
    assert r.status_code == 409, r.text
    assert "in Trash" in r.json()["detail"]


async def test_purging_the_trashed_scope_unblocks_the_class_delete(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, cc, _ = await _trashed_pool_scope(client, db_session)
    scope_id = (
        await db_session.execute(
            select(DHCPScope.id)
            .where(DHCPScope.group_id == cc.group_id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one()
    r = await client.delete(f"/api/v1/admin/trash/dhcp_scope/{scope_id}", headers=h)
    assert r.status_code == 204, r.text
    r = await client.delete(f"/api/v1/dhcp/client-classes/{cc.id}", headers=h)
    assert r.status_code == 204, r.text
